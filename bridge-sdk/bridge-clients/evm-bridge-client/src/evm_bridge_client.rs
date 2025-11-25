use std::{str::FromStr};

use bridge_connector_common::result::{BridgeSdkError, Result};
use derive_builder::Builder;
use alloy::{
    primitives::{Address, TxHash, U256, Bytes},
    providers::{Provider, ProviderBuilder},
    network::{EthereumWallet, Ethereum},
    sol,
    signers::local::PrivateKeySigner,
    sol_types::SolEvent,
};
use ethereum_types::H256 as EthH256;
use omni_types::prover_args::EvmProof;
use omni_types::prover_result::ProofKind;
use omni_types::{near_events::OmniBridgeEvent, OmniAddress};
use omni_types::{EvmAddress, Fee};
use sha3::{Digest, Keccak256};

// Define contract ABIs using the sol! macro
sol! {
    #[allow(missing_docs)]
    #[sol(rpc)]
    interface OmniBridge {
        struct MetadataPayload { 
            string token; 
            string name; 
            string symbol; 
            uint8 decimals; 
        }
        
        struct TransferMessagePayload { 
            uint64 destinationNonce; 
            uint8 originChain; 
            uint64 originNonce; 
            address tokenAddress; 
            uint128 amount; 
            address recipient; 
            string feeRecipient; 
        }
        
        function deployToken(bytes signatureData, MetadataPayload metadata) external returns (address);
        function finTransfer(bytes, TransferMessagePayload) external;
        function initTransfer(address tokenAddress, uint128 amount, uint128 fee, uint128 nativeFee, string recipient, string message) external payable;
        function nearToEthToken(string nearTokenId) external view returns (address);
        function logMetadata(address tokenAddress) external payable;
        function completedTransfers(uint64) external view returns (bool);
        
        event InitTransfer(address indexed sender, address indexed tokenAddress, uint64 indexed originNonce, uint128 amount, uint128 fee, uint128 nativeTokenFee, string recipient, string message);
    }
}

sol! {
    #[allow(missing_docs)]
    #[sol(rpc)]
    interface ERC20 {
        function allowance(address _owner, address _spender) public view returns (uint256 remaining);
        function approve(address spender, uint256 amount) external returns (bool);
    }
}

sol! {
    #[allow(missing_docs)]
    #[sol(rpc)]
    interface WormholeCore {
        function messageFee() external view returns (uint256);
    }
}

/// Bridging NEAR-originated NEP-141 tokens to EVM and back
#[derive(Builder, Default, Clone)]
pub struct EvmBridgeClient {
    #[doc = r"EVM RPC endpoint. Required for `deploy_token`, `mint`, `burn`, `withdraw`"]
    endpoint: Option<String>,
    #[doc = r"EVM chain id. Required for `deploy_token`, `mint`, `burn`, `withdraw`"]
    chain_id: Option<u64>,
    #[doc = r"EVM private key. Required for `deploy_token`, `mint`, `burn`"]
    private_key: Option<String>,
    #[doc = r"`OmniBridge` address on EVM. Required for `deploy_token`, `mint`, `burn`"]
    omni_bridge_address: Option<String>,
    #[doc = r"Wormhole core address on EVM. Required to get wormhole fee"]
    wormhole_core_address: Option<String>,
}

// Helper type for InitTransferFilter compatibility
pub struct InitTransferFilter {
    pub sender: Address,
    pub token_address: Address,
    pub origin_nonce: u64,
    pub amount: u128,
    pub fee: u128,
    pub native_token_fee: u128,
    pub recipient: String,
    pub message: String,
}

impl EvmBridgeClient {
    /// Creates an empty instance of the bridging client. Property values can be set separately depending on the required use case.
    pub fn new() -> Self {
        Self::default()
    }

    // Gets the block number of a transaction
    pub async fn get_tx_block_number(&self, tx_hash: TxHash) -> Result<u64> {
        let provider = self.provider()?;

        let tx = provider
            .get_transaction_by_hash(tx_hash)
            .await
            .map_err(|e| BridgeSdkError::UnknownError(format!("Failed to get transaction: {e}")))?
            .ok_or_else(|| {
                BridgeSdkError::UnknownError("Transaction not found".to_string())
            })?;
        
        let block_number = tx
            .block_number
            .ok_or_else(|| {
                BridgeSdkError::UnknownError("Failed to get tx block number".to_string())
            })?;

        Ok(block_number)
    }

    /// Gets last finalized block number on EVM chain
    pub async fn get_last_block_number(&self) -> Result<u64> {
        let provider = self.provider()?;

        let block = provider
            .get_block_by_number(alloy::eips::BlockNumberOrTag::Latest)
            .await
            .map_err(|e| BridgeSdkError::UnknownError(format!("Failed to get block: {e}")))?
            .ok_or_else(|| {
                BridgeSdkError::UnknownError("Failed to get finalized block number".to_string())
            })?;

        Ok(block.header.number)
    }

    /// Checks if the transfer is already finalised on EVM
    pub async fn is_transfer_finalised(&self, nonce: u64) -> Result<bool> {
        let provider = self.provider()?;
        let omni_bridge_address = self.omni_bridge_address()?;
        
        let omni_bridge = OmniBridge::new(omni_bridge_address, &provider);
        let is_finalised = omni_bridge.completedTransfers(nonce).call().await
            .map_err(|e| BridgeSdkError::UnknownError(e.to_string()))?;

        Ok(is_finalised)
    }

    /// Logs an ERC-20 token metadata
    #[tracing::instrument(skip_all, name = "LOG METADATA")]
    pub async fn log_metadata(
        &self,
        address: EvmAddress,
        tx_nonce: Option<U256>,
    ) -> Result<TxHash> {
        let provider = self.signer_provider().await?;
        let omni_bridge_address = self.omni_bridge_address()?;
        
        let omni_bridge = OmniBridge::new(omni_bridge_address, &provider);
        let token_address = Address::from_slice(&address.0);
        
        let mut call_builder = omni_bridge.logMetadata(token_address);
        
        if let Ok(wormhole_fee) = self.get_wormhole_fee(&provider).await {
            call_builder = call_builder.value(wormhole_fee);
        }
        
        if let Some(nonce) = tx_nonce {
            call_builder = call_builder.nonce(nonce.to::<u64>());
        }
        
        let receipt = call_builder.send().await
            .map_err(|e| BridgeSdkError::UnknownError(format!("Failed to send transaction: {e}")))?
            .get_receipt().await
            .map_err(|e| BridgeSdkError::UnknownError(format!("Failed to get receipt: {e}")))?;

        tracing::info!(
            tx_hash = format!("{:?}", receipt.transaction_hash),
            "Sent new bridge token transaction"
        );

        Ok(receipt.transaction_hash)
    }

    /// Deploys an ERC-20 token representing a bridged version of a token from another chain
    #[tracing::instrument(skip_all, name = "EVM DEPLOY TOKEN")]
    pub async fn deploy_token(
        &self,
        transfer_log: OmniBridgeEvent,
        tx_nonce: Option<U256>,
    ) -> Result<TxHash> {
        let provider = self.signer_provider().await?;
        let omni_bridge_address = self.omni_bridge_address()?;
        
        let OmniBridgeEvent::LogMetadataEvent {
            signature,
            metadata_payload,
        } = transfer_log
        else {
            return Err(BridgeSdkError::InvalidArgument(format!(
                "Expected LogMetadataEvent but got {transfer_log:?}"
            )));
        };

        let payload = OmniBridge::MetadataPayload {
            token: metadata_payload.token,
            name: metadata_payload.name,
            symbol: metadata_payload.symbol,
            decimals: metadata_payload.decimals,
        };

        let serialized_signature = signature.to_bytes();
        assert!(serialized_signature.len() == 65);
        
        let omni_bridge = OmniBridge::new(omni_bridge_address, &provider);
        let mut call_builder = omni_bridge.deployToken(
            Bytes::from(serialized_signature.to_vec()), 
            payload
        ).gas(500_000);

        if let Ok(wormhole_fee) = self.get_wormhole_fee(&provider).await {
            call_builder = call_builder.value(wormhole_fee);
        }
        
        if let Some(nonce) = tx_nonce {
            call_builder = call_builder.nonce(nonce.to::<u64>());
        }

        let receipt = call_builder.send().await
            .map_err(|e| BridgeSdkError::UnknownError(format!("Failed to send transaction: {e}")))?
            .get_receipt().await
            .map_err(|e| BridgeSdkError::UnknownError(format!("Failed to get receipt: {e}")))?;

        tracing::info!(
            tx_hash = format!("{:?}", receipt.transaction_hash),
            "Sent new bridge token transaction"
        );

        Ok(receipt.transaction_hash)
    }

    /// Burns bridged tokens on EVM
    #[tracing::instrument(skip_all, name = "EVM INIT TRANSFER")]
    pub async fn init_transfer(
        &self,
        token: alloy::primitives::Address,
        amount: u128,
        receiver: OmniAddress,
        fee: Fee,
        message: String,
        mut tx_nonce: Option<U256>,
    ) -> Result<TxHash> {
        let provider = self.signer_provider().await?;
        let omni_bridge_address = self.omni_bridge_address()?;
        let signer_address = self.signer_address()?;
        
        // Handle token approval if not native token
        if !token.is_zero() {
            let erc20 = ERC20::new(token, &provider);
            
            let allowance_result = erc20.allowance(signer_address, omni_bridge_address)
                .call().await?;

            let amount_u256 = U256::from(amount);
            if allowance_result < amount_u256 {
                let mut approval_call = erc20.approve(omni_bridge_address, amount_u256);
                if let Some(nonce) = tx_nonce {
                    approval_call = approval_call.nonce(nonce.to::<u64>());
                }
                
                approval_call.send().await
                    .map_err(|e| BridgeSdkError::UnknownError(format!("Failed to send approval: {e}")))?
                    .get_receipt().await
                    .map_err(|e| BridgeSdkError::UnknownError(format!("Failed to get approval receipt: {e}")))?;
                tx_nonce = tx_nonce.map(|n| n + U256::from(1));
                
                tracing::debug!("Approved tokens for spending");
            }
        }

        let mut value = U256::from(fee.native_fee.0);

        if let Ok(wormhole_fee) = self.get_wormhole_fee(&provider).await {
            value += wormhole_fee;
        }

        if token.is_zero() {
            value += U256::from(amount);
        }

        let omni_bridge = OmniBridge::new(omni_bridge_address, provider);
        let mut transfer_call = omni_bridge.initTransfer(
            token,
            amount,
            fee.fee.into(),
            fee.native_fee.into(),
            receiver.to_string(),
            message,
        ).value(value);
        
        if let Some(nonce) = tx_nonce {
            transfer_call = transfer_call.nonce(nonce.to::<u64>());
        }

        let receipt = transfer_call.send().await
            .map_err(|e| BridgeSdkError::UnknownError(format!("Failed to send transfer: {e}")))?
            .get_receipt().await
            .map_err(|e| BridgeSdkError::UnknownError(format!("Failed to get transfer receipt: {e}")))?;

        tracing::info!(
            tx_hash = format!("{:?}", receipt.transaction_hash),
            "Sent transfer transaction"
        );

        Ok(receipt.transaction_hash)
    }

    /// Mints the corresponding bridged tokens on EVM
    #[tracing::instrument(skip_all, name = "EVM FIN TRANSFER")]
    pub async fn fin_transfer(
        &self,
        transfer_log: OmniBridgeEvent,
        tx_nonce: Option<U256>,
    ) -> Result<TxHash> {
        let provider = self.signer_provider().await?;
        let omni_bridge_address = self.omni_bridge_address()?;
        
        let OmniBridgeEvent::SignTransferEvent {
            message_payload,
            signature,
        } = transfer_log
        else {
            return Err(BridgeSdkError::InvalidArgument(format!(
                "Expected SignTransferEvent but got {transfer_log:?}"
            )));
        };

        let token_address = match message_payload.token_address {
            OmniAddress::Eth(addr)
            | OmniAddress::Base(addr)
            | OmniAddress::Arb(addr)
            | OmniAddress::Bnb(addr) => Address::from_slice(&addr.0),
            OmniAddress::Near(_)
            | OmniAddress::Sol(_)
            | OmniAddress::Btc(_)
            | OmniAddress::Zcash(_) => {
                return Err(BridgeSdkError::InvalidArgument(format!(
                    "Unsupported token address type in SignTransferEvent: {:?}",
                    message_payload.token_address
                )))
            }
        };
        
        let recipient = match message_payload.recipient {
            OmniAddress::Eth(addr)
            | OmniAddress::Base(addr)
            | OmniAddress::Arb(addr)
            | OmniAddress::Bnb(addr) => Address::from_slice(&addr.0),
            OmniAddress::Near(_)
            | OmniAddress::Sol(_)
            | OmniAddress::Btc(_)
            | OmniAddress::Zcash(_) => {
                return Err(BridgeSdkError::InvalidArgument(format!(
                    "Unsupported recipient address type in SignTransferEvent: {:?}",
                    message_payload.recipient
                )))
            }
        };

        let bridge_deposit = OmniBridge::TransferMessagePayload {
            destinationNonce: message_payload.destination_nonce,
            originChain: message_payload.transfer_id.origin_chain.into(),
            originNonce: message_payload.transfer_id.origin_nonce,
            tokenAddress: token_address,
            amount: message_payload.amount.into(),
            recipient,
            feeRecipient: message_payload
                .fee_recipient
                .map_or_else(String::new, |addr| addr.to_string()),
        };

        let omni_bridge = OmniBridge::new(omni_bridge_address, &provider);
        let mut call_builder = omni_bridge.finTransfer(
            Bytes::from(signature.to_bytes().to_vec()), 
            bridge_deposit
        );

        if let Ok(wormhole_fee) = self.get_wormhole_fee(&provider).await {
            call_builder = call_builder.value(wormhole_fee);
        }
        
        if let Some(nonce) = tx_nonce {
            call_builder = call_builder.nonce(nonce.to::<u64>());
        }

        let receipt = call_builder.send().await
            .map_err(|e| BridgeSdkError::UnknownError(format!("Failed to send fin transfer: {e}")))?
            .get_receipt().await
            .map_err(|e| BridgeSdkError::UnknownError(format!("Failed to get fin transfer receipt: {e}")))?;

        tracing::info!(
            tx_hash = format!("{:?}", receipt.transaction_hash),
            "Sent finalize transfer transaction"
        );

        Ok(receipt.transaction_hash)
    }

    pub async fn get_proof_for_event(
        &self,
        tx_hash: TxHash,
        proof_kind: ProofKind,
    ) -> Result<EvmProof> {
        let endpoint = self.endpoint()?;

        let event_signature = match proof_kind {
            ProofKind::DeployToken => "DeployToken(address,string,string,string,uint8,uint8)",
            ProofKind::InitTransfer => {
                "InitTransfer(address,address,uint64,uint128,uint128,uint128,string,string)"
            }
            ProofKind::FinTransfer => "FinTransfer(uint8,uint64,address,uint128,address,string)",
            ProofKind::LogMetadata => "LogMetadata(address,string,string,uint8)",
        };
        
        let hash_bytes = Keccak256::digest(event_signature.as_bytes());
        let event_topic = EthH256::from_slice(&hash_bytes);
        
        // Convert TxHash (B256) to ethereum_types::H256
        let tx_hash_primitive = EthH256::from_slice(tx_hash.as_slice());

        let proof = eth_proof::get_proof_for_event(tx_hash_primitive, event_topic, endpoint).await?;

        Ok(proof)
    }

    pub async fn get_transfer_event(&self, tx_hash: TxHash) -> Result<InitTransferFilter> {
        let provider = self.provider()?;

        let receipt = provider.get_transaction_receipt(tx_hash).await
            .map_err(|e| BridgeSdkError::UnknownError(format!("Failed to get receipt: {e}")))?
            .ok_or(BridgeSdkError::InvalidArgument("Transaction receipt not found".to_string()))?;

        let _event_signature = OmniBridge::InitTransfer::SIGNATURE;
        
        let rpc_log = receipt
            .inner
            .logs()
            .iter()
            .find(|log| {
                if let Some(topic) = log.topics().first() {
                    // SIGNATURE is a &str constant, need to compare topics properly
                    let sig_hash = alloy::primitives::keccak256(OmniBridge::InitTransfer::SIGNATURE.as_bytes());
                    topic.0 == sig_hash.0
                } else {
                    false
                }
            })
            .ok_or(BridgeSdkError::InvalidArgument(
                "Transfer event not found".to_string(),
            ))?;

        // Convert RPC log to alloy primitive log for decoding
        let log_data = alloy::primitives::Log {
            address: rpc_log.address(),
            data: alloy::primitives::LogData::new_unchecked(
                rpc_log.topics().to_vec(),
                rpc_log.data().data.clone(),
            ),
        };

        let decoded = OmniBridge::InitTransfer::decode_log(&log_data)
            .map_err(|err| {
                BridgeSdkError::UnknownError(format!("Failed to decode event log: {err}"))
            })?;

        Ok(InitTransferFilter {
            sender: decoded.sender,
            token_address: decoded.tokenAddress,
            origin_nonce: decoded.originNonce,
            amount: decoded.amount,
            fee: decoded.fee,
            native_token_fee: decoded.nativeTokenFee,
            recipient: decoded.recipient.clone(),
            message: decoded.message.clone(),
        })
    }

    pub fn endpoint(&self) -> Result<&str> {
        Ok(self.endpoint.as_ref().ok_or(BridgeSdkError::ConfigError(
            "EVM rpc endpoint is not set".to_string(),
        ))?)
    }

    pub fn omni_bridge_address(&self) -> Result<Address> {
        self.omni_bridge_address
            .as_ref()
            .ok_or(BridgeSdkError::ConfigError(
                "OmniBridge address is not set".to_string(),
            ))
            .and_then(|addr| {
                Address::from_str(addr).map_err(|_| {
                    BridgeSdkError::ConfigError(
                        "omni_bridge_address is not a valid EVM address".to_string(),
                    )
                })
            })
    }

    pub fn wormhole_core_address(&self) -> Result<Address> {
        self.wormhole_core_address
            .as_ref()
            .ok_or(BridgeSdkError::ConfigError(
                "Wormhole core address is not set".to_string(),
            ))
            .and_then(|addr| {
                Address::from_str(addr).map_err(|_| {
                    BridgeSdkError::ConfigError(
                        "wormhole_core_address is not a valid EVM address".to_string(),
                    )
                })
            })
    }

    fn provider(&self) -> Result<impl Provider<Ethereum>> {
        let endpoint = self.endpoint()?;
        let url = endpoint.parse()
            .map_err(|_| BridgeSdkError::ConfigError("Invalid EVM rpc endpoint url".to_string()))?;
        let provider = ProviderBuilder::new()
            .on_http(url);
        Ok(provider)
    }

    async fn signer_provider(&self) -> Result<impl Provider<Ethereum>> {
        let endpoint = self.endpoint()?;
        let private_key = self.private_key.as_ref()
            .ok_or(BridgeSdkError::ConfigError("EVM private key is not set".to_string()))?;
        
        let signer = PrivateKeySigner::from_str(private_key)
            .map_err(|_| BridgeSdkError::ConfigError("Invalid EVM private key".to_string()))?;
        
        let url = endpoint.parse()
            .map_err(|_| BridgeSdkError::ConfigError("Invalid EVM rpc endpoint url".to_string()))?;
        let provider = ProviderBuilder::new()
            .wallet(EthereumWallet::from(signer))
            .on_http(url);
        
        Ok(provider)
    }

    fn signer_address(&self) -> Result<Address> {
        let private_key = self.private_key.as_ref()
            .ok_or(BridgeSdkError::ConfigError("EVM private key is not set".to_string()))?;
        
        let signer = PrivateKeySigner::from_str(private_key)
            .map_err(|_| BridgeSdkError::ConfigError("Invalid EVM private key".to_string()))?;
        
        Ok(signer.address())
    }

    async fn get_wormhole_fee<P>(&self, provider: &P) -> Result<U256> 
    where
        P: Provider<Ethereum>
    {
        let wormhole_address = self.wormhole_core_address()?;
        let wormhole = WormholeCore::new(wormhole_address, provider);
        let fee = wormhole.messageFee().call().await?;
        Ok(fee)
    }
}
