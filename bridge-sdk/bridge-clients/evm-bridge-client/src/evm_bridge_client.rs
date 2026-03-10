use alloy::{
    contract::{CallBuilder, CallDecoder},
    network::Network,
    primitives::{Address, Bytes, TxHash, U256},
    providers::{DynProvider, Provider},
    sol,
    sol_types::SolEvent,
};
use error::Result;
use ethereum_types::H256 as EthH256;
use omni_types::prover_args::EvmProof;
use omni_types::prover_result::ProofKind;
use omni_types::{near_events::OmniBridgeEvent, OmniAddress};
use omni_types::{EvmAddress, Fee};
use sha3::{Digest, Keccak256};

use crate::error::EvmBridgeClientError;

pub use builder::EvmBridgeClientBuilder;

mod builder;
pub mod error;

const DEPLOY_TOKEN_GAS: u64 = 500_000;
const FIN_TRANSFER_GAS: u64 = 250_000;

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
        function logMetadata(address tokenAddress) external payable;
        function completedTransfers(uint64) external view returns (bool);

        event InitTransfer(address indexed sender, address indexed tokenAddress, uint64 indexed originNonce, uint128 amount, uint128 fee, uint128 nativeTokenFee, string recipient, string message);
    }
}

sol! {
    #[allow(missing_docs)]
    #[sol(rpc)]
    interface ERC20 {
        function allowance(address owner, address spender) public view returns (uint256 remaining);
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

// Helper type for InitTransferFilter compatibility
#[derive(Debug)]
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

/// Bridging NEAR-originated NEP-141 tokens to EVM and back
#[derive(Clone)]
pub struct EvmBridgeClient {
    endpoint: String,
    provider: DynProvider,
    signer_provider: Option<DynProvider>,
    signer_address: Option<Address>,
    omni_bridge_address: Option<Address>,
    wormhole_core_address: Option<Address>,
}

impl EvmBridgeClient {
    /// Gets the block number of a transaction
    pub async fn get_tx_block_number(&self, tx_hash: TxHash) -> Result<u64> {
        let tx = self
            .provider
            .get_transaction_by_hash(tx_hash)
            .await?
            .ok_or_else(|| {
                EvmBridgeClientError::BlockchainDataError("Transaction missing".to_string())
            })?;

        let block_number = tx.block_number.ok_or_else(|| {
            EvmBridgeClientError::BlockchainDataError("Block number missing for tx".to_string())
        })?;

        Ok(block_number)
    }

    /// Gets last finalized block number on EVM chain
    pub async fn get_last_block_number(&self) -> Result<u64> {
        let block = self
            .provider
            .get_block_by_number(alloy::eips::BlockNumberOrTag::Latest)
            .await?
            .ok_or_else(|| {
                EvmBridgeClientError::BlockchainDataError("Latest block missing".to_string())
            })?;

        Ok(block.header.number)
    }

    /// Checks if the transfer is already finalised on EVM
    pub async fn is_transfer_finalised(&self, nonce: u64) -> Result<bool> {
        let omni_bridge = self.omni_bridge()?;
        let is_finalised = omni_bridge.completedTransfers(nonce).call().await?;

        Ok(is_finalised)
    }

    /// Logs an ERC-20 token metadata
    #[tracing::instrument(skip_all, name = "LOG METADATA")]
    pub async fn log_metadata(
        &self,
        address: EvmAddress,
        tx_nonce: Option<U256>,
    ) -> Result<TxHash> {
        let omni_bridge = self.omni_bridge()?;
        let token_address = Address::from_slice(&address.0);

        let call_builder = self.prepare_tx_for_sending(
            omni_bridge.logMetadata(token_address),
            tx_nonce,
            self.get_wormhole_fee().await.ok(),
            None,
        );

        let receipt = call_builder.send().await?.get_receipt().await?;

        tracing::info!(
            tx_hash = format!("{:?}", receipt.transaction_hash),
            "Sent new bridge token transaction"
        );

        Ok(receipt.transaction_hash)
    }

    /// Deploys an ERC-20 token representing a bridged version of a token from another chain. Requires a receipt from `log_metadata` transaction on Near
    #[tracing::instrument(skip_all, name = "EVM DEPLOY TOKEN")]
    pub async fn deploy_token(
        &self,
        transfer_log: OmniBridgeEvent,
        tx_nonce: Option<U256>,
    ) -> Result<TxHash> {
        let omni_bridge = self.omni_bridge()?;

        let OmniBridgeEvent::LogMetadataEvent {
            signature,
            metadata_payload,
        } = transfer_log
        else {
            return Err(EvmBridgeClientError::InvalidArgument(format!(
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

        let call_builder = self.prepare_tx_for_sending(
            omni_bridge.deployToken(Bytes::from(serialized_signature), payload),
            tx_nonce,
            self.get_wormhole_fee().await.ok(),
            Some(DEPLOY_TOKEN_GAS),
        );

        let receipt = call_builder.send().await?.get_receipt().await?;

        tracing::info!(
            tx_hash = format!("{:?}", receipt.transaction_hash),
            "Sent new bridge token transaction"
        );

        Ok(receipt.transaction_hash)
    }

    /// Burns bridged tokens on EVM. The proof from this transaction is then used to withdraw the corresponding tokens on Near
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
        let omni_bridge_address = self.omni_bridge_address()?;
        let omni_bridge = self.omni_bridge()?;
        let signer_address = self.signer_address()?;
        let signer_provider = self.signer_provider()?;

        // Handle token approval if not native token
        if !token.is_zero() {
            let erc20 = ERC20::new(token, &signer_provider);

            let allowance_result = erc20
                .allowance(*signer_address, omni_bridge_address)
                .call()
                .await?;

            let amount_u256 = U256::from(amount);
            if allowance_result < amount_u256 {
                let mut approval_call = erc20.approve(omni_bridge_address, amount_u256);
                if let Some(nonce) = tx_nonce {
                    approval_call = approval_call.nonce(nonce.to::<u64>());
                }

                approval_call.send().await?.get_receipt().await?;
                tx_nonce = tx_nonce.map(|n| n + U256::from(1));

                tracing::debug!("Approved tokens for spending");
            }
        }

        let mut value = U256::from(fee.native_fee.0);

        if let Ok(wormhole_fee) = self.get_wormhole_fee().await {
            value += wormhole_fee;
        }

        if token.is_zero() {
            value += U256::from(amount);
        }

        let call_builder = self.prepare_tx_for_sending(
            omni_bridge.initTransfer(
                token,
                amount,
                fee.fee.into(),
                fee.native_fee.into(),
                receiver.to_string(),
                message,
            ),
            tx_nonce,
            Some(value),
            None,
        );

        let receipt = call_builder.send().await?.get_receipt().await?;

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
        let omni_bridge = self.omni_bridge()?;

        let OmniBridgeEvent::SignTransferEvent {
            message_payload,
            signature,
        } = transfer_log
        else {
            return Err(EvmBridgeClientError::InvalidArgument(format!(
                "Expected SignTransferEvent but got {transfer_log:?}"
            )));
        };

        let bridge_deposit = OmniBridge::TransferMessagePayload {
            destinationNonce: message_payload.destination_nonce,
            originChain: message_payload.transfer_id.origin_chain.into(),
            originNonce: message_payload.transfer_id.origin_nonce,
            tokenAddress: Self::convert_omni_address(message_payload.token_address)?,
            amount: message_payload.amount.into(),
            recipient: Self::convert_omni_address(message_payload.recipient)?,
            feeRecipient: message_payload
                .fee_recipient
                .map_or_else(String::new, |addr| addr.to_string()),
        };

        let call_builder = self.prepare_tx_for_sending(
            omni_bridge.finTransfer(Bytes::from(signature.to_bytes()), bridge_deposit),
            tx_nonce,
            self.get_wormhole_fee().await.ok(),
            Some(FIN_TRANSFER_GAS),
        );

        let receipt = call_builder.send().await?.get_receipt().await?;

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

        let proof =
            eth_proof::get_proof_for_event(tx_hash_primitive, event_topic, &self.endpoint).await?;

        Ok(proof)
    }

    pub async fn get_transfer_event(&self, tx_hash: TxHash) -> Result<InitTransferFilter> {
        let receipt = self
            .provider
            .get_transaction_receipt(tx_hash)
            .await?
            .ok_or(EvmBridgeClientError::BlockchainDataError(
                "Transaction receipt missing".to_string(),
            ))?;

        let rpc_log = receipt
            .inner
            .into_logs()
            .into_iter()
            .find(|log| {
                if let Some(topic) = log.topics().first() {
                    // SIGNATURE is a &str constant, need to compare topics properly
                    let sig_hash = alloy::primitives::keccak256(
                        OmniBridge::InitTransfer::SIGNATURE.as_bytes(),
                    );
                    topic.0 == sig_hash.0
                } else {
                    false
                }
            })
            .ok_or(EvmBridgeClientError::BlockchainDataError(
                "Transfer event missing".to_string(),
            ))?;

        let log_data = rpc_log.into_inner();

        let decoded = OmniBridge::InitTransfer::decode_log(&log_data).map_err(|err| {
            EvmBridgeClientError::BlockchainDataError(format!("Failed to decode event log: {err}"))
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

    pub fn prepare_tx_for_sending<P, D, N>(
        &self,
        mut call_builder: CallBuilder<P, D, N>,
        tx_nonce: Option<U256>,
        value: Option<U256>,
        gas: Option<u64>,
    ) -> CallBuilder<P, D, N>
    where
        P: Provider<N>,
        D: CallDecoder,
        N: Network,
    {
        if let Some(nonce) = tx_nonce {
            call_builder = call_builder.nonce(nonce.to::<u64>());
        }

        if let Some(value) = value {
            call_builder = call_builder.value(value);
        }

        if let Some(gas) = gas {
            call_builder = call_builder.gas(gas);
        }

        call_builder
    }

    async fn get_wormhole_fee(&self) -> Result<U256> {
        let wormhole_address = self.wormhole_core_address()?;
        let wormhole = WormholeCore::new(wormhole_address, &self.provider);
        let fee = wormhole.messageFee().call().await?;
        Ok(fee)
    }

    pub fn omni_bridge_address(&self) -> Result<Address> {
        self.omni_bridge_address
            .ok_or(EvmBridgeClientError::ConfigError(
                "OmniBridge address is not set".to_string(),
            ))
    }

    pub fn wormhole_core_address(&self) -> Result<Address> {
        self.wormhole_core_address
            .ok_or(EvmBridgeClientError::ConfigError(
                "Wormhole core address is not set".to_string(),
            ))
    }

    fn omni_bridge(&self) -> Result<OmniBridge::OmniBridgeInstance<&DynProvider>> {
        let omni_bridge_address = self.omni_bridge_address()?;
        Ok(OmniBridge::new(
            omni_bridge_address,
            self.signer_provider()?,
        ))
    }

    fn signer_provider(&self) -> Result<&DynProvider> {
        self.signer_provider
            .as_ref()
            .ok_or(EvmBridgeClientError::ConfigError(
                "EVM private key is not set".to_string(),
            ))
    }

    fn signer_address(&self) -> Result<&Address> {
        self.signer_address
            .as_ref()
            .ok_or(EvmBridgeClientError::ConfigError(
                "EVM private key is not set".to_string(),
            ))
    }

    fn convert_omni_address(address: OmniAddress) -> Result<Address> {
        match address {
            OmniAddress::Eth(addr)
            | OmniAddress::Base(addr)
            | OmniAddress::Arb(addr)
            | OmniAddress::Bnb(addr)
            | OmniAddress::Pol(addr)
            | OmniAddress::HyperEvm(addr)
            | OmniAddress::Abs(addr) => Ok(Address::from_slice(&addr.0)),
            OmniAddress::Near(_)
            | OmniAddress::Sol(_)
            | OmniAddress::Btc(_)
            | OmniAddress::Zcash(_)
            | OmniAddress::Strk(_) => Err(EvmBridgeClientError::InvalidArgument(format!(
                "Unsupported address type in SignTransferEvent: {address:?}",
            ))),
        }
    }
}
