use std::{str::FromStr, sync::Arc};

use bridge_connector_common::result::{BridgeSdkError, Result};
use derive_builder::Builder;
use ethers::{abi::Address, prelude::*};
use omni_types::prover_args::EvmProof;
use omni_types::prover_result::ProofKind;
use omni_types::Fee;
use omni_types::{near_events::Nep141LockerEvent, OmniAddress};
use sha3::{Digest, Keccak256};

abigen!(
    BridgeTokenFactory,
    r#"[
      struct MetadataPayload { string token; string name; string symbol; uint8 decimals; }
      struct TransferMessagePayload { uint64 destinationNonce; uint8 originChain; uint64 originNonce; address tokenAddress; uint128 amount; address recipient; string feeRecipient; }
      function deployToken(bytes signatureData, MetadataPayload metadata) external returns (address)
      function finTransfer(bytes, TransferMessagePayload) external
      function initTransfer(address tokenAddress, uint128 amount, uint128 fee, uint128 nativeFee, string recipient, string message) external
      function nearToEthToken(string nearTokenId) external view returns (address)
    ]"#
);

abigen!(
    ERC20,
    r#"[
      function allowance(address _owner, address _spender) public view returns (uint256 remaining)
      function approve(address spender, uint256 amount) external returns (bool)
    ]"#
);

/// Bridging NEAR-originated NEP-141 tokens to EVM and back
#[derive(Builder, Default, Clone)]
pub struct EvmBridgeClient {
    #[doc = r"EVM RPC endpoint. Required for `deploy_token`, `mint`, `burn`, `withdraw`"]
    endpoint: Option<String>,
    #[doc = r"EVM chain id. Required for `deploy_token`, `mint`, `burn`, `withdraw`"]
    chain_id: Option<u64>,
    #[doc = r"EVM private key. Required for `deploy_token`, `mint`, `burn`"]
    private_key: Option<String>,
    #[doc = r"Bridged token factory address on EVM. Required for `deploy_token`, `mint`, `burn`"]
    bridge_token_factory_address: Option<String>,
}

impl EvmBridgeClient {
    /// Creates an empty instance of the bridging client. Property values can be set separately depending on the required use case.
    pub fn new() -> Self {
        Self::default()
    }

    /// Deploys an ERC-20 token representing a bridged version of a token from another chain. Requires a receipt from log_metadata transaction on Near
    #[tracing::instrument(skip_all, name = "EVM DEPLOY TOKEN")]
    pub async fn deploy_token(&self, transfer_log: Nep141LockerEvent) -> Result<TxHash> {
        let factory = self.bridge_token_factory()?;

        let Nep141LockerEvent::LogMetadataEvent {
            signature,
            metadata_payload,
        } = transfer_log
        else {
            return Err(BridgeSdkError::UnknownError);
        };

        let payload = MetadataPayload {
            token: metadata_payload.token,
            name: metadata_payload.name,
            symbol: metadata_payload.symbol,
            decimals: metadata_payload.decimals,
        };

        let serialized_signature = signature.to_bytes();

        assert!(serialized_signature.len() == 65);

        let mut call = factory
            .deploy_token(serialized_signature.into(), payload)
            .gas(500_000);
        self.apply_required_gas_fee(&mut call).await?;
        let tx = call.send().await?;

        tracing::info!(
            tx_hash = format!("{:?}", tx.tx_hash()),
            "Sent new bridge token transaction"
        );

        Ok(tx.tx_hash())
    }

    /// Burns bridged tokens on EVM. The proof from this transaction is then used to withdraw the corresponding tokens on Near
    #[tracing::instrument(skip_all, name = "EVM INIT TRANSFER")]
    pub async fn init_transfer(
        &self,
        near_token_id: String,
        amount: u128,
        receiver: String,
        fee: Fee,
    ) -> Result<TxHash> {
        let factory = self.bridge_token_factory()?;

        let erc20_address = factory
            .near_to_eth_token(near_token_id.clone())
            .call()
            .await?;

        tracing::debug!(
            address = format!("{:?}", erc20_address),
            "Retrieved ERC20 address"
        );

        let bridge_token = &self.bridge_token(erc20_address)?;

        let signer = self.signer()?;
        let bridge_token_factory_address = self.bridge_token_factory_address()?;
        let allowance = bridge_token
            .allowance(signer.address(), bridge_token_factory_address)
            .call()
            .await?;

        let amount256: ethers::types::U256 = amount.into();
        if allowance < amount256 {
            bridge_token
                .approve(bridge_token_factory_address, amount256 - allowance)
                .send()
                .await?
                .await
                .map_err(ContractError::from)?;

            tracing::debug!("Approved tokens for spending");
        }

        let withdraw_call = factory.init_transfer(
            erc20_address,
            amount,
            fee.fee.into(),
            fee.native_fee.into(),
            receiver,
            String::new(),
        );
        let tx = withdraw_call.send().await?;

        tracing::info!(
            tx_hash = format!("{:?}", tx.tx_hash()),
            "Sent transfer transaction"
        );

        Ok(tx.tx_hash())
    }

    /// Mints the corresponding bridged tokens on EVM. Requires an MPC signature
    #[tracing::instrument(skip_all, name = "EVM FIN TRANSFER")]
    pub async fn fin_transfer(&self, transfer_log: Nep141LockerEvent) -> Result<TxHash> {
        let factory = self.bridge_token_factory()?;

        let Nep141LockerEvent::SignTransferEvent {
            message_payload,
            signature,
        } = transfer_log
        else {
            return Err(BridgeSdkError::UnknownError);
        };

        let bridge_deposit = TransferMessagePayload {
            destination_nonce: message_payload.destination_nonce,
            origin_chain: message_payload.transfer_id.origin_chain as u8,
            origin_nonce: message_payload.transfer_id.origin_nonce,
            token_address: match message_payload.token_address {
                OmniAddress::Eth(addr) | OmniAddress::Base(addr) | OmniAddress::Arb(addr) => {
                    addr.0.into()
                }
                _ => return Err(BridgeSdkError::UnknownError),
            },
            amount: message_payload.amount.into(),
            recipient: match message_payload.recipient {
                OmniAddress::Eth(addr) | OmniAddress::Base(addr) | OmniAddress::Arb(addr) => {
                    H160(addr.0)
                }
                _ => return Err(BridgeSdkError::UnknownError),
            },
            fee_recipient: message_payload
                .fee_recipient
                .map_or_else(String::new, |addr| addr.to_string()),
        };

        let mut call = factory.fin_transfer(signature.to_bytes().into(), bridge_deposit);
        self.apply_required_gas_fee(&mut call).await?;
        let tx = call.send().await?;

        tracing::info!(
            tx_hash = format!("{:?}", tx.tx_hash()),
            "Sent finalize transfer transaction"
        );

        Ok(tx.tx_hash())
    }

    pub async fn get_proof_for_event(
        &self,
        tx_hash: TxHash,
        proof_kind: ProofKind,
    ) -> Result<EvmProof> {
        let endpoint = self.endpoint()?;

        let event_signature = match proof_kind {
            ProofKind::DeployToken => "DeployToken(address,string,string,string,uint8)",
            ProofKind::InitTransfer => {
                "InitTransfer(address,address,uint64,uint128,uint128,uint128,string,string)"
            }
            ProofKind::FinTransfer => "FinTransfer(uint8,uint64,address,uint128,address,string)",
            ProofKind::LogMetadata => "LogMetadata(address,string,string,uint8)",
        };
        let event_topic =
            H256::from_str(&hex::encode(Keccak256::digest(event_signature.as_bytes())))
                .map_err(|_| BridgeSdkError::UnknownError)?;

        let proof = eth_proof::get_proof_for_event(tx_hash, event_topic, endpoint).await?;

        Ok(proof)
    }

    pub fn endpoint(&self) -> Result<&str> {
        Ok(self.endpoint.as_ref().ok_or(BridgeSdkError::ConfigError(
            "EVM rpc endpoint is not set".to_string(),
        ))?)
    }

    pub fn bridge_token_factory_address(&self) -> Result<Address> {
        self.bridge_token_factory_address
            .as_ref()
            .ok_or(BridgeSdkError::ConfigError(
                "Bridge token factory address is not set".to_string(),
            ))
            .and_then(|addr| {
                Address::from_str(addr).map_err(|_| {
                    BridgeSdkError::ConfigError(
                        "bridge_token_factory_address is not a valid EVM address".to_string(),
                    )
                })
            })
    }

    pub fn bridge_token_factory(
        &self,
    ) -> Result<BridgeTokenFactory<SignerMiddleware<Provider<Http>, LocalWallet>>> {
        let endpoint = self.endpoint()?;

        let provider = Provider::<Http>::try_from(endpoint)
            .map_err(|_| BridgeSdkError::ConfigError("Invalid EVM rpc endpoint url".to_string()))?;

        let wallet = self.signer()?;

        let signer = SignerMiddleware::new(provider, wallet);
        let client = Arc::new(signer);

        Ok(BridgeTokenFactory::new(
            self.bridge_token_factory_address()?,
            client,
        ))
    }

    pub fn bridge_token(
        &self,
        address: Address,
    ) -> Result<ERC20<SignerMiddleware<Provider<Http>, LocalWallet>>> {
        let endpoint = self.endpoint()?;

        let provider = Provider::<Http>::try_from(endpoint)
            .map_err(|_| BridgeSdkError::ConfigError("Invalid EVM rpc endpoint url".to_string()))?;

        let wallet = self.signer()?;

        let signer = SignerMiddleware::new(provider, wallet);
        let client = Arc::new(signer);

        Ok(ERC20::new(address, client))
    }

    pub fn signer(&self) -> Result<LocalWallet> {
        let private_key = self
            .private_key
            .as_ref()
            .ok_or(BridgeSdkError::ConfigError(
                "EVM private key is not set".to_string(),
            ))?;

        let chain_id = self.chain_id.as_ref().ok_or(BridgeSdkError::ConfigError(
            "EVM chain id is not set".to_string(),
        ))?;

        let private_key_bytes = hex::decode(private_key).map_err(|_| {
            BridgeSdkError::ConfigError("EVM private key is not a valid hex string".to_string())
        })?;

        if private_key_bytes.len() != 32 {
            return Err(BridgeSdkError::ConfigError(
                "EVM private key is of invalid length".to_string(),
            ));
        }

        Ok(LocalWallet::from_bytes(&private_key_bytes)
            .map_err(|_| BridgeSdkError::ConfigError("Invalid EVM private key".to_string()))?
            .with_chain_id(*chain_id))
    }

    pub async fn get_required_gas_fee(&self) -> Result<(U256, U256)> {
        let endpoint = self.endpoint()?;
        let client = Provider::<Http>::try_from(endpoint)
            .map_err(|_| BridgeSdkError::ConfigError("Invalid EVM rpc endpoint url".to_string()))?;

        let response: std::result::Result<U256, ProviderError> =
            client.request("eth_maxPriorityFeePerGas", ()).await;

        let max_priority_fee_per_gas = match response {
            Ok(fee) => fee,
            Err(_) => U256::zero(),
        };

        let response = client.get_block(BlockNumber::Latest).await;

        let base_fee_per_gas = match response {
            Ok(Some(block)) => block.base_fee_per_gas.unwrap_or_default(),
            _ => return Err(BridgeSdkError::UnknownError),
        };

        Ok((max_priority_fee_per_gas, base_fee_per_gas))
    }

    pub async fn apply_required_gas_fee<B, M, D>(
        &self,
        call: &mut FunctionCall<B, M, D>,
    ) -> Result<()> {
        let (max_priority_fee_per_gas, base_fee_per_gas) = self.get_required_gas_fee().await?;

        let Some(tx) = call.tx.as_eip1559_mut() else {
            return Err(BridgeSdkError::UnknownError);
        };

        tx.max_priority_fee_per_gas = Some(max_priority_fee_per_gas);
        tx.max_fee_per_gas = Some(base_fee_per_gas);

        Ok(())
    }
}
