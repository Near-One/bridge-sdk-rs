use borsh::BorshSerialize;
use bridge_connector_common::result::{BridgeSdkError, Result};
use ethers::{abi::Address, prelude::*};
use near_contract_standards::storage_management::StorageBalance;
use near_crypto::SecretKey;
use near_primitives::{
    hash::CryptoHash,
    types::AccountId,
    views::{FinalExecutionOutcomeView, FinalExecutionStatus},
};
use near_token::NearToken;
use omni_types::prover_args::EvmVerifyProofArgs;
use omni_types::prover_result::ProofKind;
use omni_types::{
    locker_args::{BindTokenArgs, ClaimFeeArgs, FinTransferArgs},
    near_events::Nep141LockerEvent,
    ChainKind, Fee, OmniAddress,
};
use serde_json::json;
use sha3::{Digest, Keccak256};
use std::{str::FromStr, sync::Arc};

abigen!(
    BridgeTokenFactory,
    r#"[
      struct MetadataPayload { string token; string name; string symbol; uint8 decimals; }
      struct FinTransferPayload { uint128 nonce; string token; uint128 amount; address recipient; string feeRecipient; }
      struct ClaimFeePayload { uint128[] nonces; uint128 amount; address recipient; }
      function deployToken(bytes signatureData, MetadataPayload metadata) external returns (address)
      function finTransfer(bytes, FinTransferPayload) external
      function initTransfer(string token, uint128 amount, uint128 fee, uint128 nativeFee, string memory recipient) external
      function claimNativeFee(bytes calldata signatureData, ClaimFeePayload memory payload) external
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

/// Bridging NEAR-originated NEP-141 tokens to Ethereum and back
#[derive(Builder, Default)]
pub struct OmniConnector {
    #[doc = r"Ethereum RPC endpoint. Required for `deploy_token`, `mint`, `burn`, `withdraw`"]
    eth_endpoint: Option<String>,
    #[doc = r"Ethereum chain id. Required for `deploy_token`, `mint`, `burn`, `withdraw`"]
    eth_chain_id: Option<u64>,
    #[doc = r"Ethereum private key. Required for `deploy_token`, `mint`, `burn`"]
    eth_private_key: Option<String>,
    #[doc = r"Bridged token factory address on Ethereum. Required for `deploy_token`, `mint`, `burn`"]
    bridge_token_factory_address: Option<String>,
    #[doc = r"NEAR RPC endpoint. Required for `log_token_metadata`, `storage_deposit_for_token`, `deploy_token`, `deposit`, `mint`, `withdraw`"]
    near_endpoint: Option<String>,
    #[doc = r"NEAR private key. Required for `log_token_metadata`, `storage_deposit_for_token`, `deploy_token`, `deposit`, `withdraw`"]
    near_private_key: Option<String>,
    #[doc = r"NEAR account id of the transaction signer. Required for `log_token_metadata`, `storage_deposit_for_token`, `deploy_token`, `deposit`, `withdraw`"]
    near_signer: Option<String>,
    #[doc = r"Token locker account id on Near. Required for `log_token_metadata`, `storage_deposit_for_token`, `deploy_token`, `deposit`, `mint`, `withdraw`"]
    token_locker_id: Option<String>,
}

impl OmniConnector {
    /// Creates an empty instance of the bridging client. Property values can be set separately depending on the required use case.
    pub fn new() -> Self {
        Self::default()
    }

    /// Logs token metadata to token_locker contract. The proof from this transaction is then used to deploy a corresponding token on Ethereum
    #[tracing::instrument(skip_all, name = "LOG METADATA")]
    pub async fn log_token_metadata(&self, near_token_id: String) -> Result<CryptoHash> {
        let near_endpoint = self.near_endpoint()?;

        let args = format!(r#"{{"token_id":"{near_token_id}"}}"#).into_bytes();

        let tx_id = near_rpc_client::change(
            near_endpoint,
            self.near_signer()?,
            self.token_locker_id()?.to_string(),
            "log_metadata".to_string(),
            args,
            300_000_000_000_000,
            200_000_000_000_000_000_000_000,
        )
        .await?;

        tracing::info!(tx_hash = tx_id.to_string(), "Sent log transaction");

        Ok(tx_id)
    }

    /// Performs a storage deposit on behalf of the token_locker so that the tokens can be transferred to the locker. To be called once for each NEP-141
    #[tracing::instrument(skip_all, name = "STORAGE DEPOSIT")]
    pub async fn storage_deposit_for_token(
        &self,
        near_token_id: String,
        amount: u128,
    ) -> Result<CryptoHash> {
        let near_endpoint = self.near_endpoint()?;
        let token_locker = self.token_locker_id()?.to_string();

        let args = format!(r#"{{"account_id":"{token_locker}"}}"#).into_bytes();

        let tx_id = near_rpc_client::change(
            near_endpoint,
            self.near_signer()?,
            near_token_id,
            "storage_deposit".to_string(),
            args,
            300_000_000_000_000,
            amount,
        )
        .await?;

        tracing::info!(
            tx_hash = tx_id.to_string(),
            "Sent storage deposit transaction"
        );

        Ok(tx_id)
    }

    /// Deploys an ERC-20 token that will be used when bridging NEP-141 tokens to Ethereum. Requires a receipt from log_metadata transaction on Near
    #[tracing::instrument(skip_all, name = "EVM DEPLOY TOKEN")]
    pub async fn evm_deploy_token(
        &self,
        transaction_hash: CryptoHash,
        sender_id: Option<AccountId>,
    ) -> Result<TxHash> {
        let transfer_log = self
            .extract_transfer_log(transaction_hash, sender_id, "LogMetadataEvent")
            .await?;

        self.evm_deploy_token_with_log(
            serde_json::from_str(&transfer_log).map_err(|_| BridgeSdkError::UnknownError)?,
        )
        .await
    }

    #[tracing::instrument(skip_all, name = "EVM DEPLOY TOKEN WITH LOG")]
    pub async fn evm_deploy_token_with_log(
        &self,
        transfer_log: Nep141LockerEvent,
    ) -> Result<TxHash> {
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

        let call = factory
            .deploy_token(serialized_signature.into(), payload)
            .gas(500_000);
        let tx = call.send().await?;

        tracing::info!(
            tx_hash = format!("{:?}", tx.tx_hash()),
            "Sent new bridge token transaction"
        );

        Ok(tx.tx_hash())
    }

    /// Transfers NEP-141 tokens to the token locker. The proof from this transaction is then used to mint the corresponding tokens on Ethereum
    #[tracing::instrument(skip_all, name = "NEAR INIT TRANSFER")]
    pub async fn near_init_transfer(
        &self,
        near_token_id: String,
        amount: u128,
        receiver: String,
    ) -> Result<CryptoHash> {
        let near_endpoint = self.near_endpoint()?;
        let token_locker = self.token_locker_id()?.to_string();

        let required_balance = self
            .get_required_balance_for_init_transfer(&receiver, self.near_account_id()?.as_str())
            .await?
            + self.get_required_balance_for_account().await?;
        let existing_balance = self.get_storage_balance().await?;

        if existing_balance < required_balance {
            self.storage_deposit(required_balance - existing_balance)
                .await?;
        }

        let fee = 0;
        let args =
            format!(r#"{{"receiver_id":"{token_locker}","amount":"{amount}","msg":"{{\"recipient\":\"{receiver}\",\"fee\":\"{fee}\",\"native_token_fee\":\"0\"}}"}}"#)
                .into_bytes();

        let tx_hash = near_rpc_client::change(
            near_endpoint,
            self.near_signer()?,
            near_token_id,
            "ft_transfer_call".to_string(),
            args,
            300_000_000_000_000,
            1,
        )
        .await?;

        tracing::info!(
            tx_hash = format!("{:?}", tx_hash),
            "Sent transfer transaction"
        );

        Ok(tx_hash)
    }

    /// Mints the corresponding bridged tokens on Ethereum. Requires an MPC signature
    #[tracing::instrument(skip_all, name = "EVM FIN TRANSFER")]
    pub async fn evm_fin_transfer(
        &self,
        transaction_hash: CryptoHash,
        sender_id: Option<AccountId>,
    ) -> Result<TxHash> {
        let transfer_log = self
            .extract_transfer_log(transaction_hash, sender_id, "SignTransferEvent")
            .await?;

        self.evm_fin_transfer_with_log(
            serde_json::from_str(&transfer_log).map_err(|_| BridgeSdkError::UnknownError)?,
        )
        .await
    }

    #[tracing::instrument(skip_all, name = "EVM FIN TRANSFER WITH LOG")]
    pub async fn evm_fin_transfer_with_log(
        &self,
        transfer_log: Nep141LockerEvent,
    ) -> Result<TxHash> {
        let factory = self.bridge_token_factory()?;

        let Nep141LockerEvent::SignTransferEvent {
            message_payload,
            signature,
        } = transfer_log
        else {
            return Err(BridgeSdkError::UnknownError);
        };

        let bridge_deposit = FinTransferPayload {
            nonce: message_payload.nonce.into(),
            token: message_payload.token.to_string(),
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

        let call = factory.fin_transfer(signature.to_bytes().into(), bridge_deposit);
        let tx = call.send().await?;

        tracing::info!(
            tx_hash = format!("{:?}", tx.tx_hash()),
            "Sent finalize transfer transaction"
        );

        Ok(tx.tx_hash())
    }

    /// Burns bridged tokens on Ethereum. The proof from this transaction is then used to withdraw the corresponding tokens on Near
    #[tracing::instrument(skip_all, name = "EVM INIT TRANSFER")]
    pub async fn evm_init_transfer(
        &self,
        near_token_id: String,
        amount: u128,
        receiver: String,
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

        let signer = self.eth_signer()?;
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

        // TODO: Provide fee and nativeFee
        let withdraw_call = factory.init_transfer(near_token_id, amount, 0, 0, receiver);
        let tx = withdraw_call.send().await?;

        tracing::info!(
            tx_hash = format!("{:?}", tx.tx_hash()),
            "Sent transfer transaction"
        );

        Ok(tx.tx_hash())
    }

    /// Withdraws NEP-141 tokens from the token locker. Requires a proof from the burn transaction
    #[tracing::instrument(skip_all, name = "NEAR FIN TRANSFER")]
    pub async fn near_fin_transfer(&self, args: FinTransferArgs) -> Result<CryptoHash> {
        let near_endpoint = self.near_endpoint()?;

        let tx_hash = near_rpc_client::change(
            near_endpoint,
            self.near_signer()?,
            self.token_locker_id()?.to_string(),
            "fin_transfer".to_string(),
            borsh::to_vec(&args).map_err(|_| BridgeSdkError::UnknownError)?,
            300_000_000_000_000,
            60_000_000_000_000_000_000_000,
        )
        .await?;

        tracing::info!(
            tx_hash = format!("{:?}", tx_hash),
            "Sent finalize transfer transaction"
        );

        Ok(tx_hash)
    }

    /// Signs transfer using the token locker
    #[tracing::instrument(skip_all, name = "SIGN TRANSFER")]
    pub async fn sign_transfer(
        &self,
        origin_nonce: u128,
        fee_recipient: Option<AccountId>,
        fee: Option<Fee>,
    ) -> Result<FinalExecutionOutcomeView> {
        let near_endpoint = self.near_endpoint()?;

        let outcome = near_rpc_client::change_and_wait_for_outcome(
            near_endpoint,
            self.near_signer()?,
            self.token_locker_id()?.to_string(),
            "sign_transfer".to_string(),
            serde_json::json!({
                "nonce": origin_nonce.to_string(),
                "fee_recipient": fee_recipient,
                "fee": fee,
            })
            .to_string()
            .into_bytes(),
            300_000_000_000_000,
            500_000_000_000_000_000_000_000,
        )
        .await?;

        tracing::info!(
            tx_hash = format!("{:?}", outcome.transaction.hash),
            "Sent sign transfer transaction"
        );

        Ok(outcome)
    }

    /// Claims fee on NEAR chain using the token locker
    #[tracing::instrument(skip_all, name = "CLAIM FEE")]
    pub async fn claim_fee(&self, args: ClaimFeeArgs) -> Result<FinalExecutionOutcomeView> {
        let near_endpoint = self.near_endpoint()?;
        let token_locker_id = self.token_locker_id()?;

        let outcome = near_rpc_client::change_and_wait_for_outcome(
            near_endpoint,
            self.near_signer()?,
            token_locker_id.to_string(),
            "claim_fee".to_string(),
            borsh::to_vec(&args).map_err(|_| BridgeSdkError::UnknownError)?,
            300_000_000_000_000,
            200_000_000_000_000_000_000_000,
        )
        .await?;

        tracing::info!(
            tx_hash = format!("{:?}", outcome.transaction.hash),
            "Sent claim fee request"
        );

        Ok(outcome)
    }

    pub async fn bind_token_with_evm_prover(&self, tx_hash: TxHash) -> Result<CryptoHash> {
        let eth_endpoint = self.eth_endpoint()?;

        let event_topic = H256::from_str(&hex::encode(Keccak256::digest(
            "DeployToken(address,string,string,string,uint8)".as_bytes(),
        )))
        .map_err(|_| BridgeSdkError::UnknownError)?;

        let proof = eth_proof::get_proof_for_event(tx_hash, event_topic, eth_endpoint).await?;

        let evm_verify_proof_args = EvmVerifyProofArgs {
            proof_kind: ProofKind::DeployToken,
            proof,
        };

        let mut proof_args = Vec::new();
        evm_verify_proof_args
            .serialize(&mut proof_args)
            .map_err(|_| BridgeSdkError::EthProofError("Failed to serialize proof".to_string()))?;

        self.bind_token(BindTokenArgs {
            chain_kind: ChainKind::Eth,
            prover_args: proof_args,
        })
        .await
    }

    #[tracing::instrument(skip_all, name = "BIND TOKEN")]
    pub async fn bind_token(&self, args: BindTokenArgs) -> Result<CryptoHash> {
        let near_endpoint = self.near_endpoint()?;
        let token_locker_id = self.token_locker_id()?;

        let mut serialized_args = Vec::new();
        args.serialize(&mut serialized_args)
            .map_err(|_| BridgeSdkError::UnknownError)?;

        let tx_id = near_rpc_client::change(
            near_endpoint,
            self.near_signer()?,
            token_locker_id.to_string(),
            "bind_token".to_string(),
            serialized_args,
            300_000_000_000_000,
            200_000_000_000_000_000_000_000,
        )
        .await?;

        tracing::info!(
            tx_hash = format!("{:?}", tx_id),
            "Sent bind token transaction"
        );

        Ok(tx_id)
    }

    /// Signs claiming native fee on NEAR chain using the token locker
    #[tracing::instrument(skip_all, name = "SIGN NATIVE CLAIM FEE")]
    pub async fn sign_claim_native_fee(
        &self,
        nonces: Vec<u128>,
        recipient: OmniAddress,
    ) -> Result<FinalExecutionOutcomeView> {
        let near_endpoint = self.near_endpoint()?;
        let token_locker_id = self.token_locker_id()?;

        let outcome = near_rpc_client::change_and_wait_for_outcome(
            near_endpoint,
            self.near_signer()?,
            token_locker_id.to_string(),
            "sign_claim_native_fee".to_string(),
            json!({
                "nonces": nonces.iter().map(ToString::to_string).collect::<Vec<_>>(),
                "recipient": recipient
            })
            .to_string()
            .into_bytes(),
            300_000_000_000_000,
            500_000_000_000_000_000_000_000,
        )
        .await?;

        tracing::info!(
            tx_hash = format!("{:?}", outcome.transaction.hash),
            "Sent claim native fee request"
        );

        Ok(outcome)
    }

    /// Claims fee on Ethereum chain
    #[tracing::instrument(skip_all, name = "EVM CLAIM NATIVE FEE")]
    pub async fn evm_claim_native_fee(
        &self,
        transaction_hash: CryptoHash,
        sender_id: Option<AccountId>,
    ) -> Result<TxHash> {
        let transfer_log = self
            .extract_transfer_log(transaction_hash, sender_id, "SignClaimNativeFeeEvent")
            .await?;

        self.evm_claim_native_fee_with_log(
            serde_json::from_str(&transfer_log).map_err(|_| BridgeSdkError::UnknownError)?,
        )
        .await
    }

    #[tracing::instrument(skip_all, name = "EVM CLAIM NATIVE FEE WITH LOG")]
    pub async fn evm_claim_native_fee_with_log(
        &self,
        transfer_log: Nep141LockerEvent,
    ) -> Result<TxHash> {
        let factory = self.bridge_token_factory()?;

        let Nep141LockerEvent::SignClaimNativeFeeEvent {
            signature,
            claim_payload,
        } = transfer_log
        else {
            return Err(BridgeSdkError::UnknownError);
        };

        let (OmniAddress::Eth(recipient)
        | OmniAddress::Base(recipient)
        | OmniAddress::Arb(recipient)) = claim_payload.recipient
        else {
            return Err(BridgeSdkError::UnknownError);
        };

        let payload = ClaimFeePayload {
            nonces: claim_payload.nonces.into_iter().map(Into::into).collect(),
            amount: claim_payload.amount.into(),
            recipient: H160(recipient.0),
        };

        let serialized_signature = signature.to_bytes();

        assert!(serialized_signature.len() == 65);

        let call = factory
            .claim_native_fee(serialized_signature.into(), payload)
            .gas(500_000);
        let tx = call.send().await?;

        tracing::info!(
            tx_hash = format!("{:?}", tx.tx_hash()),
            "Sent claim native fee transaction"
        );

        Ok(tx.tx_hash())
    }

    pub async fn storage_deposit(&self, amount: u128) -> Result<()> {
        let near_endpoint = self.near_endpoint()?;
        let token_locker_id = self.token_locker_id()?;

        let tx = near_rpc_client::change_and_wait_for_outcome(
            near_endpoint,
            self.near_signer()?,
            token_locker_id.to_string(),
            "storage_deposit".to_string(),
            json!({
                "account_id": None::<AccountId>
            })
            .to_string()
            .into_bytes(),
            10_000_000_000_000,
            amount,
        )
        .await?;

        if let FinalExecutionStatus::Failure(_) = tx.status {
            return Err(BridgeSdkError::UnknownError);
        }

        tracing::info!(
            tx_hash = format!("{:?}", tx.transaction.hash),
            "Sent storage deposit transaction"
        );

        Ok(())
    }

    pub async fn get_storage_balance(&self) -> Result<u128> {
        let near_endpoint = self.near_endpoint()?;
        let token_locker_id = self.token_locker_id_as_account_id()?;

        let response = near_rpc_client::view(
            near_endpoint,
            token_locker_id,
            "storage_balance_of".to_string(),
            serde_json::json!({
                "account_id": self.near_account_id()?
            }),
        )
        .await?;

        let storage_balance: Option<StorageBalance> = serde_json::from_slice(&response)?;

        match storage_balance {
            Some(balance) => Ok(balance.available.as_yoctonear()),
            None => Ok(0),
        }
    }

    pub async fn get_required_balance_for_account(&self) -> Result<u128> {
        let near_endpoint = self.near_endpoint()?;
        let token_locker_id = self.token_locker_id_as_account_id()?;

        let response = near_rpc_client::view(
            near_endpoint,
            token_locker_id,
            "required_balance_for_account".to_string(),
            serde_json::Value::Null,
        )
        .await?;

        let required_balance: NearToken = serde_json::from_slice(&response)?;
        Ok(required_balance.as_yoctonear())
    }

    pub async fn get_required_balance_for_init_transfer(
        &self,
        recipient: &str,
        sender: &str,
    ) -> Result<u128> {
        let near_endpoint = self.near_endpoint()?;
        let token_locker_id = self.token_locker_id_as_account_id()?;

        let response = near_rpc_client::view(
            near_endpoint,
            token_locker_id,
            "required_balance_for_init_transfer".to_string(),
            serde_json::json!({
                "recipient": recipient,
                "sender": format!("near:{}", sender)
            }),
        )
        .await?;

        let required_balance: NearToken = serde_json::from_slice(&response)?;
        Ok(required_balance.as_yoctonear())
    }

    async fn extract_transfer_log(
        &self,
        transaction_hash: CryptoHash,
        sender_id: Option<AccountId>,
        event_name: &str,
    ) -> Result<String> {
        let near_endpoint = self.near_endpoint()?;

        let sender_id = match sender_id {
            Some(id) => id,
            None => self.near_account_id()?,
        };
        let sign_tx = near_rpc_client::wait_for_tx_final_outcome(
            transaction_hash,
            sender_id,
            near_endpoint,
            30,
        )
        .await?;

        let transfer_log = sign_tx
            .receipts_outcome
            .iter()
            .find(|receipt| {
                !receipt.outcome.logs.is_empty() && receipt.outcome.logs[0].contains(event_name)
            })
            .ok_or(BridgeSdkError::UnknownError)?
            .outcome
            .logs[0]
            .clone();

        Ok(transfer_log)
    }

    fn eth_endpoint(&self) -> Result<&str> {
        Ok(self
            .eth_endpoint
            .as_ref()
            .ok_or(BridgeSdkError::ConfigError(
                "Ethereum rpc endpoint is not set".to_string(),
            ))?)
    }

    fn near_endpoint(&self) -> Result<&str> {
        Ok(self
            .near_endpoint
            .as_ref()
            .ok_or(BridgeSdkError::ConfigError(
                "Near rpc endpoint is not set".to_string(),
            ))?)
    }

    fn token_locker_id(&self) -> Result<&str> {
        Ok(self
            .token_locker_id
            .as_ref()
            .ok_or(BridgeSdkError::ConfigError(
                "Token locker account id is not set".to_string(),
            ))?)
    }

    fn token_locker_id_as_account_id(&self) -> Result<AccountId> {
        self.token_locker_id()?
            .parse::<AccountId>()
            .map_err(|_| BridgeSdkError::ConfigError("Invalid token locker account id".to_string()))
    }

    fn bridge_token_factory_address(&self) -> Result<Address> {
        self.bridge_token_factory_address
            .as_ref()
            .ok_or(BridgeSdkError::ConfigError(
                "Bridge token factory address is not set".to_string(),
            ))
            .and_then(|addr| {
                Address::from_str(addr).map_err(|_| {
                    BridgeSdkError::ConfigError(
                        "bridge_token_factory_address is not a valid Ethereum address".to_string(),
                    )
                })
            })
    }

    fn near_account_id(&self) -> Result<AccountId> {
        self.near_signer
            .as_ref()
            .ok_or(BridgeSdkError::ConfigError(
                "Near signer account id is not set".to_string(),
            ))?
            .parse::<AccountId>()
            .map_err(|_| BridgeSdkError::ConfigError("Invalid near signer account id".to_string()))
    }

    fn near_signer(&self) -> Result<near_crypto::InMemorySigner> {
        let near_private_key =
            self.near_private_key
                .as_ref()
                .ok_or(BridgeSdkError::ConfigError(
                    "Near account private key is not set".to_string(),
                ))?;
        let near_signer_id = self.near_account_id()?;

        Ok(near_crypto::InMemorySigner::from_secret_key(
            near_signer_id,
            SecretKey::from_str(near_private_key)
                .map_err(|_| BridgeSdkError::ConfigError("Invalid near private key".to_string()))?,
        ))
    }

    fn bridge_token_factory(
        &self,
    ) -> Result<BridgeTokenFactory<SignerMiddleware<Provider<Http>, LocalWallet>>> {
        let eth_endpoint = self.eth_endpoint()?;

        let eth_provider = Provider::<Http>::try_from(eth_endpoint).map_err(|_| {
            BridgeSdkError::ConfigError("Invalid ethereum rpc endpoint url".to_string())
        })?;

        let wallet = self.eth_signer()?;

        let signer = SignerMiddleware::new(eth_provider, wallet);
        let client = Arc::new(signer);

        Ok(BridgeTokenFactory::new(
            self.bridge_token_factory_address()?,
            client,
        ))
    }

    fn bridge_token(
        &self,
        address: Address,
    ) -> Result<ERC20<SignerMiddleware<Provider<Http>, LocalWallet>>> {
        let eth_endpoint = self.eth_endpoint()?;

        let eth_provider = Provider::<Http>::try_from(eth_endpoint).map_err(|_| {
            BridgeSdkError::ConfigError("Invalid ethereum rpc endpoint url".to_string())
        })?;

        let wallet = self.eth_signer()?;

        let signer = SignerMiddleware::new(eth_provider, wallet);
        let client = Arc::new(signer);

        Ok(ERC20::new(address, client))
    }

    fn eth_signer(&self) -> Result<LocalWallet> {
        let eth_private_key = self
            .eth_private_key
            .as_ref()
            .ok_or(BridgeSdkError::ConfigError(
                "Ethereum private key is not set".to_string(),
            ))?;

        let eth_chain_id = self
            .eth_chain_id
            .as_ref()
            .ok_or(BridgeSdkError::ConfigError(
                "Ethereum chain id is not set".to_string(),
            ))?;

        let private_key_bytes = hex::decode(eth_private_key).map_err(|_| {
            BridgeSdkError::ConfigError(
                "Ethereum private key is not a valid hex string".to_string(),
            )
        })?;

        if private_key_bytes.len() != 32 {
            return Err(BridgeSdkError::ConfigError(
                "Ethereum private key is of invalid length".to_string(),
            ));
        }

        Ok(LocalWallet::from_bytes(&private_key_bytes)
            .map_err(|_| BridgeSdkError::ConfigError("Invalid ethereum private key".to_string()))?
            .with_chain_id(*eth_chain_id))
    }
}
