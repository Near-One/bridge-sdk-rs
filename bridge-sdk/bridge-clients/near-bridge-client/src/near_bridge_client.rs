use bridge_connector_common::result::{BridgeSdkError, Result};
use derive_builder::Builder;
use near_contract_standards::storage_management::StorageBalance;
use near_crypto::SecretKey;
use near_primitives::{
    hash::CryptoHash,
    types::AccountId,
    views::{FinalExecutionOutcomeView, FinalExecutionStatus},
};
use near_token::NearToken;
use omni_types::{
    locker_args::{BindTokenArgs, ClaimFeeArgs, DeployTokenArgs, FinTransferArgs},
    ChainKind, Fee, OmniAddress,
};
use serde_json::json;
use std::str::FromStr;

const STORAGE_DEPOSIT_GAS: u64 = 10_000_000_000_000;

const LOG_METADATA_GAS: u64 = 300_000_000_000_000;
const LOG_METADATA_DEPOSIT: u128 = 200_000_000_000_000_000_000_000;

const DEPLOY_TOKEN_WITH_VAA_GAS: u64 = 120_000_000_000_000;
const DEPLOY_TOKEN_WITH_VAA_DEPOSIT: u128 = 4_000_000_000_000_000_000_000_000;

const DEPLOY_TOKEN_WITH_EVM_PROOF_GAS: u64 = 120_000_000_000_000;
const DEPLOY_TOKEN_WITH_EVM_PROOF_DEPOSIT: u128 = 4_000_000_000_000_000_000_000_000;

const BIND_TOKEN_GAS: u64 = 300_000_000_000_000;
const BIND_TOKEN_DEPOSIT: u128 = 200_000_000_000_000_000_000_000;

const SIGN_TRANSFER_GAS: u64 = 300_000_000_000_000;
const SIGN_TRANSFER_DEPOSIT: u128 = 500_000_000_000_000_000_000_000;

const INIT_TRANSFER_GAS: u64 = 300_000_000_000_000;
const INIT_TRANSFER_DEPOSIT: u128 = 1;

const FIN_TRANSFER_GAS: u64 = 300_000_000_000_000;
const FIN_TRANSFER_DEPOSIT: u128 = 60_000_000_000_000_000_000_000;

const CLAIM_FEE_GAS: u64 = 300_000_000_000_000;
const CLAIM_FEE_DEPOSIT: u128 = 200_000_000_000_000_000_000_000;

/// Bridging NEAR-originated NEP-141 tokens
#[derive(Builder, Default, Clone)]
pub struct NearBridgeClient {
    #[doc = r"NEAR RPC endpoint"]
    endpoint: Option<String>,
    #[doc = r"NEAR private key"]
    private_key: Option<String>,
    #[doc = r"NEAR account id of the transaction signer"]
    signer: Option<String>,
    #[doc = r"Token locker account id on Near"]
    token_locker_id: Option<String>,
}

impl NearBridgeClient {
    pub async fn get_token_id(&self, token_address: OmniAddress) -> Result<AccountId> {
        let endpoint = self.endpoint()?;
        let token_id = self.token_locker_id_as_account_id()?;

        let response = near_rpc_client::view(
            endpoint,
            token_id,
            "get_token_id".to_string(),
            serde_json::json!({
                "address": token_address
            }),
        )
        .await?;

        let token_id = serde_json::from_slice::<AccountId>(&response)?;

        Ok(token_id)
    }

    pub async fn get_native_token_id(&self, origin_chain: ChainKind) -> Result<AccountId> {
        let endpoint = self.endpoint()?;
        let token_id = self.token_locker_id_as_account_id()?;

        let response = near_rpc_client::view(
            endpoint,
            token_id,
            "get_native_token_id".to_string(),
            serde_json::json!({
                "origin_chain": origin_chain
            }),
        )
        .await?;

        let token_id = serde_json::from_slice::<AccountId>(&response)?;

        Ok(token_id)
    }

    pub async fn get_storage_balance(&self, account_id: AccountId) -> Result<u128> {
        let endpoint = self.endpoint()?;
        let token_locker_id = self.token_locker_id_as_account_id()?;

        let response = near_rpc_client::view(
            endpoint,
            token_locker_id,
            "storage_balance_of".to_string(),
            serde_json::json!({
                "account_id": account_id
            }),
        )
        .await?;

        let storage_balance: Option<StorageBalance> = serde_json::from_slice(&response)?;

        storage_balance.map_or(Ok(0), |balance| Ok(balance.available.as_yoctonear()))
    }

    pub async fn get_required_balance_for_account(&self) -> Result<u128> {
        let endpoint = self.endpoint()?;
        let token_locker_id = self.token_locker_id_as_account_id()?;

        let response = near_rpc_client::view(
            endpoint,
            token_locker_id,
            "required_balance_for_account".to_string(),
            serde_json::Value::Null,
        )
        .await?;

        let required_balance: NearToken = serde_json::from_slice(&response)?;
        Ok(required_balance.as_yoctonear())
    }

    pub async fn get_required_storage_deposit(
        &self,
        token_id: AccountId,
        account_id: AccountId,
    ) -> Result<u128> {
        let endpoint = self.endpoint()?;

        let response = near_rpc_client::view(
            endpoint,
            token_id.clone(),
            "storage_minimum_balance".to_string(),
            serde_json::Value::Null,
        )
        .await?;

        let storage_minimum_balance = serde_json::from_slice::<NearToken>(&response)?;

        let total_balance = NearToken::from_yoctonear(self.get_storage_balance(account_id).await?);

        Ok(storage_minimum_balance
            .saturating_sub(total_balance)
            .as_yoctonear())
    }

    /// Performs a storage deposit on behalf of the token_locker so that the tokens can be transferred to the locker. To be called once for each NEP-141
    #[tracing::instrument(skip_all, name = "STORAGE DEPOSIT")]
    pub async fn storage_deposit_for_token(
        &self,
        token_id: String,
        amount: u128,
    ) -> Result<CryptoHash> {
        let endpoint = self.endpoint()?;
        let token_locker = self.token_locker_id_as_str()?;

        let tx_hash = near_rpc_client::change(
            endpoint,
            self.signer()?,
            token_id,
            "storage_deposit".to_string(),
            serde_json::json!({
                "account_id": token_locker
            })
            .to_string()
            .into_bytes(),
            STORAGE_DEPOSIT_GAS,
            amount,
        )
        .await?;

        tracing::info!(
            tx_hash = tx_hash.to_string(),
            "Sent storage deposit transaction"
        );

        Ok(tx_hash)
    }

    pub async fn storage_deposit(&self, amount: u128) -> Result<()> {
        let endpoint = self.endpoint()?;
        let token_locker_id = self.token_locker_id_as_str()?;

        let tx = near_rpc_client::change_and_wait_for_outcome(
            endpoint,
            self.signer()?,
            token_locker_id.to_string(),
            "storage_deposit".to_string(),
            json!({
                "account_id": None::<AccountId>
            })
            .to_string()
            .into_bytes(),
            STORAGE_DEPOSIT_GAS,
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

    /// Logs token metadata to token_locker contract. The proof from this transaction is then used to deploy a corresponding token on other chains
    #[tracing::instrument(skip_all, name = "LOG METADATA")]
    pub async fn log_token_metadata(&self, token_id: String) -> Result<CryptoHash> {
        let endpoint = self.endpoint()?;

        let tx_hash = near_rpc_client::change(
            endpoint,
            self.signer()?,
            self.token_locker_id_as_str()?.to_string(),
            "log_metadata".to_string(),
            serde_json::json!({
                "token_id": token_id
            })
            .to_string()
            .into_bytes(),
            LOG_METADATA_GAS,
            LOG_METADATA_DEPOSIT,
        )
        .await?;

        tracing::info!(tx_hash = tx_hash.to_string(), "Sent log transaction");

        Ok(tx_hash)
    }

    /// Deploys a token on the target chain using the vaa proof
    pub async fn deploy_token_with_vaa_proof(
        &self,
        chain_kind: ChainKind,
        vaa: &str,
    ) -> Result<CryptoHash> {
        let endpoint = self.endpoint()?;
        let token_locker_id = self.token_locker_id_as_str()?;

        let prover_args = omni_types::prover_args::WormholeVerifyProofArgs {
            proof_kind: omni_types::prover_result::ProofKind::LogMetadata,
            vaa: vaa.to_owned(),
        };

        let args = DeployTokenArgs {
            chain_kind,
            prover_args: borsh::to_vec(&prover_args).unwrap(),
        };

        let tx_hash = near_rpc_client::change(
            endpoint,
            self.signer()?,
            token_locker_id.to_string(),
            "deploy_token".to_string(),
            borsh::to_vec(&args).map_err(|_| BridgeSdkError::UnknownError)?,
            DEPLOY_TOKEN_WITH_VAA_GAS,
            DEPLOY_TOKEN_WITH_VAA_DEPOSIT,
        )
        .await?;

        tracing::info!(
            tx_hash = format!("{:?}", tx_hash),
            "Sent deploy token transaction"
        );

        Ok(tx_hash)
    }

    /// Deploys a token on the target chain using the evm proof
    pub async fn deploy_token_with_evm_proof(&self, args: DeployTokenArgs) -> Result<CryptoHash> {
        let endpoint = self.endpoint()?;
        let token_locker_id = self.token_locker_id_as_str()?;

        let tx_hash = near_rpc_client::change(
            endpoint,
            self.signer()?,
            token_locker_id.to_string(),
            "deploy_token".to_string(),
            borsh::to_vec(&args).map_err(|_| BridgeSdkError::UnknownError)?,
            DEPLOY_TOKEN_WITH_EVM_PROOF_GAS,
            DEPLOY_TOKEN_WITH_EVM_PROOF_DEPOSIT,
        )
        .await?;

        tracing::info!(
            tx_hash = format!("{:?}", tx_hash),
            "Sent deploy token transaction"
        );

        Ok(tx_hash)
    }

    /// Binds token on NEAR chain using the token locker
    #[tracing::instrument(skip_all, name = "BIND TOKEN")]
    pub async fn bind_token(&self, args: BindTokenArgs) -> Result<CryptoHash> {
        let endpoint = self.endpoint()?;
        let token_locker_id = self.token_locker_id_as_str()?;

        let tx_hash = near_rpc_client::change(
            endpoint,
            self.signer()?,
            token_locker_id.to_string(),
            "bind_token".to_string(),
            borsh::to_vec(&args).map_err(|_| BridgeSdkError::UnknownError)?,
            BIND_TOKEN_GAS,
            BIND_TOKEN_DEPOSIT,
        )
        .await?;

        tracing::info!(
            tx_hash = format!("{:?}", tx_hash),
            "Sent bind token transaction"
        );

        Ok(tx_hash)
    }

    /// Signs transfer using the token locker
    #[tracing::instrument(skip_all, name = "SIGN TRANSFER")]
    pub async fn sign_transfer(
        &self,
        origin_nonce: u64,
        fee_recipient: Option<AccountId>,
        fee: Option<Fee>,
    ) -> Result<FinalExecutionOutcomeView> {
        let endpoint = self.endpoint()?;

        let outcome = near_rpc_client::change_and_wait_for_outcome(
            endpoint,
            self.signer()?,
            self.token_locker_id_as_str()?.to_string(),
            "sign_transfer".to_string(),
            serde_json::json!({
                "transfer_id": {
                "origin_chain": ChainKind::Near, // TODO: provide transfer_id instead of only nonce
                    "origin_nonce": origin_nonce
                },
                "fee_recipient": fee_recipient,
                "fee": fee,
            })
            .to_string()
            .into_bytes(),
            SIGN_TRANSFER_GAS,
            SIGN_TRANSFER_DEPOSIT, // TODO: make a contract call to signer account to determine the required deposit
        )
        .await?;

        tracing::info!(
            tx_hash = format!("{:?}", outcome.transaction.hash),
            "Sent sign transfer transaction"
        );

        Ok(outcome)
    }

    /// Gets the required balance for the init transfer
    pub async fn get_required_balance_for_init_transfer(
        &self,
        recipient: &str,
        sender: &str,
    ) -> Result<u128> {
        let endpoint = self.endpoint()?;
        let token_locker_id = self.token_locker_id_as_account_id()?;

        let response = near_rpc_client::view(
            endpoint,
            token_locker_id,
            "required_balance_for_init_transfer".to_string(),
            serde_json::json!({
                "recipient": recipient,
                "sender": format!("near:{}", sender)
            }),
        )
        .await?;

        let required_balance = serde_json::from_slice::<NearToken>(&response)?;
        Ok(required_balance.as_yoctonear())
    }

    /// Transfers NEP-141 tokens to the token locker. The proof from this transaction is then used to mint the corresponding tokens on Ethereum
    #[tracing::instrument(skip_all, name = "NEAR INIT TRANSFER")]
    pub async fn init_transfer(
        &self,
        token_id: String,
        amount: u128,
        receiver: String,
    ) -> Result<CryptoHash> {
        let endpoint = self.endpoint()?;
        let token_locker = self.token_locker_id_as_str()?;

        let required_balance = self
            .get_required_balance_for_init_transfer(&receiver, self.account_id()?.as_str())
            .await?
            + self.get_required_balance_for_account().await?;
        let existing_balance = self.get_storage_balance(self.account_id()?).await?;

        if existing_balance < required_balance {
            self.storage_deposit(required_balance - existing_balance)
                .await?;
        }

        let fee = 0;
        let native_fee = 0;

        let tx_hash = near_rpc_client::change(
            endpoint,
            self.signer()?,
            token_id,
            "ft_transfer_call".to_string(),
            serde_json::json!({
                "receiver_id": token_locker,
                "amount": amount.to_string(),
                "msg": serde_json::json!({
                    "recipient": receiver,
                    "fee": fee,
                    "native_token_fee": native_fee
                })
            })
            .to_string()
            .into_bytes(),
            INIT_TRANSFER_GAS,
            INIT_TRANSFER_DEPOSIT,
        )
        .await?;

        tracing::info!(
            tx_hash = format!("{:?}", tx_hash),
            "Sent transfer transaction"
        );

        Ok(tx_hash)
    }

    /// Withdraws NEP-141 tokens from the token locker. Requires a proof from the burn transaction
    #[tracing::instrument(skip_all, name = "NEAR FIN TRANSFER")]
    pub async fn fin_transfer(&self, args: FinTransferArgs) -> Result<CryptoHash> {
        let endpoint = self.endpoint()?;

        let tx_hash = near_rpc_client::change(
            endpoint,
            self.signer()?,
            self.token_locker_id_as_str()?.to_string(),
            "fin_transfer".to_string(),
            borsh::to_vec(&args).map_err(|_| BridgeSdkError::UnknownError)?,
            FIN_TRANSFER_GAS,
            FIN_TRANSFER_DEPOSIT,
        )
        .await?;

        tracing::info!(
            tx_hash = format!("{:?}", tx_hash),
            "Sent finalize transfer transaction"
        );

        Ok(tx_hash)
    }

    /// Claims fee on NEAR chain using the token locker
    #[tracing::instrument(skip_all, name = "CLAIM FEE")]
    pub async fn claim_fee(&self, args: ClaimFeeArgs) -> Result<FinalExecutionOutcomeView> {
        let endpoint = self.endpoint()?;
        let token_locker_id = self.token_locker_id_as_str()?;

        let outcome = near_rpc_client::change_and_wait_for_outcome(
            endpoint,
            self.signer()?,
            token_locker_id.to_string(),
            "claim_fee".to_string(),
            borsh::to_vec(&args).map_err(|_| BridgeSdkError::UnknownError)?,
            CLAIM_FEE_GAS,
            CLAIM_FEE_DEPOSIT,
        )
        .await?;

        tracing::info!(
            tx_hash = format!("{:?}", outcome.transaction.hash),
            "Sent claim fee request"
        );

        Ok(outcome)
    }

    pub async fn extract_transfer_log(
        &self,
        transaction_hash: CryptoHash,
        sender_id: Option<AccountId>,
        event_name: &str,
    ) -> Result<String> {
        let endpoint = self.endpoint()?;

        let sender_id = match sender_id {
            Some(id) => id,
            None => self.account_id()?,
        };
        let sign_tx =
            near_rpc_client::wait_for_tx_final_outcome(transaction_hash, sender_id, endpoint, 30)
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

    pub fn endpoint(&self) -> Result<&str> {
        Ok(self.endpoint.as_ref().ok_or(BridgeSdkError::ConfigError(
            "Near rpc endpoint is not set".to_string(),
        ))?)
    }

    pub fn account_id(&self) -> Result<AccountId> {
        self.signer
            .as_ref()
            .ok_or(BridgeSdkError::ConfigError(
                "Near signer account id is not set".to_string(),
            ))?
            .parse::<AccountId>()
            .map_err(|_| BridgeSdkError::ConfigError("Invalid near signer account id".to_string()))
    }

    pub fn signer(&self) -> Result<near_crypto::InMemorySigner> {
        let private_key = self
            .private_key
            .as_ref()
            .ok_or(BridgeSdkError::ConfigError(
                "Near account private key is not set".to_string(),
            ))?;
        let signer_id = self.account_id()?;

        Ok(near_crypto::InMemorySigner::from_secret_key(
            signer_id,
            SecretKey::from_str(private_key)
                .map_err(|_| BridgeSdkError::ConfigError("Invalid near private key".to_string()))?,
        ))
    }

    pub fn token_locker_id_as_str(&self) -> Result<&str> {
        Ok(self
            .token_locker_id
            .as_ref()
            .ok_or(BridgeSdkError::ConfigError(
                "Token locker account id is not set".to_string(),
            ))?)
    }

    pub fn token_locker_id_as_account_id(&self) -> Result<AccountId> {
        self.token_locker_id_as_str()?
            .parse::<AccountId>()
            .map_err(|_| BridgeSdkError::ConfigError("Invalid token locker account id".to_string()))
    }
}
