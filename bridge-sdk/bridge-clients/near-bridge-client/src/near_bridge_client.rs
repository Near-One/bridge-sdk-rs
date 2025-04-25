use std::str::FromStr;

use bridge_connector_common::result::{BridgeSdkError, Result};
use derive_builder::Builder;
use near_contract_standards::storage_management::StorageBalance;
use near_crypto::{SecretKey, Signer};
use near_primitives::{hash::CryptoHash, types::AccountId, views::TxExecutionStatus};
use near_primitives::types::Gas;
use near_rpc_client::{ChangeRequest, ViewRequest};
use near_sdk::json_types::U128;
use near_token::NearToken;
use omni_types::{
    locker_args::{BindTokenArgs, ClaimFeeArgs, DeployTokenArgs, FinTransferArgs},
    ChainKind, Fee, OmniAddress, TransferId, TransferMessage,
};
use serde_json::json;

const STORAGE_DEPOSIT_GAS: u64 = 10_000_000_000_000;

const LOG_METADATA_GAS: u64 = 300_000_000_000_000;

const DEPLOY_TOKEN_GAS: u64 = 300_000_000_000_000;
const DEPLOY_TOKEN_DEPOSIT: u128 = 4_000_000_000_000_000_000_000_000;

const BIND_TOKEN_GAS: u64 = 300_000_000_000_000;
const BIND_TOKEN_DEPOSIT: u128 = 200_000_000_000_000_000_000_000;

const SIGN_TRANSFER_GAS: u64 = 300_000_000_000_000;

const INIT_TRANSFER_GAS: u64 = 300_000_000_000_000;
const INIT_TRANSFER_DEPOSIT: u128 = 1;

const FIN_TRANSFER_GAS: u64 = 300_000_000_000_000;
const FIN_TRANSFER_DEPOSIT: u128 = 600_000_000_000_000_000_000;

const FIN_BTC_TRANSFER_GAS: u64 = 300_000_000_000_000;

const CLAIM_FEE_GAS: u64 = 300_000_000_000_000;
const CLAIM_FEE_DEPOSIT: u128 = 1;

const MPC_DEPOSIT: u128 = 1;

pub struct TransactionOptions {
    pub nonce: Option<u64>,
    pub wait_until: TxExecutionStatus,
}

impl Default for TransactionOptions {
    fn default() -> Self {
        Self {
            nonce: None,
            wait_until: TxExecutionStatus::Final,
        }
    }
}

#[derive(serde::Deserialize)]
struct StorageBalanceBounds {
    min: NearToken,
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct PostAction {
    pub receiver_id: AccountId,
    pub amount: U128,
    pub memo: Option<String>,
    pub msg: String,
    pub gas: Option<Gas>,
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct DepositMsg {
    pub recipient_id: AccountId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub post_actions: Option<Vec<PostAction>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extra_msg: Option<String>,
}


#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct FinBtcTransferArgs {
    pub deposit_msg: DepositMsg,
    pub tx_bytes: Vec<u8>,
    pub vout: usize,
    pub tx_block_blockhash: String,
    pub tx_index: u64,
    pub merkle_proof: Vec<String>,
}

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
    #[doc = r"BTC Connector account id on Near"]
    btc_connector: Option<String>,
}

impl NearBridgeClient {
    pub async fn get_transfer_message(&self, transfer_id: TransferId) -> Result<TransferMessage> {
        let endpoint = self.endpoint()?;
        let token_id = self.token_locker_id()?;

        let response = near_rpc_client::view(
            endpoint,
            ViewRequest {
                contract_account_id: token_id,
                method_name: "get_transfer_message".to_string(),
                args: serde_json::json!({
                    "transfer_id": transfer_id
                }),
            },
        )
        .await?;

        let transfer_message = serde_json::from_slice::<TransferMessage>(&response)?;

        Ok(transfer_message)
    }

    pub async fn is_transfer_finalised(&self, transfer_id: TransferId) -> Result<bool> {
        let endpoint = self.endpoint()?;
        let token_id = self.token_locker_id()?;

        let response = near_rpc_client::view(
            endpoint,
            ViewRequest {
                contract_account_id: token_id,
                method_name: "is_transfer_finalised".to_string(),
                args: serde_json::json!({
                    "transfer_id": transfer_id
                }),
            },
        )
        .await?;

        let is_transfer_finalised = serde_json::from_slice::<bool>(&response)?;

        Ok(is_transfer_finalised)
    }

    pub async fn get_token_id(&self, token_address: OmniAddress) -> Result<AccountId> {
        let endpoint = self.endpoint()?;
        let token_id = self.token_locker_id()?;

        let response = near_rpc_client::view(
            endpoint,
            ViewRequest {
                contract_account_id: token_id,
                method_name: "get_token_id".to_string(),
                args: serde_json::json!({
                    "address": token_address
                }),
            },
        )
        .await?;

        let token_id = serde_json::from_slice::<AccountId>(&response)?;

        Ok(token_id)
    }

    pub async fn get_native_token_id(&self, origin_chain: ChainKind) -> Result<AccountId> {
        let endpoint = self.endpoint()?;
        let token_id = self.token_locker_id()?;

        let response = near_rpc_client::view(
            endpoint,
            ViewRequest {
                contract_account_id: token_id,
                method_name: "get_native_token_id".to_string(),
                args: serde_json::json!({
                    "chain": origin_chain
                }),
            },
        )
        .await?;

        let token_id = serde_json::from_slice::<AccountId>(&response)?;

        Ok(token_id)
    }

    pub async fn get_storage_balance(
        &self,
        token_id: AccountId,
        account_id: AccountId,
    ) -> Result<u128> {
        let endpoint = self.endpoint()?;

        let response = near_rpc_client::view(
            endpoint,
            ViewRequest {
                contract_account_id: token_id,
                method_name: "storage_balance_of".to_string(),
                args: serde_json::json!({
                    "account_id": account_id
                }),
            },
        )
        .await?;

        let storage_balance: Option<StorageBalance> = serde_json::from_slice(&response)?;

        storage_balance.map_or(Ok(0), |balance| Ok(balance.total.as_yoctonear()))
    }

    pub async fn get_required_balance_for_account(&self) -> Result<u128> {
        let endpoint = self.endpoint()?;
        let token_locker_id = self.token_locker_id()?;

        let response = near_rpc_client::view(
            endpoint,
            ViewRequest {
                contract_account_id: token_locker_id,
                method_name: "required_balance_for_account".to_string(),
                args: serde_json::Value::Null,
            },
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
            ViewRequest {
                contract_account_id: token_id.clone(),
                method_name: "storage_balance_bounds".to_string(),
                args: serde_json::Value::Null,
            },
        )
        .await?;

        let storage_balance_bounds = serde_json::from_slice::<StorageBalanceBounds>(&response)?;

        let total_balance =
            NearToken::from_yoctonear(self.get_storage_balance(token_id, account_id).await?);

        Ok(storage_balance_bounds
            .min
            .saturating_sub(total_balance)
            .as_yoctonear())
    }

    /// Performs a storage deposit on behalf of the token_locker so that the tokens can be transferred to the locker. To be called once for each NEP-141
    #[tracing::instrument(skip_all, name = "STORAGE DEPOSIT")]
    pub async fn storage_deposit_for_token(
        &self,
        token_id: String,
        amount: u128,
        transaction_options: TransactionOptions,
        wait_final_outcome_timeout_sec: Option<u64>,
    ) -> Result<CryptoHash> {
        let endpoint = self.endpoint()?;
        let token_locker = self.token_locker_id()?;

        let tx_hash = near_rpc_client::change_and_wait(
            endpoint,
            ChangeRequest {
                signer: self.signer()?,
                nonce: transaction_options.nonce,
                receiver_id: token_id.parse().map_err(|err| {
                    BridgeSdkError::ConfigError(format!("Failed to parse token_id: {err}"))
                })?,
                method_name: "storage_deposit".to_string(),
                args: serde_json::json!({
                    "account_id": token_locker
                })
                .to_string()
                .into_bytes(),
                gas: STORAGE_DEPOSIT_GAS,
                deposit: amount,
            },
            transaction_options.wait_until,
            wait_final_outcome_timeout_sec,
        )
        .await?;

        tracing::info!(
            tx_hash = tx_hash.to_string(),
            "Sent storage deposit transaction"
        );

        Ok(tx_hash)
    }

    pub async fn storage_deposit(
        &self,
        amount: u128,
        transaction_options: TransactionOptions,
        wait_final_outcome_timeout_sec: Option<u64>,
    ) -> Result<CryptoHash> {
        let endpoint = self.endpoint()?;
        let token_locker_id = self.token_locker_id()?;

        let tx_hash = near_rpc_client::change_and_wait(
            endpoint,
            ChangeRequest {
                signer: self.signer()?,
                nonce: transaction_options.nonce,
                receiver_id: token_locker_id,
                method_name: "storage_deposit".to_string(),
                args: json!({
                    "account_id": None::<AccountId>
                })
                .to_string()
                .into_bytes(),
                gas: STORAGE_DEPOSIT_GAS,
                deposit: amount,
            },
            transaction_options.wait_until,
            wait_final_outcome_timeout_sec,
        )
        .await?;

        tracing::info!(
            tx_hash = tx_hash.to_string(),
            "Sent storage deposit transaction"
        );

        Ok(tx_hash)
    }

    /// Logs token metadata to token_locker contract. The proof from this transaction is then used to deploy a corresponding token on other chains
    #[tracing::instrument(skip_all, name = "LOG METADATA")]
    pub async fn log_token_metadata(
        &self,
        token_id: String,
        transaction_options: TransactionOptions,
        wait_final_outcome_timeout_sec: Option<u64>,
    ) -> Result<CryptoHash> {
        let endpoint = self.endpoint()?;

        let tx_hash = near_rpc_client::change_and_wait(
            endpoint,
            ChangeRequest {
                signer: self.signer()?,
                nonce: transaction_options.nonce,
                receiver_id: self.token_locker_id()?,
                method_name: "log_metadata".to_string(),
                args: serde_json::json!({
                    "token_id": token_id
                })
                .to_string()
                .into_bytes(),
                gas: LOG_METADATA_GAS,
                deposit: MPC_DEPOSIT,
            },
            transaction_options.wait_until,
            wait_final_outcome_timeout_sec,
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
        transaction_options: TransactionOptions,
        wait_final_outcome_timeout_sec: Option<u64>,
    ) -> Result<CryptoHash> {
        let endpoint = self.endpoint()?;
        let token_locker_id = self.token_locker_id()?;

        let prover_args = omni_types::prover_args::WormholeVerifyProofArgs {
            proof_kind: omni_types::prover_result::ProofKind::LogMetadata,
            vaa: vaa.to_owned(),
        };

        let args = DeployTokenArgs {
            chain_kind,
            prover_args: borsh::to_vec(&prover_args).unwrap(),
        };

        let tx_hash = near_rpc_client::change_and_wait(
            endpoint,
            ChangeRequest {
                signer: self.signer()?,
                nonce: transaction_options.nonce,
                receiver_id: token_locker_id,
                method_name: "deploy_token".to_string(),
                args: borsh::to_vec(&args)
                    .map_err(|err| BridgeSdkError::UnknownError(err.to_string()))?,
                gas: DEPLOY_TOKEN_GAS,
                deposit: DEPLOY_TOKEN_DEPOSIT,
            },
            transaction_options.wait_until,
            wait_final_outcome_timeout_sec,
        )
        .await?;

        tracing::info!(
            tx_hash = tx_hash.to_string(),
            "Sent deploy token transaction"
        );

        Ok(tx_hash)
    }

    /// Deploys a token on the target chain using the evm proof
    pub async fn deploy_token_with_evm_proof(
        &self,
        args: DeployTokenArgs,
        transaction_options: TransactionOptions,
        wait_final_outcome_timeout_sec: Option<u64>,
    ) -> Result<CryptoHash> {
        let endpoint = self.endpoint()?;
        let token_locker_id = self.token_locker_id()?;

        let tx_hash = near_rpc_client::change_and_wait(
            endpoint,
            ChangeRequest {
                signer: self.signer()?,
                nonce: transaction_options.nonce,
                receiver_id: token_locker_id,
                method_name: "deploy_token".to_string(),
                args: borsh::to_vec(&args)
                    .map_err(|err| BridgeSdkError::UnknownError(err.to_string()))?,
                gas: DEPLOY_TOKEN_GAS,
                deposit: DEPLOY_TOKEN_DEPOSIT,
            },
            transaction_options.wait_until,
            wait_final_outcome_timeout_sec,
        )
        .await?;

        tracing::info!(
            tx_hash = tx_hash.to_string(),
            "Sent deploy token transaction"
        );

        Ok(tx_hash)
    }

    /// Binds token on NEAR chain using the token locker
    #[tracing::instrument(skip_all, name = "BIND TOKEN")]
    pub async fn bind_token(
        &self,
        args: BindTokenArgs,
        transaction_options: TransactionOptions,
        wait_final_outcome_timeout_sec: Option<u64>,
    ) -> Result<CryptoHash> {
        let endpoint = self.endpoint()?;
        let token_locker_id = self.token_locker_id()?;

        let tx_hash = near_rpc_client::change_and_wait(
            endpoint,
            ChangeRequest {
                signer: self.signer()?,
                nonce: transaction_options.nonce,
                receiver_id: token_locker_id,
                method_name: "bind_token".to_string(),
                args: borsh::to_vec(&args)
                    .map_err(|err| BridgeSdkError::UnknownError(err.to_string()))?,
                gas: BIND_TOKEN_GAS,
                deposit: BIND_TOKEN_DEPOSIT,
            },
            transaction_options.wait_until,
            wait_final_outcome_timeout_sec,
        )
        .await?;

        tracing::info!(tx_hash = tx_hash.to_string(), "Sent bind token transaction");
        Ok(tx_hash)
    }

    /// Signs transfer using the token locker
    #[tracing::instrument(skip_all, name = "SIGN TRANSFER")]
    pub async fn sign_transfer(
        &self,
        transfer_id: TransferId,
        fee_recipient: Option<AccountId>,
        fee: Option<Fee>,
        transaction_options: TransactionOptions,
        wait_final_outcome_timeout_sec: Option<u64>,
    ) -> Result<CryptoHash> {
        let endpoint = self.endpoint()?;

        let tx_hash = near_rpc_client::change_and_wait(
            endpoint,
            ChangeRequest {
                signer: self.signer()?,
                nonce: transaction_options.nonce,
                receiver_id: self.token_locker_id()?,
                method_name: "sign_transfer".to_string(),
                args: serde_json::json!({
                    "transfer_id": transfer_id,
                    "fee_recipient": fee_recipient,
                    "fee": fee,
                })
                .to_string()
                .into_bytes(),
                gas: SIGN_TRANSFER_GAS,
                deposit: MPC_DEPOSIT,
            },
            transaction_options.wait_until,
            wait_final_outcome_timeout_sec,
        )
        .await?;

        tracing::info!(
            tx_hash = tx_hash.to_string(),
            "Sent sign transfer transaction"
        );
        Ok(tx_hash)
    }

    /// Gets the required balance for the init transfer
    pub async fn get_required_balance_for_init_transfer(
        &self,
        recipient: &OmniAddress,
        sender: &OmniAddress,
    ) -> Result<u128> {
        let endpoint = self.endpoint()?;
        let token_locker_id = self.token_locker_id()?;

        let response = near_rpc_client::view(
            endpoint,
            ViewRequest {
                contract_account_id: token_locker_id,
                method_name: "required_balance_for_init_transfer".to_string(),
                args: serde_json::json!({
                    "recipient": recipient,
                    "sender": format!("near:{}", sender)
                }),
            },
        )
        .await?;

        let required_balance = serde_json::from_slice::<NearToken>(&response)?;
        Ok(required_balance.as_yoctonear())
    }

    /// Transfers NEP-141 tokens to the token locker. The proof from this transaction is then used to mint the corresponding tokens on Ethereum
    #[tracing::instrument(skip_all, name = "NEAR INIT TRANSFER")]
    #[allow(clippy::too_many_arguments)]
    pub async fn init_transfer(
        &self,
        token_id: String,
        amount: u128,
        receiver: OmniAddress,
        fee: u128,
        native_fee: u128,
        transaction_options: TransactionOptions,
        wait_final_outcome_timeout_sec: Option<u64>,
    ) -> Result<CryptoHash> {
        let endpoint = self.endpoint()?;
        let token_locker = self.token_locker_id()?;

        let required_balance = self
            .get_required_balance_for_init_transfer(
                &receiver,
                &OmniAddress::Near(self.account_id()?),
            )
            .await?
            + self.get_required_balance_for_account().await?;
        let existing_balance = self
            .get_storage_balance(token_locker.clone(), self.account_id()?)
            .await?;

        if existing_balance < required_balance {
            self.storage_deposit(
                required_balance - existing_balance,
                TransactionOptions {
                    nonce: transaction_options.nonce,
                    wait_until: TxExecutionStatus::Final,
                },
                wait_final_outcome_timeout_sec,
            )
            .await?;
        }

        let tx_hash = near_rpc_client::change_and_wait(
            endpoint,
            ChangeRequest {
                signer: self.signer()?,
                // Increment nonce since previous was used for storage deposit
                nonce: transaction_options.nonce.map(|nonce| nonce + 1),
                receiver_id: token_id.parse().map_err(|err| {
                    BridgeSdkError::ConfigError(format!("Failed to parse token_id: {err}"))
                })?,
                method_name: "ft_transfer_call".to_string(),
                args: serde_json::json!({
                    "receiver_id": token_locker,
                    "amount": amount.to_string(),
                    "msg": serde_json::json!({
                        "recipient": receiver,
                        "fee": fee.to_string(),
                        "native_token_fee": native_fee.to_string()
                    })
                    .to_string()
                })
                .to_string()
                .into_bytes(),
                gas: INIT_TRANSFER_GAS,
                deposit: INIT_TRANSFER_DEPOSIT,
            },
            transaction_options.wait_until,
            wait_final_outcome_timeout_sec,
        )
        .await?;

        tracing::info!(tx_hash = tx_hash.to_string(), "Sent transfer transaction");
        Ok(tx_hash)
    }

    /// Withdraws NEP-141 tokens from the token locker. Requires a proof from the burn transaction
    #[tracing::instrument(skip_all, name = "NEAR FIN TRANSFER")]
    pub async fn fin_transfer(
        &self,
        args: FinTransferArgs,
        transaction_options: TransactionOptions,
        wait_final_outcome_timeout_sec: Option<u64>,
    ) -> Result<CryptoHash> {
        let endpoint = self.endpoint()?;

        let mut required_deposit = FIN_TRANSFER_DEPOSIT;
        for storage_deposit_action in args.storage_deposit_actions.clone() {
            if let Some(amount) = storage_deposit_action.storage_deposit_amount {
                required_deposit += amount;
            }
        }

        let tx_hash = near_rpc_client::change_and_wait(
            endpoint,
            ChangeRequest {
                signer: self.signer()?,
                nonce: transaction_options.nonce,
                receiver_id: self.token_locker_id()?,
                method_name: "fin_transfer".to_string(),
                args: borsh::to_vec(&args)
                    .map_err(|err| BridgeSdkError::UnknownError(err.to_string()))?,
                gas: FIN_TRANSFER_GAS,
                deposit: required_deposit,
            },
            transaction_options.wait_until,
            wait_final_outcome_timeout_sec,
        )
        .await?;

        tracing::info!(
            tx_hash = tx_hash.to_string(),
            "Sent finalize transfer transaction"
        );
        Ok(tx_hash)
    }

    pub async fn fin_btc_transfer(&self,
                                  args: FinBtcTransferArgs,
                                  transaction_options: TransactionOptions,
                                  wait_final_outcome_timeout_sec: Option<u64>) -> Result<CryptoHash> {
        let endpoint = self.endpoint()?;
        let btc_connector = self.btc_connector()?;
        let tx_hash = near_rpc_client::change_and_wait(
            endpoint,
            ChangeRequest {
                signer: self.signer()?,
                nonce: transaction_options.nonce,
                receiver_id: btc_connector,
                method_name: "verify_deposit".to_string(),
                args: serde_json::json!(args)
                    .to_string()
                    .into_bytes(),
                gas: FIN_BTC_TRANSFER_GAS,
                deposit: 0,
            },
            transaction_options.wait_until,
            wait_final_outcome_timeout_sec,
        ).await?;

        tracing::info!(
            tx_hash = tx_hash.to_string(),
            "Sent BTC finalize transfer transaction"
        );
        Ok(tx_hash)
    }

    /// Claims fee on NEAR chain using the token locker
    #[tracing::instrument(skip_all, name = "CLAIM FEE")]
    pub async fn claim_fee(
        &self,
        args: ClaimFeeArgs,
        transaction_options: TransactionOptions,
        wait_final_outcome_timeout_sec: Option<u64>,
    ) -> Result<CryptoHash> {
        let endpoint = self.endpoint()?;
        let token_locker_id = self.token_locker_id()?;

        let tx_hash = near_rpc_client::change_and_wait(
            endpoint,
            ChangeRequest {
                signer: self.signer()?,
                nonce: transaction_options.nonce,
                receiver_id: token_locker_id,
                method_name: "claim_fee".to_string(),
                args: borsh::to_vec(&args)
                    .map_err(|err| BridgeSdkError::UnknownError(err.to_string()))?,
                gas: CLAIM_FEE_GAS,
                deposit: CLAIM_FEE_DEPOSIT,
            },
            transaction_options.wait_until,
            wait_final_outcome_timeout_sec,
        )
        .await?;

        tracing::info!(tx_hash = tx_hash.to_string(), "Sent claim fee request");
        Ok(tx_hash)
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
        let tx_hash = near_rpc_client::wait_for_tx(
            endpoint,
            transaction_hash,
            sender_id.clone(),
            near_primitives::views::TxExecutionStatus::Final,
            60,
        )
        .await?;

        let sign_tx = near_rpc_client::get_tx_final_outcome(endpoint, tx_hash, sender_id).await?;

        let transfer_log = sign_tx
            .receipts_outcome
            .iter()
            .find(|receipt| {
                !receipt.outcome.logs.is_empty() && receipt.outcome.logs[0].contains(event_name)
            })
            .ok_or(BridgeSdkError::UnknownError(
                "Failed to find correct receipt".to_string(),
            ))?
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

        if let Signer::InMemory(signer) = near_crypto::InMemorySigner::from_secret_key(
            signer_id,
            SecretKey::from_str(private_key)
                .map_err(|_| BridgeSdkError::ConfigError("Invalid near private key".to_string()))?,
        ) {
            Ok(signer)
        } else {
            Err(BridgeSdkError::ConfigError(
                "Failed to create near signer".to_string(),
            ))
        }
    }

    pub fn token_locker_id(&self) -> Result<AccountId> {
        self.token_locker_id
            .as_ref()
            .ok_or(BridgeSdkError::ConfigError(
                "Token locker account id is not set".to_string(),
            ))?
            .parse::<AccountId>()
            .map_err(|_| BridgeSdkError::ConfigError("Invalid token locker account id".to_string()))
    }

    pub fn btc_connector(&self) -> Result<AccountId> {
        self.btc_connector
            .as_ref()
            .ok_or(BridgeSdkError::ConfigError(
                "BTC Connector account id is not set".to_string(),
            ))?
            .parse::<AccountId>()
            .map_err(|_| BridgeSdkError::ConfigError("Invalid btc connector account id".to_string()))
    }
}
