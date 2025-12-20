use std::collections::HashMap;
use std::str::FromStr;

use bridge_connector_common::result::{BridgeSdkError, Result};
use derive_builder::Builder;
use near_contract_standards::storage_management::StorageBalance;
use near_crypto::{SecretKey, Signer};
use near_primitives::{hash::CryptoHash, types::AccountId, views::TxExecutionStatus};
use near_sdk::json_types::U128;
use near_rpc_client::{ChangeRequest, ViewRequest};
use near_token::NearToken;
use omni_types::{
    locker_args::{BindTokenArgs, ClaimFeeArgs, DeployTokenArgs, FinTransferArgs},
    ChainKind, FastTransferId, FastTransferStatus, Fee, OmniAddress, TransferId, TransferMessage,
};
use serde_json::json;

pub mod btc;

const STORAGE_DEPOSIT_GAS: u64 = 10_000_000_000_000;

const LOG_METADATA_GAS: u64 = 300_000_000_000_000;

const DEPLOY_TOKEN_GAS: u64 = 300_000_000_000_000;

const BIND_TOKEN_GAS: u64 = 300_000_000_000_000;

const SIGN_TRANSFER_GAS: u64 = 300_000_000_000_000;

const INIT_TRANSFER_GAS: u64 = 300_000_000_000_000;

const FIN_TRANSFER_GAS: u64 = 300_000_000_000_000;

const CLAIM_FEE_GAS: u64 = 300_000_000_000_000;
const CLAIM_FEE_DEPOSIT: u128 = 1;

const FAST_FIN_TRANSFER_GAS: u64 = 300_000_000_000_000;

const MPC_DEPOSIT: u128 = 1;
const FT_TRANSFER_DEPOSIT: u128 = 1;

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct Decimals {
    pub decimals: u8,
    pub origin_decimals: u8,
}

#[derive(Clone)]
pub struct TransactionOptions {
    pub nonce: Option<u64>,
    pub wait_until: TxExecutionStatus,
    pub wait_final_outcome_timeout_sec: Option<u64>,
}

impl Default for TransactionOptions {
    fn default() -> Self {
        Self {
            nonce: None,
            wait_until: TxExecutionStatus::Final,
            wait_final_outcome_timeout_sec: None,
        }
    }
}

#[derive(serde::Deserialize)]
struct StorageBalanceBounds {
    min: NearToken,
}

#[derive(serde::Serialize)]
pub struct FastFinTransferArgs {
    pub token_id: AccountId,
    pub amount_to_send: u128,
    pub transfer_id: TransferId,
    pub recipient: OmniAddress,
    pub amount: u128,
    pub fee: Fee,
    pub msg: String,
    pub storage_deposit_amount: Option<u128>,
    pub relayer: AccountId,
}

#[derive(Default, Clone)]
pub struct UTXOChainAccounts {
    #[doc = r"UTXO Chain Connector account id on Near"]
    pub utxo_chain_connector: Option<AccountId>,
    #[doc = r"UTXO Chain Token account id on Near"]
    pub utxo_chain_token: Option<AccountId>,
    #[doc = r"Satoshi Relayer Account Id which sign transaction in UTXO Chain Bridge"]
    pub satoshi_relayer: Option<AccountId>,
}

/// Bridging NEAR-originated NEP-141 tokens
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct TransferFee {
    pub native_token_fee: U128,
    pub transferred_token_fee: Option<U128>,
    pub gas_fee: Option<U128>,
    pub usd_fee: Option<f64>,
}

#[derive(Builder, Default, Clone)]
pub struct NearBridgeClient {
    #[doc = r"NEAR RPC endpoint"]
    endpoint: Option<String>,
    #[doc = r"NEAR private key"]
    private_key: Option<String>,
    #[doc = r"NEAR account id of the transaction signer"]
    signer: Option<AccountId>,
    #[doc = r"`OmniBridge` account id on Near"]
    omni_bridge_id: Option<AccountId>,
    #[doc = r"Accounts Id for UTXO chains Bridges"]
    pub utxo_bridges: HashMap<ChainKind, UTXOChainAccounts>,
    pub bridge_indexer_api_url: Option<String>,
}

impl NearBridgeClient {
    pub async fn get_transfer_message(&self, transfer_id: TransferId) -> Result<TransferMessage> {
        let endpoint = self.endpoint()?;
        let token_id = self.omni_bridge_id()?;

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
        let token_id = self.omni_bridge_id()?;

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
        let token_id = self.omni_bridge_id()?;

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

    pub async fn get_token_decimals(&self, token_address: OmniAddress) -> Result<Decimals> {
        let endpoint = self.endpoint()?;
        let token_id = self.omni_bridge_id()?;

        let response = near_rpc_client::view(
            endpoint,
            ViewRequest {
                contract_account_id: token_id,
                method_name: "get_token_decimals".to_string(),
                args: serde_json::json!({
                    "address": token_address
                }),
            },
        )
        .await?;

        let token_id = serde_json::from_slice::<Decimals>(&response)?;

        Ok(token_id)
    }

    pub async fn get_native_token_id(&self, origin_chain: ChainKind) -> Result<AccountId> {
        let endpoint = self.endpoint()?;
        let token_id = self.omni_bridge_id()?;

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

    pub async fn get_fast_transfer_status(
        &self,
        fast_transfer_id: FastTransferId,
    ) -> Result<Option<FastTransferStatus>> {
        let endpoint = self.endpoint()?;
        let omni_bridge_id = self.omni_bridge_id()?;

        let response = near_rpc_client::view(
            endpoint,
            ViewRequest {
                contract_account_id: omni_bridge_id,
                method_name: "get_fast_transfer_status".to_string(),
                args: serde_json::json!({
                    "fast_transfer_id": fast_transfer_id
                }),
            },
        )
        .await?;

        let status = serde_json::from_slice::<Option<FastTransferStatus>>(&response)?;
        Ok(status)
    }

    pub async fn is_fast_transfer_finalised(
        &self,
        fast_transfer_id: FastTransferId,
    ) -> Result<bool> {
        let endpoint = self.endpoint()?;
        let omni_bridge_id = self.omni_bridge_id()?;

        let response = near_rpc_client::view(
            endpoint,
            ViewRequest {
                contract_account_id: omni_bridge_id,
                method_name: "is_fast_transfer_finalised".to_string(),
                args: serde_json::json!({
                    "fast_transfer_id": fast_transfer_id
                }),
            },
        )
        .await?;

        let is_finalised = serde_json::from_slice::<bool>(&response)?;
        Ok(is_finalised)
    }

    pub async fn get_storage_balance(
        &self,
        contract_id: AccountId,
        account_id: AccountId,
    ) -> Result<StorageBalance> {
        let endpoint = self.endpoint()?;

        let response = near_rpc_client::view(
            endpoint,
            ViewRequest {
                contract_account_id: contract_id,
                method_name: "storage_balance_of".to_string(),
                args: serde_json::json!({
                    "account_id": account_id
                }),
            },
        )
        .await?;

        let storage_balance: Option<StorageBalance> = serde_json::from_slice(&response)?;

        Ok(storage_balance.unwrap_or(StorageBalance {
            total: NearToken::from_yoctonear(0),
            available: NearToken::from_yoctonear(0),
        }))
    }

    pub async fn get_required_balance_for_account(&self) -> Result<u128> {
        let endpoint = self.endpoint()?;
        let omni_bridge_id = self.omni_bridge_id()?;

        let response = near_rpc_client::view(
            endpoint,
            ViewRequest {
                contract_account_id: omni_bridge_id,
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

        let total_balance = self.get_storage_balance(token_id, account_id).await?.total;

        Ok(storage_balance_bounds
            .min
            .saturating_sub(total_balance)
            .as_yoctonear())
    }

    /// Performs a storage deposit on behalf of the `OmniBridge` so that the tokens can be transferred to the bridge contract. To be called once for each NEP-141
    #[tracing::instrument(skip_all, name = "STORAGE DEPOSIT")]
    pub async fn storage_deposit_for_token(
        &self,
        token_id: AccountId,
        account_id: AccountId,
        amount: u128,
        transaction_options: TransactionOptions,
    ) -> Result<CryptoHash> {
        let endpoint = self.endpoint()?;

        let tx_hash = near_rpc_client::change_and_wait(
            endpoint,
            ChangeRequest {
                signer: self.signer()?,
                nonce: transaction_options.nonce,
                receiver_id: token_id,
                method_name: "storage_deposit".to_string(),
                args: serde_json::json!({
                    "account_id": account_id
                })
                .to_string()
                .into_bytes(),
                gas: STORAGE_DEPOSIT_GAS,
                deposit: amount,
            },
            transaction_options.wait_until,
            transaction_options.wait_final_outcome_timeout_sec,
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
    ) -> Result<CryptoHash> {
        let endpoint = self.endpoint()?;
        let omni_bridge_id = self.omni_bridge_id()?;

        let tx_hash = near_rpc_client::change_and_wait(
            endpoint,
            ChangeRequest {
                signer: self.signer()?,
                nonce: transaction_options.nonce,
                receiver_id: omni_bridge_id,
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
            transaction_options.wait_final_outcome_timeout_sec,
        )
        .await?;

        tracing::info!(
            tx_hash = tx_hash.to_string(),
            "Sent storage deposit transaction"
        );

        Ok(tx_hash)
    }

    /// Logs token metadata to `OmniBridge` contract. The proof from this transaction is then used to deploy a corresponding token on other chains
    #[tracing::instrument(skip_all, name = "LOG METADATA")]
    pub async fn log_token_metadata(
        &self,
        token_id: String,
        transaction_options: TransactionOptions,
    ) -> Result<CryptoHash> {
        let endpoint = self.endpoint()?;

        let tx_hash = near_rpc_client::change_and_wait(
            endpoint,
            ChangeRequest {
                signer: self.signer()?,
                nonce: transaction_options.nonce,
                receiver_id: self.omni_bridge_id()?,
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
            transaction_options.wait_final_outcome_timeout_sec,
        )
        .await?;

        tracing::info!(tx_hash = tx_hash.to_string(), "Sent log transaction");

        Ok(tx_hash)
    }

    /// Deploys a token on the target chain using the vaa proof
    #[tracing::instrument(skip_all, name = "DEPLOY TOKEN")]
    pub async fn deploy_token_with_vaa_proof(
        &self,
        chain_kind: ChainKind,
        vaa: &str,
        transaction_options: TransactionOptions,
    ) -> Result<CryptoHash> {
        let endpoint = self.endpoint()?;
        let omni_bridge_id = self.omni_bridge_id()?;

        let deposit = self.get_required_balance_for_deploy_token().await?;

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
                receiver_id: omni_bridge_id,
                method_name: "deploy_token".to_string(),
                args: borsh::to_vec(&args)
                    .map_err(|err| BridgeSdkError::UnknownError(err.to_string()))?,
                gas: DEPLOY_TOKEN_GAS,
                deposit,
            },
            transaction_options.wait_until,
            transaction_options.wait_final_outcome_timeout_sec,
        )
        .await?;

        tracing::info!(
            tx_hash = tx_hash.to_string(),
            "Sent deploy token transaction"
        );

        Ok(tx_hash)
    }

    /// Deploys a token on the target chain using the evm proof
    #[tracing::instrument(skip_all, name = "DEPLOY TOKEN")]
    pub async fn deploy_token_with_evm_proof(
        &self,
        args: DeployTokenArgs,
        transaction_options: TransactionOptions,
    ) -> Result<CryptoHash> {
        let endpoint = self.endpoint()?;
        let omni_bridge_id = self.omni_bridge_id()?;

        let deposit = self.get_required_balance_for_deploy_token().await?;

        let tx_hash = near_rpc_client::change_and_wait(
            endpoint,
            ChangeRequest {
                signer: self.signer()?,
                nonce: transaction_options.nonce,
                receiver_id: omni_bridge_id,
                method_name: "deploy_token".to_string(),
                args: borsh::to_vec(&args)
                    .map_err(|err| BridgeSdkError::UnknownError(err.to_string()))?,
                gas: DEPLOY_TOKEN_GAS,
                deposit,
            },
            transaction_options.wait_until,
            transaction_options.wait_final_outcome_timeout_sec,
        )
        .await?;

        tracing::info!(
            tx_hash = tx_hash.to_string(),
            "Sent deploy token transaction"
        );

        Ok(tx_hash)
    }

    /// Binds token on NEAR chain using `OmniBridge`
    #[tracing::instrument(skip_all, name = "BIND TOKEN")]
    pub async fn bind_token(
        &self,
        args: BindTokenArgs,
        transaction_options: TransactionOptions,
    ) -> Result<CryptoHash> {
        let endpoint = self.endpoint()?;
        let omni_bridge_id = self.omni_bridge_id()?;

        let deposit = self.get_required_balance_for_bind_token().await?;

        let tx_hash = near_rpc_client::change_and_wait(
            endpoint,
            ChangeRequest {
                signer: self.signer()?,
                nonce: transaction_options.nonce,
                receiver_id: omni_bridge_id,
                method_name: "bind_token".to_string(),
                args: borsh::to_vec(&args)
                    .map_err(|err| BridgeSdkError::UnknownError(err.to_string()))?,
                gas: BIND_TOKEN_GAS,
                deposit,
            },
            transaction_options.wait_until,
            transaction_options.wait_final_outcome_timeout_sec,
        )
        .await?;

        tracing::info!(tx_hash = tx_hash.to_string(), "Sent bind token transaction");
        Ok(tx_hash)
    }

    /// Signs transfer using `OmniBridge`
    #[tracing::instrument(skip_all, name = "SIGN TRANSFER")]
    pub async fn sign_transfer(
        &self,
        transfer_id: TransferId,
        fee_recipient: Option<AccountId>,
        fee: Option<Fee>,
        transaction_options: TransactionOptions,
    ) -> Result<CryptoHash> {
        let endpoint = self.endpoint()?;

        let tx_hash = near_rpc_client::change_and_wait(
            endpoint,
            ChangeRequest {
                signer: self.signer()?,
                nonce: transaction_options.nonce,
                receiver_id: self.omni_bridge_id()?,
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
            transaction_options.wait_final_outcome_timeout_sec,
        )
        .await?;

        tracing::info!(
            tx_hash = tx_hash.to_string(),
            "Sent sign transfer transaction"
        );
        Ok(tx_hash)
    }

    /// Fetches the transfer fee from the Bridge Indexer API
    pub async fn get_transfer_fee(
        &self,
        sender: &OmniAddress,
        recipient: &OmniAddress,
        token: &OmniAddress,
    ) -> Result<(u128, u128)> {
        let Some(api_url) = &self.bridge_indexer_api_url else {
            return Err(BridgeSdkError::ConfigError(
                "Bridge indexer API URL is not configured; provide it or specify fees".to_string(),
            ));
        };

        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .map_err(|e| BridgeSdkError::UnknownError(e.to_string()))?;
        let response = client
            .get(format!("{}/api/v3/transfer-fee", api_url))
            .query(&[
                ("sender", sender.to_string()),
                ("recipient", recipient.to_string()),
                ("token", token.to_string()),
            ])
            .send()
            .await
            .map_err(|e| BridgeSdkError::UnknownError(e.to_string()))?;

        let transfer_fee: TransferFee = response
            .error_for_status()
            .map_err(|e| BridgeSdkError::UnknownError(e.to_string()))?
            .json()
            .await
            .map_err(|e| BridgeSdkError::UnknownError(e.to_string()))?;

        let fee = transfer_fee
            .transferred_token_fee
            .ok_or_else(|| {
                BridgeSdkError::UnknownError(
                    "Missing transferred_token_fee in indexer response".to_string(),
                )
            })?
            .0;
        let native_fee = transfer_fee.native_token_fee.0;

        Ok((fee, native_fee))
    }

    #[tracing::instrument(skip_all, name = "NEAR INIT TRANSFER")]
    #[allow(clippy::too_many_arguments)]
    pub async fn init_transfer(
        &self,
        token_id: String,
        amount: u128,
        receiver: OmniAddress,
        fee: Option<u128>,
        native_fee: Option<u128>,
        transaction_options: TransactionOptions,
    ) -> Result<CryptoHash> {
        let endpoint = self.endpoint()?;
        let omni_bridge_id = self.omni_bridge_id()?;

        let sender = OmniAddress::Near(self.account_id()?);
        let token = OmniAddress::Near(token_id.parse().map_err(|err| {
            BridgeSdkError::ConfigError(format!("Failed to parse token_id: {err}"))
        })?);

        // Optimization: Skip API call if both fees are provided
        let (fee, native_fee) = if let (Some(fee), Some(native_fee)) = (fee, native_fee) {
            (fee, native_fee)
        } else {
            let (calculated_fee, calculated_native_fee) = self
                .get_transfer_fee(&sender, &receiver, &token)
                .await?;
            (
                fee.unwrap_or(calculated_fee),
                native_fee.unwrap_or(calculated_native_fee),
            )
        };

        if amount == 0 {
            return Err(BridgeSdkError::ConfigError(
                "Transfer amount must be greater than 0".to_string(),
            ));
        }

        if fee == 0 && native_fee == 0 {
            tracing::warn!("Transfer initiated with 0 fee. This transaction may be rejected by the relayer.");
        }

        let required_balance = self
            .get_required_balance_for_init_transfer()
            .await?
            .saturating_add(native_fee);

        let nonce = if self
            .deposit_storage_if_required(required_balance, transaction_options.clone())
            .await?
        {
            transaction_options.nonce.map(|nonce| nonce + 1)
        } else {
            transaction_options.nonce
        };

        let tx_hash = near_rpc_client::change_and_wait(
            endpoint,
            ChangeRequest {
                signer: self.signer()?,
                nonce,
                receiver_id: token_id.parse().map_err(|err| {
                    BridgeSdkError::ConfigError(format!("Failed to parse token_id: {err}"))
                })?,
                method_name: "ft_transfer_call".to_string(),
                args: serde_json::json!({
                    "receiver_id": omni_bridge_id,
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
                deposit: FT_TRANSFER_DEPOSIT,
            },
            transaction_options.wait_until,
            transaction_options.wait_final_outcome_timeout_sec,
        )
        .await?;

        tracing::info!(tx_hash = tx_hash.to_string(), "Sent transfer transaction");
        Ok(tx_hash)
    }

    /// Withdraws NEP-141 tokens from `OmniBridge`. Requires a proof from the burn transaction
    #[tracing::instrument(skip_all, name = "NEAR FIN TRANSFER")]
    pub async fn fin_transfer(
        &self,
        destination_chain: ChainKind,
        args: FinTransferArgs,
        transaction_options: TransactionOptions,
    ) -> Result<CryptoHash> {
        let endpoint = self.endpoint()?;

        let mut required_deposit = self.get_required_balance_for_fin_transfer().await?;

        for storage_deposit_action in args.storage_deposit_actions.clone() {
            if let Some(amount) = storage_deposit_action.storage_deposit_amount {
                required_deposit += amount;
            }
        }

        if destination_chain != ChainKind::Near {
            required_deposit += self.get_required_balance_for_init_transfer().await?;
        }

        let tx_hash = near_rpc_client::change_and_wait(
            endpoint,
            ChangeRequest {
                signer: self.signer()?,
                nonce: transaction_options.nonce,
                receiver_id: self.omni_bridge_id()?,
                method_name: "fin_transfer".to_string(),
                args: borsh::to_vec(&args)
                    .map_err(|err| BridgeSdkError::UnknownError(err.to_string()))?,
                gas: FIN_TRANSFER_GAS,
                deposit: required_deposit,
            },
            transaction_options.wait_until,
            transaction_options.wait_final_outcome_timeout_sec,
        )
        .await?;

        tracing::info!(
            tx_hash = tx_hash.to_string(),
            "Sent finalize transfer transaction"
        );
        Ok(tx_hash)
    }

    /// Claims fee on NEAR chain
    #[tracing::instrument(skip_all, name = "CLAIM FEE")]
    pub async fn claim_fee(
        &self,
        args: ClaimFeeArgs,
        transaction_options: TransactionOptions,
    ) -> Result<CryptoHash> {
        let endpoint = self.endpoint()?;
        let omni_bridge_id = self.omni_bridge_id()?;

        let tx_hash = near_rpc_client::change_and_wait(
            endpoint,
            ChangeRequest {
                signer: self.signer()?,
                nonce: transaction_options.nonce,
                receiver_id: omni_bridge_id,
                method_name: "claim_fee".to_string(),
                args: borsh::to_vec(&args)
                    .map_err(|err| BridgeSdkError::UnknownError(err.to_string()))?,
                gas: CLAIM_FEE_GAS,
                deposit: CLAIM_FEE_DEPOSIT,
            },
            transaction_options.wait_until,
            transaction_options.wait_final_outcome_timeout_sec,
        )
        .await?;

        tracing::info!(tx_hash = tx_hash.to_string(), "Sent claim fee request");
        Ok(tx_hash)
    }

    /// Fast finalize transfer on NEAR
    #[tracing::instrument(skip_all, name = "FAST FIN TRANSFER")]
    pub async fn fast_fin_transfer(
        &self,
        args: FastFinTransferArgs,
        transaction_options: TransactionOptions,
    ) -> Result<CryptoHash> {
        let endpoint = self.endpoint()?;
        let omni_bridge_id = self.omni_bridge_id()?;

        let tx_hash = near_rpc_client::change_and_wait(
            endpoint,
            ChangeRequest {
                signer: self.signer()?,
                nonce: transaction_options.nonce,
                receiver_id: args.token_id,
                method_name: "ft_transfer_call".to_string(),
                args: serde_json::json!({
                    "receiver_id": omni_bridge_id,
                    "amount": args.amount_to_send.to_string(),
                    "msg": serde_json::json!({
                        "FastFinTransfer": {
                            "recipient": args.recipient,
                            "amount": args.amount.to_string(),
                            "fee": args.fee,
                            "transfer_id": args.transfer_id,
                            "msg": args.msg,
                            "storage_deposit_amount": args.storage_deposit_amount,
                            "relayer": args.relayer,
                        }
                    })
                    .to_string()
                })
                .to_string()
                .into_bytes(),
                gas: FAST_FIN_TRANSFER_GAS,
                deposit: FT_TRANSFER_DEPOSIT,
            },
            transaction_options.wait_until,
            transaction_options.wait_final_outcome_timeout_sec,
        )
        .await?;

        tracing::info!(
            tx_hash = tx_hash.to_string(),
            "Sent fast finalize transfer transaction"
        );
        Ok(tx_hash)
    }

    pub async fn ft_balance_of(&self, token_id: AccountId, account_id: AccountId) -> Result<u128> {
        let endpoint = self.endpoint()?;

        let response = near_rpc_client::view(
            endpoint,
            ViewRequest {
                contract_account_id: token_id,
                method_name: "ft_balance_of".to_string(),
                args: serde_json::json!({
                    "account_id": account_id
                }),
            },
        )
        .await?;

        let balance = serde_json::from_slice::<NearToken>(&response)?;
        Ok(balance.as_yoctonear())
    }

    pub async fn get_required_balance(&self, method_name: &str) -> Result<u128> {
        let endpoint = self.endpoint()?;
        let omni_bridge_id = self.omni_bridge_id()?;

        let response = near_rpc_client::view(
            endpoint,
            ViewRequest {
                contract_account_id: omni_bridge_id,
                method_name: method_name.to_string(),
                args: serde_json::json!({}),
            },
        )
        .await?;

        let required_balance = serde_json::from_slice::<NearToken>(&response)?;
        Ok(required_balance.as_yoctonear())
    }

    pub async fn get_required_balance_for_deploy_token(&self) -> Result<u128> {
        self.get_required_balance("required_balance_for_deploy_token")
            .await
    }

    pub async fn get_required_balance_for_bind_token(&self) -> Result<u128> {
        self.get_required_balance("required_balance_for_bind_token")
            .await
    }

    pub async fn get_required_balance_for_init_transfer(&self) -> Result<u128> {
        self.get_required_balance("required_balance_for_init_transfer")
            .await
    }

    pub async fn get_required_balance_for_fin_transfer(&self) -> Result<u128> {
        self.get_required_balance("required_balance_for_fin_transfer")
            .await
    }

    pub async fn get_required_balance_for_fast_fin_transfer(&self) -> Result<u128> {
        self.get_required_balance("required_balance_for_fast_transfer")
            .await
    }

    pub async fn deposit_storage_if_required(
        &self,
        required_balance: u128,
        transaction_options: TransactionOptions,
    ) -> Result<bool> {
        let existing_balance = self
            .get_storage_balance(self.omni_bridge_id()?, self.account_id()?)
            .await?
            .available
            .as_yoctonear();

        if existing_balance < required_balance {
            self.storage_deposit(
                required_balance - existing_balance,
                TransactionOptions {
                    nonce: transaction_options.nonce,
                    wait_until: TxExecutionStatus::Final,
                    wait_final_outcome_timeout_sec: transaction_options
                        .wait_final_outcome_timeout_sec,
                },
            )
            .await?;

            Ok(true)
        } else {
            Ok(false)
        }
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
            .find_map(|receipt| {
                receipt
                    .outcome
                    .logs
                    .iter()
                    .find(|log| log.contains(event_name))
                    .cloned()
            })
            .ok_or(BridgeSdkError::UnknownError(
                "Failed to find correct receipt".to_string(),
            ))?;

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
            ))
            .map_err(|_| BridgeSdkError::ConfigError("Invalid near signer account id".to_string()))
            .cloned()
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

    pub fn omni_bridge_id(&self) -> Result<AccountId> {
        self.omni_bridge_id
            .as_ref()
            .ok_or(BridgeSdkError::ConfigError(
                "OmniBridge account id is not set".to_string(),
            ))
            .map_err(|_| BridgeSdkError::ConfigError("Invalid omni bridge account id".to_string()))
            .cloned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use httpmock::prelude::*;

    #[test]
    fn test_bridge_indexer_fee_response_parsing() {
        let json_response = r#"{
            "native_token_fee": "1000",
            "transferred_token_fee": "500",
            "gas_fee": "250",
            "usd_fee": 0.1
        }"#;

        let fee: TransferFee = serde_json::from_str(json_response).expect("Failed to deserialize TransferFee");

        assert_eq!(fee.native_token_fee.0, 1000);
        assert_eq!(fee.transferred_token_fee.unwrap().0, 500);
        assert_eq!(fee.gas_fee.unwrap().0, 250);
        assert!((fee.usd_fee.unwrap() - 0.1).abs() < f64::EPSILON);
    }

    #[tokio::test]
    async fn test_get_transfer_fee_from_indexer() {
        let server = MockServer::start();

        let mock = server.mock(|when, then| {
            when.method(GET)
                .path("/api/v3/transfer-fee")
                .query_param("sender", "near:alice.near")
                .query_param("recipient", "near:bob.near")
                .query_param("token", "near:wrap.near");
            then.status(200)
                .header("content-type", "application/json")
                .body(
                    r#"{
                        "native_token_fee": "1000",
                        "transferred_token_fee": "500",
                        "gas_fee": "250",
                        "usd_fee": 0.1
                    }"#,
                );
        });

        let client = NearBridgeClient {
            bridge_indexer_api_url: Some(server.base_url()),
            ..Default::default()
        };

        let sender = OmniAddress::Near("alice.near".parse().unwrap());
        let recipient = OmniAddress::Near("bob.near".parse().unwrap());
        let token = OmniAddress::Near("wrap.near".parse().unwrap());

        let (fee, native_fee) = client
            .get_transfer_fee(&sender, &recipient, &token)
            .await
            .expect("Expected fee fetch to succeed");

        assert_eq!(fee, 500);
        assert_eq!(native_fee, 1000);
        mock.assert();
    }
}
