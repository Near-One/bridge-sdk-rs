use crate::NearBridgeClient;
use crate::TransactionOptions;
use bitcoin::{OutPoint, TxOut};
use bridge_connector_common::result::{BridgeSdkError, Result};
use btc_utils::UTXO;
use near_primitives::types::Gas;
use near_primitives::{hash::CryptoHash, types::AccountId};
use near_rpc_client::{ChangeRequest, ViewRequest};
use serde_json::{json, Value};
use serde_with::{serde_as, DisplayFromStr};
use std::cmp::max;
use std::collections::HashMap;
use std::str::FromStr;

const INIT_BTC_TRANSFER_GAS: u64 = 300_000_000_000_000;
const ACTIVE_UTXO_MANAGEMENT_GAS: u64 = 300_000_000_000_000;
const SIGN_BTC_TRANSACTION_GAS: u64 = 300_000_000_000_000;
const BTC_VERIFY_DEPOSIT_GAS: u64 = 300_000_000_000_000;
const BTC_VERIFY_WITHDRAW_GAS: u64 = 300_000_000_000_000;
const BTC_CANCEL_WITHDRAW_GAS: u64 = 300_000_000_000_000;
const BTC_VERIFY_ACTIVE_UTXO_MANAGEMENT_GAS: u64 = 300_000_000_000_000;

const INIT_BTC_TRANSFER_DEPOSIT: u128 = 1;
const ACTIVE_UTXO_MANAGEMENT_DEPOSIT: u128 = 1;
const SIGN_BTC_TRANSACTION_DEPOSIT: u128 = 250_000_000_000_000_000_000_000;
const BTC_VERIFY_DEPOSIT_DEPOSIT: u128 = 0;
const BTC_VERIFY_WITHDRAW_DEPOSIT: u128 = 0;
const BTC_CANCEL_WITHDRAW_DEPOSIT: u128 = 1;
const BTC_VERIFY_ACTIVE_UTXO_MANAGEMENT_DEPOSIT: u128 = 0;
pub const MAX_RATIO: u32 = 10000;

#[serde_as]
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct PostAction {
    pub receiver_id: AccountId,
    #[serde_as(as = "DisplayFromStr")]
    pub amount: u128,
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

#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct BtcVerifyWithdrawArgs {
    pub tx_id: String,
    pub tx_block_blockhash: String,
    pub tx_index: u64,
    pub merkle_proof: Vec<String>,
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub enum TokenReceiverMessage {
    DepositProtocolFee,
    Withdraw {
        target_btc_address: String,
        input: Vec<OutPoint>,
        output: Vec<TxOut>,
    },
}

#[serde_as]
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct BridgeFee {
    #[serde_as(as = "DisplayFromStr")]
    pub fee_min: u128,
    pub fee_rate: u32,
    pub protocol_fee_rate: u32,
}

impl BridgeFee {
    pub fn get_fee(&self, amount: u128) -> u128 {
        std::cmp::max(
            amount * u128::from(self.fee_rate) / u128::from(MAX_RATIO),
            self.fee_min,
        )
    }
}

#[serde_as]
#[derive(Clone, serde::Serialize, serde::Deserialize)]
struct WithdrawBridgeFee {
    #[serde_as(as = "DisplayFromStr")]
    fee_min: u128,
    fee_rate: u64,
    protocol_fee_rate: u64,
}

#[serde_as]
#[derive(Clone, serde::Serialize, serde::Deserialize)]
struct PartialConfig {
    withdraw_bridge_fee: WithdrawBridgeFee,
    change_address: String,
    deposit_bridge_fee: BridgeFee,
    #[serde_as(as = "DisplayFromStr")]
    min_deposit_amount: u128,
    max_active_utxo_management_input_number: u8,
    max_active_utxo_management_output_number: u8,
    active_management_lower_limit: u32,
    active_management_upper_limit: u32,
}

impl NearBridgeClient {
    /// Signs a NEAR transfer to BTC by calling sign_btc_transaction on the BTC connector contract.
    #[tracing::instrument(skip_all, name = "NEAR SIGN BTC TRANSACTION")]
    pub async fn sign_btc_transaction(
        &self,
        is_zcash: bool,
        btc_pending_id: String,
        sign_index: u64,
        transaction_options: TransactionOptions,
    ) -> Result<CryptoHash> {
        let endpoint = self.endpoint()?;
        let btc_connector = if is_zcash {
            self.zcash_connector()?
        } else {
            self.btc_connector()?
        };
        let tx_hash = near_rpc_client::change_and_wait(
            endpoint,
            ChangeRequest {
                signer: self.signer()?,
                nonce: transaction_options.nonce,
                receiver_id: btc_connector,
                method_name: "sign_btc_transaction".to_string(),
                args: serde_json::json!({
                    "btc_pending_sign_id": btc_pending_id,
                    "sign_index": sign_index,
                    "key_version": 0,
                })
                .to_string()
                .into_bytes(),
                gas: SIGN_BTC_TRANSACTION_GAS,
                deposit: SIGN_BTC_TRANSACTION_DEPOSIT,
            },
            transaction_options.wait_until,
            transaction_options.wait_final_outcome_timeout_sec,
        )
        .await?;

        tracing::info!(tx_hash = tx_hash.to_string(), "Sent sign BTC transaction");
        Ok(tx_hash)
    }

    /// Finalizes a BTC transfer by calling verify_deposit on the BTC connector contract.
    #[tracing::instrument(skip_all, name = "NEAR FIN BTC TRANSFER")]
    pub async fn fin_btc_transfer(
        &self,
        is_zcash: bool,
        args: FinBtcTransferArgs,
        transaction_options: TransactionOptions,
    ) -> Result<CryptoHash> {
        let endpoint = self.endpoint()?;
        let btc_connector = if is_zcash {
            self.zcash_connector()?
        } else {
            self.btc_connector()?
        };
        let tx_hash = near_rpc_client::change_and_wait(
            endpoint,
            ChangeRequest {
                signer: self.signer()?,
                nonce: transaction_options.nonce,
                receiver_id: btc_connector,
                method_name: "verify_deposit".to_string(),
                args: serde_json::json!(args).to_string().into_bytes(),
                gas: BTC_VERIFY_DEPOSIT_GAS,
                deposit: BTC_VERIFY_DEPOSIT_DEPOSIT,
            },
            transaction_options.wait_until,
            transaction_options.wait_final_outcome_timeout_sec,
        )
        .await?;

        tracing::info!(
            tx_hash = tx_hash.to_string(),
            "Sent BTC finalize transfer transaction"
        );
        Ok(tx_hash)
    }

    // Submit the proof to the btc_connector on NEAR that the withdraw transfer
    // to Bitcoin was successfully completed. It is needed in order to store the new change UTXO
    // and to ensure the relayer receives the fee.
    #[tracing::instrument(skip_all, name = "NEAR BTC VERIFY WITHDRAW")]
    pub async fn btc_verify_withdraw(
        &self,
        is_zcash: bool,
        args: BtcVerifyWithdrawArgs,
        transaction_options: TransactionOptions,
    ) -> Result<CryptoHash> {
        let endpoint = self.endpoint()?;
        let btc_connector = if is_zcash {
            self.zcash_connector()?
        } else {
            self.btc_connector()?
        };
        let tx_hash = near_rpc_client::change_and_wait(
            endpoint,
            ChangeRequest {
                signer: self.signer()?,
                nonce: transaction_options.nonce,
                receiver_id: btc_connector,
                method_name: "verify_withdraw".to_string(),
                args: serde_json::json!(args).to_string().into_bytes(),
                gas: BTC_VERIFY_WITHDRAW_GAS,
                deposit: BTC_VERIFY_WITHDRAW_DEPOSIT,
            },
            transaction_options.wait_until,
            transaction_options.wait_final_outcome_timeout_sec,
        )
        .await?;

        tracing::info!(
            tx_hash = tx_hash.to_string(),
            "Sent BTC Verify Withdraw transaction"
        );
        Ok(tx_hash)
    }

    #[tracing::instrument(skip_all, name = "NEAR BTC CANCEL WITHDRAW")]
    pub async fn btc_cancel_withdraw(
        &self,
        is_zcash: bool,
        tx_hash: String,
        transaction_options: TransactionOptions,
    ) -> Result<CryptoHash> {
        let endpoint = self.endpoint()?;
        let btc_connector = if is_zcash {
            self.zcash_connector()?
        } else {
            self.btc_connector()?
        };
        let tx_hash = near_rpc_client::change_and_wait(
            endpoint,
            ChangeRequest {
                signer: self.signer()?,
                nonce: transaction_options.nonce,
                receiver_id: btc_connector,
                method_name: "cancel_withdraw".to_string(),
                args: serde_json::json!({"original_btc_pending_verify_id": tx_hash, "output": []})
                    .to_string()
                    .into_bytes(),
                gas: BTC_CANCEL_WITHDRAW_GAS,
                deposit: BTC_CANCEL_WITHDRAW_DEPOSIT,
            },
            transaction_options.wait_until,
            transaction_options.wait_final_outcome_timeout_sec,
        )
        .await?;

        tracing::info!(
            tx_hash = tx_hash.to_string(),
            "Sent BTC Cancel Withdraw transaction"
        );
        Ok(tx_hash)
    }

    #[tracing::instrument(skip_all, name = "NEAR BTC VERIFY ACTIVE UTXO MANAGEMENT")]
    pub async fn btc_verify_active_utxo_management(
        &self,
        is_zcash: bool,
        args: BtcVerifyWithdrawArgs,
        transaction_options: TransactionOptions,
    ) -> Result<CryptoHash> {
        let endpoint = self.endpoint()?;
        let btc_connector = if is_zcash {
            self.zcash_connector()?
        } else {
            self.btc_connector()?
        };
        let tx_hash = near_rpc_client::change_and_wait(
            endpoint,
            ChangeRequest {
                signer: self.signer()?,
                nonce: transaction_options.nonce,
                receiver_id: btc_connector,
                method_name: "verify_active_utxo_management".to_string(),
                args: serde_json::json!(args).to_string().into_bytes(),
                gas: BTC_VERIFY_ACTIVE_UTXO_MANAGEMENT_GAS,
                deposit: BTC_VERIFY_ACTIVE_UTXO_MANAGEMENT_DEPOSIT,
            },
            transaction_options.wait_until,
            transaction_options.wait_final_outcome_timeout_sec,
        )
        .await?;

        tracing::info!(
            tx_hash = tx_hash.to_string(),
            "Sent BTC Verify Active UTXO Management transaction"
        );
        Ok(tx_hash)
    }

    #[tracing::instrument(skip_all, name = "ACTIVE UTXO MANAGEMENT")]
    pub async fn active_utxo_management(
        &self,
        is_zcash: bool,
        input: Vec<OutPoint>,
        output: Vec<TxOut>,
        transaction_options: TransactionOptions,
    ) -> Result<CryptoHash> {
        let endpoint = self.endpoint()?;
        let btc_connector = if is_zcash {
            self.zcash_connector()?
        } else {
            self.btc_connector()?
        };
        let tx_hash = near_rpc_client::change_and_wait(
            endpoint,
            ChangeRequest {
                signer: self.signer()?,
                nonce: transaction_options.nonce,
                receiver_id: btc_connector,
                method_name: "active_utxo_management".to_string(),
                args: serde_json::json!({
                    "input": input,
                    "output": output
                })
                .to_string()
                .into_bytes(),
                gas: ACTIVE_UTXO_MANAGEMENT_GAS,
                deposit: ACTIVE_UTXO_MANAGEMENT_DEPOSIT,
            },
            transaction_options.wait_until,
            transaction_options.wait_final_outcome_timeout_sec,
        )
        .await?;

        tracing::info!(tx_hash = tx_hash.to_string(), "Init BTC transfer");
        Ok(tx_hash)
    }

    /// Init a BTC transfer from Near to BTC.
    #[tracing::instrument(skip_all, name = "NEAR INIT BTC TRANSFER")]
    pub async fn init_btc_transfer_near_to_btc(
        &self,
        is_zcash: bool,
        amount: u128,
        msg: TokenReceiverMessage,
        transaction_options: TransactionOptions,
    ) -> Result<CryptoHash> {
        let endpoint = self.endpoint()?;
        let (btc_connector, btc) = if is_zcash {
            (self.zcash_connector()?, self.zcash()?)
        } else {
            (self.btc_connector()?, self.btc()?)
        };
        let tx_hash = near_rpc_client::change_and_wait(
            endpoint,
            ChangeRequest {
                signer: self.signer()?,
                nonce: transaction_options.nonce,
                receiver_id: btc,
                method_name: "ft_transfer_call".to_string(),
                args: serde_json::json!({
                    "receiver_id": btc_connector,
                    "amount": amount.to_string(),
                    "msg": json!(msg).to_string(),
                })
                .to_string()
                .into_bytes(),
                gas: INIT_BTC_TRANSFER_GAS,
                deposit: INIT_BTC_TRANSFER_DEPOSIT,
            },
            transaction_options.wait_until,
            transaction_options.wait_final_outcome_timeout_sec,
        )
        .await?;

        tracing::info!(tx_hash = tx_hash.to_string(), "Init BTC transfer");
        Ok(tx_hash)
    }

    pub async fn get_btc_address(
        &self,
        is_zcash: bool,
        recipient_id: &str,
        amount: u128,
        fee: u128,
    ) -> Result<String> {
        let deposit_msg = self.get_deposit_msg_for_omni_bridge(recipient_id, amount, fee)?;
        let endpoint = self.endpoint()?;
        let btc_connector = if is_zcash {
            self.zcash_connector()?
        } else {
            self.btc_connector()?
        };

        let response = near_rpc_client::view(
            endpoint,
            ViewRequest {
                contract_account_id: btc_connector,
                method_name: "get_user_deposit_address".to_string(),
                args: serde_json::json!({
                    "deposit_msg": deposit_msg
                }),
            },
        )
        .await?;

        let btc_address = serde_json::from_slice::<String>(&response)?;
        Ok(btc_address)
    }

    pub async fn get_utxos(&self, is_zcash: bool) -> Result<HashMap<String, UTXO>> {
        let endpoint = self.endpoint()?;
        let btc_connector = if is_zcash {
            self.zcash_connector()?
        } else {
            self.btc_connector()?
        };

        let response = near_rpc_client::view(
            endpoint,
            ViewRequest {
                contract_account_id: btc_connector,
                method_name: "get_utxos_paged".to_string(),
                args: serde_json::json!({}),
            },
        )
        .await?;

        let utxos = serde_json::from_slice::<HashMap<String, UTXO>>(&response)?;
        Ok(utxos)
    }

    pub async fn get_withdraw_fee(&self, is_zcash: bool) -> Result<u128> {
        let config = self.get_config(is_zcash).await?;
        Ok(config.withdraw_bridge_fee.fee_min)
    }

    pub async fn get_change_address(&self, is_zcash: bool) -> Result<String> {
        let config = self.get_config(is_zcash).await?;
        Ok(config.change_address)
    }

    pub async fn get_active_management_limit(&self, is_zcash: bool) -> Result<(u32, u32, u8, u8)> {
        let config = self.get_config(is_zcash).await?;
        Ok((
            config.active_management_lower_limit,
            config.active_management_upper_limit,
            config.max_active_utxo_management_input_number,
            config.max_active_utxo_management_output_number,
        ))
    }

    pub async fn get_amount_to_transfer(&self, is_zcash: bool, amount: u128) -> Result<u128> {
        let config = self.get_config(is_zcash).await?;
        Ok(max(
            config.deposit_bridge_fee.get_fee(amount) + amount,
            config.min_deposit_amount,
        ))
    }

    pub async fn get_min_deposit_amount(&self, is_zcash: bool) -> Result<u128> {
        let config = self.get_config(is_zcash).await?;
        Ok(config.min_deposit_amount)
    }

    async fn get_config(&self, is_zcash: bool) -> Result<PartialConfig> {
        let endpoint = self.endpoint()?;
        let btc_connector = if is_zcash {
            self.zcash_connector()?
        } else {
            self.btc_connector()?
        };

        let response = near_rpc_client::view(
            endpoint,
            ViewRequest {
                contract_account_id: btc_connector,
                method_name: "get_config".to_string(),
                args: serde_json::json!({}),
            },
        )
        .await?;

        Ok(serde_json::from_slice::<PartialConfig>(&response)?)
    }

    pub fn get_deposit_msg_for_omni_bridge(
        &self,
        recipient_id: &str,
        amount: u128,
        fee: u128,
    ) -> Result<DepositMsg> {
        if recipient_id.contains(':') {
            let omni_bridge_id = self.omni_bridge_id()?;
            let account_id = self.account_id()?;
            Ok(DepositMsg {
                recipient_id: account_id,
                post_actions: Some(vec![PostAction {
                    receiver_id: omni_bridge_id,
                    amount,
                    memo: None,
                    msg: json!({
                        "recipient": recipient_id.to_string(),
                        "fee": fee.to_string(),
                        "native_token_fee": "0",
                    })
                    .to_string(),
                    gas: None,
                }]),
                extra_msg: None,
            })
        } else {
            Ok(DepositMsg {
                recipient_id: recipient_id.parse().map_err(|err| {
                    BridgeSdkError::BtcClientError(format!("Incorrect recipient_id: {err}"))
                })?,
                post_actions: None,
                extra_msg: None,
            })
        }
    }

    pub async fn get_btc_tx_data(
        &self,
        near_tx_hash: String,
        relayer: Option<AccountId>,
    ) -> Result<Vec<u8>> {
        let tx_hash = CryptoHash::from_str(&near_tx_hash).map_err(|err| {
            BridgeSdkError::BtcClientError(format!("Error on parsing Near Tx Hash: {err}"))
        })?;

        let relayer_id = relayer.unwrap_or(self.satoshi_relayer()?);
        let log = self
            .extract_transfer_log(tx_hash, Some(relayer_id), "signed_btc_transaction")
            .await?;

        let json_str = log
            .strip_prefix("EVENT_JSON:")
            .ok_or(BridgeSdkError::BtcClientError("Incorrect logs".to_string()))?;
        let v: Value = serde_json::from_str(json_str)?;
        let bytes = v["data"][0]["tx_bytes"]
            .as_array()
            .ok_or_else(|| {
                BridgeSdkError::BtcClientError(
                    "Expected 'tx_bytes' to be an array in logs".to_string(),
                )
            })?
            .iter()
            .map(|val| {
                let num = val.as_u64().ok_or_else(|| {
                    BridgeSdkError::BtcClientError(format!(
                        "Expected u64 value in 'tx_bytes', got: {val}"
                    ))
                })?;

                u8::try_from(num).map_err(|e| {
                    BridgeSdkError::BtcClientError(format!(
                        "Value {num} in 'tx_bytes' is out of range for u8: {e}"
                    ))
                })
            })
            .collect::<Result<Vec<u8>>>()?;

        Ok(bytes)
    }

    pub fn btc_connector(&self) -> Result<AccountId> {
        self.btc_bridge
            .as_ref()
            .ok_or(BridgeSdkError::ConfigError(
                "BTC accounts id is not set".to_string(),
            ))?
            .utxo_chain_connector
            .as_ref()
            .ok_or(BridgeSdkError::ConfigError(
                "BTC Connector account id is not set".to_string(),
            ))?
            .parse::<AccountId>()
            .map_err(|_| {
                BridgeSdkError::ConfigError("Invalid btc connector account id".to_string())
            })
    }

    pub fn zcash_connector(&self) -> Result<AccountId> {
        self.zcash_bridge
            .as_ref()
            .ok_or(BridgeSdkError::ConfigError(
                "Zcash accounts id is not set".to_string(),
            ))?
            .utxo_chain_connector
            .as_ref()
            .ok_or(BridgeSdkError::ConfigError(
                "Zcash Connector account id is not set".to_string(),
            ))?
            .parse::<AccountId>()
            .map_err(|_| {
                BridgeSdkError::ConfigError("Invalid zcash connector account id".to_string())
            })
    }

    pub fn btc(&self) -> Result<AccountId> {
        self.btc_bridge
            .as_ref()
            .ok_or(BridgeSdkError::ConfigError(
                "BTC accounts id is not set".to_string(),
            ))?
            .utxo_chain_token
            .as_ref()
            .ok_or(BridgeSdkError::ConfigError(
                "Bitcoin account id is not set".to_string(),
            ))?
            .parse::<AccountId>()
            .map_err(|_| BridgeSdkError::ConfigError("Invalid bitcoin account id".to_string()))
    }

    pub fn zcash(&self) -> Result<AccountId> {
        self.zcash_bridge
            .as_ref()
            .ok_or(BridgeSdkError::ConfigError(
                "BTC accounts id is not set".to_string(),
            ))?
            .utxo_chain_token
            .as_ref()
            .ok_or(BridgeSdkError::ConfigError(
                "Bitcoin account id is not set".to_string(),
            ))?
            .parse::<AccountId>()
            .map_err(|_| BridgeSdkError::ConfigError("Invalid bitcoin account id".to_string()))
    }

    pub fn satoshi_relayer(&self) -> Result<AccountId> {
        self.btc_bridge
            .as_ref()
            .ok_or(BridgeSdkError::ConfigError(
                "BTC accounts id is not set".to_string(),
            ))?
            .satoshi_relayer
            .as_ref()
            .ok_or(BridgeSdkError::ConfigError(
                "Satoshi Relayer account id is not set".to_string(),
            ))?
            .parse::<AccountId>()
            .map_err(|_| {
                BridgeSdkError::ConfigError("Invalid Satoshi Relayer account id".to_string())
            })
    }
}
