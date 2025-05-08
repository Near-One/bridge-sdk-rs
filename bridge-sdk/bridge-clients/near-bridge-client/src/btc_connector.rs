use crate::NearBridgeClient;
use crate::TransactionOptions;
use bitcoin::{Address, Amount, OutPoint, TxOut};
use bridge_connector_common::result::{BridgeSdkError, Result};
use near_primitives::types::Gas;
use near_primitives::{hash::CryptoHash, types::AccountId};
use near_rpc_client::{ChangeRequest, ViewRequest};
use serde_json::{json, Value};
use serde_with::{serde_as, DisplayFromStr};
use std::collections::HashMap;
use std::str::FromStr;

const FIN_BTC_TRANSFER_GAS: u64 = 300_000_000_000_000;
const INIT_BTC_TRANSFER_GAS: u64 = 300_000_000_000_000;

const FIN_BTC_TRANSFER_DEPOSIT: u128 = 0;

pub mod u64_dec_format {
    use serde::de;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(num: &u64, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&num.to_string())
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<u64, D::Error>
    where
        D: Deserializer<'de>,
    {
        String::deserialize(deserializer)?
            .parse()
            .map_err(de::Error::custom)
    }
}

#[derive(Clone, serde::Serialize, serde::Deserialize, Debug)]
pub struct UTXO {
    pub path: String,
    pub tx_bytes: Vec<u8>,
    pub vout: usize,
    #[serde(with = "u64_dec_format")]
    pub balance: u64,
}

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
struct WithdrawBridgeFee {
    #[serde_as(as = "DisplayFromStr")]
    fee_min: u128,
    fee_rate: u64,
    protocol_fee_rate: u64,
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
struct PartialConfig {
    withdraw_bridge_fee: WithdrawBridgeFee,
    change_address: String,
}

impl NearBridgeClient {
    /// Finalizes a BTC transfer by calling verify_deposit on the BTC connector contract.
    #[tracing::instrument(skip_all, name = "NEAR FIN BTC TRANSFER")]
    pub async fn fin_btc_transfer(
        &self,
        args: FinBtcTransferArgs,
        transaction_options: TransactionOptions,
        wait_final_outcome_timeout_sec: Option<u64>,
    ) -> Result<CryptoHash> {
        let endpoint = self.endpoint()?;
        let btc_connector = self.btc_connector()?;
        let tx_hash = near_rpc_client::change_and_wait(
            endpoint,
            ChangeRequest {
                signer: self.signer()?,
                nonce: transaction_options.nonce,
                receiver_id: btc_connector,
                method_name: "verify_deposit".to_string(),
                args: serde_json::json!(args).to_string().into_bytes(),
                gas: FIN_BTC_TRANSFER_GAS,
                deposit: FIN_BTC_TRANSFER_DEPOSIT,
            },
            transaction_options.wait_until,
            wait_final_outcome_timeout_sec,
        )
        .await?;

        tracing::info!(
            tx_hash = tx_hash.to_string(),
            "Sent BTC finalize transfer transaction"
        );
        Ok(tx_hash)
    }

    /// Finalizes a BTC transfer by calling verify_deposit on the BTC connector contract.
    #[tracing::instrument(skip_all, name = "NEAR INIT BTC TRANSFER")]
    pub async fn init_btc_transfer(
        &self,
        amount: u128,
        msg: TokenReceiverMessage,
        transaction_options: TransactionOptions,
        wait_final_outcome_timeout_sec: Option<u64>,
    ) -> Result<CryptoHash> {
        let endpoint = self.endpoint()?;
        let btc = self.btc()?;
        let btc_connector = self.btc_connector()?;
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
                deposit: 1,
            },
            transaction_options.wait_until,
            wait_final_outcome_timeout_sec,
        )
        .await?;

        tracing::info!(tx_hash = tx_hash.to_string(), "Init BTC transfer");
        Ok(tx_hash)
    }

    pub async fn get_btc_address(
        &self,
        recipient_id: &str,
        amount: u128,
        fee: u128,
    ) -> Result<String> {
        let deposit_msg = self.get_deposit_msg_for_omni_bridge(recipient_id, amount, fee)?;
        let endpoint = self.endpoint()?;
        let btc_connector = self.btc_connector()?;

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

    pub fn get_tx_outs(
        &self,
        target_btc_address: String,
        amount: u64,
        change_address: String,
        change_amount: u64,
    ) -> Vec<TxOut> {
        let btc_recipient_address =
            Address::from_str(&target_btc_address).expect("Invalid Bitcoin address");
        let btc_recipient_address = btc_recipient_address.assume_checked();
        let btc_recipient_script_pubkey = btc_recipient_address.script_pubkey();

        let change_address =
            Address::from_str(&change_address).expect("Invalid Bitcoin Change address");
        let change_address = change_address.assume_checked();
        let change_script_pubkey = change_address.script_pubkey();
        vec![
            TxOut {
                value: Amount::from_sat(amount),
                script_pubkey: btc_recipient_script_pubkey,
            },
            TxOut {
                value: Amount::from_sat(change_amount),
                script_pubkey: change_script_pubkey,
            },
        ]
    }

    fn utxo_to_out_points(utxos: Vec<(String, UTXO)>) -> Result<Vec<OutPoint>> {
        utxos
            .into_iter()
            .map(|(txid, utxo)| {
                let txid_str = txid.split('@').next().ok_or_else(|| {
                    BridgeSdkError::BtcClientError(format!("Invalid txid format: {}", txid))
                })?;

                let parsed_txid = txid_str.parse().map_err(|e| {
                    BridgeSdkError::BtcClientError(format!(
                        "Failed to parse txid '{}' into bitcoin::Txid: {}",
                        txid_str, e
                    ))
                })?;

                let vout = u32::try_from(utxo.vout).map_err(|e| {
                    BridgeSdkError::BtcClientError(format!(
                        "Invalid vout value (expected u32): {} ({})",
                        utxo.vout, e
                    ))
                })?;

                Ok(OutPoint::new(parsed_txid, vout))
            })
            .collect()
    }

    pub fn choose_utxos(
        &self,
        amount: u128,
        utxos: HashMap<String, UTXO>,
    ) -> Result<(Vec<OutPoint>, u128)> {
        let mut utxo_list: Vec<(String, UTXO)> = utxos.into_iter().collect();
        utxo_list.sort_by(|a, b| b.1.balance.cmp(&a.1.balance));

        let mut selected = Vec::new();
        let mut utxos_balance = 0;

        for utxo in utxo_list {
            if utxos_balance >= amount {
                break;
            }
            utxos_balance += utxo.1.balance as u128;
            selected.push(utxo);
        }

        let out_points = Self::utxo_to_out_points(selected)?;
        Ok((out_points, utxos_balance))
    }

    pub async fn get_utxos(&self) -> Result<HashMap<String, UTXO>> {
        let endpoint = self.endpoint()?;
        let btc_connector = self.btc_connector()?;

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

    pub async fn get_withdraw_fee(&self) -> Result<u128> {
        let config = self.get_config().await?;
        Ok(config.withdraw_bridge_fee.fee_min)
    }

    pub async fn get_change_address(&self) -> Result<String> {
        let config = self.get_config().await?;
        Ok(config.change_address)
    }

    async fn get_config(&self) -> Result<PartialConfig> {
        let endpoint = self.endpoint()?;
        let btc_connector = self.btc_connector()?;

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

    pub async fn get_btc_tx_data(&self, near_tx_hash: String) -> Result<Vec<u8>> {
        let tx_hash = CryptoHash::from_str(&near_tx_hash).map_err(|err| {
            BridgeSdkError::BtcClientError(format!("Error on parsing Near Tx Hash: {}", err))
        })?;
        let log = self
            .extract_transfer_log(
                tx_hash,
                Some(self.satoshi_relayer()?),
                "signed_btc_transaction",
            )
            .await?;

        let json_str = log
            .strip_prefix("EVENT_JSON:")
            .ok_or(BridgeSdkError::BtcClientError("Incorrect logs".to_string()))?;
        let v: Value = serde_json::from_str(json_str)?;
        let bytes = v["data"][0]["tx_bytes"]
            .as_array()
            .ok_or(BridgeSdkError::BtcClientError(
                "Expected 'tx_bytes' to be an array in logs".to_string(),
            ))?
            .iter()
            .map(|val| {
                val.as_u64()
                    .ok_or_else(|| {
                        BridgeSdkError::BtcClientError(format!(
                            "Expected u64 value in 'tx_bytes', got: {val}"
                        ))
                    })
                    .map(|num| num as u8)
            })
            .collect::<Result<Vec<u8>>>()?;

        Ok(bytes)
    }

    pub fn btc_connector(&self) -> Result<AccountId> {
        self.btc_connector
            .as_ref()
            .ok_or(BridgeSdkError::ConfigError(
                "BTC Connector account id is not set".to_string(),
            ))?
            .parse::<AccountId>()
            .map_err(|_| {
                BridgeSdkError::ConfigError("Invalid btc connector account id".to_string())
            })
    }

    pub fn btc(&self) -> Result<AccountId> {
        self.btc
            .as_ref()
            .ok_or(BridgeSdkError::ConfigError(
                "Bitcoin account id is not set".to_string(),
            ))?
            .parse::<AccountId>()
            .map_err(|_| BridgeSdkError::ConfigError("Invalid bitcoin account id".to_string()))
    }

    pub fn satoshi_relayer(&self) -> Result<AccountId> {
        self.satoshi_relayer
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
