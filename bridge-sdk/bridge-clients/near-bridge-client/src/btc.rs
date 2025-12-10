use crate::NearBridgeClient;
use crate::TransactionOptions;
use base64::Engine;
use bitcoin::{OutPoint, TxOut};
use bridge_connector_common::result::{BridgeSdkError, Result};
use futures::future::join_all;
use near_primitives::types::Gas;
use near_primitives::{hash::CryptoHash, types::AccountId};
use near_rpc_client::{ChangeRequest, ViewRequest};
use near_sdk::json_types::Base64VecU8;
use near_sdk::json_types::U128;
use near_sdk::json_types::U64;
use omni_types::ChainKind;
use omni_types::{OmniAddress, TransferId};
use serde_json::{json, Value};
use serde_with::{serde_as, DisplayFromStr};
use std::cmp::max;
use std::collections::HashMap;
use std::str::FromStr;
use utxo_utils::UTXO;

const INIT_BTC_TRANSFER_GAS: u64 = 300_000_000_000_000;
const ACTIVE_UTXO_MANAGEMENT_GAS: u64 = 300_000_000_000_000;
const SIGN_BTC_TRANSACTION_GAS: u64 = 300_000_000_000_000;
const BTC_VERIFY_DEPOSIT_GAS: u64 = 300_000_000_000_000;
const BTC_VERIFY_WITHDRAW_GAS: u64 = 300_000_000_000_000;
const BTC_CANCEL_WITHDRAW_GAS: u64 = 300_000_000_000_000;
const BTC_RBF_INCREASE_GAS_FEE_GAS: u64 = 300_000_000_000_000;
const BTC_VERIFY_ACTIVE_UTXO_MANAGEMENT_GAS: u64 = 300_000_000_000_000;
const SUBMIT_BTC_TRANSFER_GAS: u64 = 300_000_000_000_000;

const INIT_BTC_TRANSFER_DEPOSIT: u128 = 1;
const ACTIVE_UTXO_MANAGEMENT_DEPOSIT: u128 = 1;
const SIGN_BTC_TRANSACTION_DEPOSIT: u128 = 250_000_000_000_000_000_000_000;
const BTC_SAFE_VERIFY_DEPOSIT_DEPOSIT: u128 = 1_200_000_000_000_000_000_000;
const BTC_VERIFY_DEPOSIT_DEPOSIT: u128 = 0;
const BTC_VERIFY_WITHDRAW_DEPOSIT: u128 = 0;
const BTC_CANCEL_WITHDRAW_DEPOSIT: u128 = 1;
const BTC_RBF_INCREASE_GAS_FEE_DEPOSIT: u128 = 0;
const BTC_VERIFY_ACTIVE_UTXO_MANAGEMENT_DEPOSIT: u128 = 0;
const SUBMIT_BTC_TRANSFER_DEPOSIT: u128 = 0;
pub const MAX_RATIO: u32 = 10000;

pub const UTXO_BATCH_SIZE: u32 = 500;

#[serde_as]
#[derive(Clone, serde::Serialize, serde::Deserialize, Debug)]
pub enum VUTXO {
    Current(UTXO),
}

#[serde_as]
#[derive(Clone, serde::Serialize, serde::Deserialize, Debug)]
pub struct BTCPendingInfoPartial {
    pub account_id: AccountId,
    pub btc_pending_id: String,
    #[serde_as(as = "DisplayFromStr")]
    pub transfer_amount: u128,
    #[serde_as(as = "DisplayFromStr")]
    pub actual_received_amount: u128,
    #[serde_as(as = "DisplayFromStr")]
    pub withdraw_fee: u128,
    #[serde_as(as = "DisplayFromStr")]
    pub gas_fee: u128,
    #[serde_as(as = "DisplayFromStr")]
    pub burn_amount: u128,
    pub tx_bytes_with_sign: Option<Vec<u8>>,
    pub vutxos: Vec<VUTXO>,
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
pub struct SafeDepositMsg {
    pub msg: String,
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct DepositMsg {
    pub recipient_id: AccountId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub post_actions: Option<Vec<PostAction>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extra_msg: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub safe_deposit: Option<SafeDepositMsg>,
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
pub struct ChainSpecificData {
    pub orchard_bundle_bytes: Option<Base64VecU8>,
    pub expiry_height: Option<u32>,
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub enum TokenReceiverMessage {
    DepositProtocolFee,
    Withdraw {
        target_btc_address: String,
        input: Vec<OutPoint>,
        output: Vec<TxOut>,
        max_gas_fee: Option<U128>,
        chain_specific_data: Option<ChainSpecificData>,
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
    confirmations_strategy: HashMap<String, u8>,
    confirmations_delta: u8,
}

#[serde_as]
#[derive(Clone, serde::Serialize, serde::Deserialize)]
struct PartialMetadata {
    pub current_utxos_num: u32,
}

#[derive(Clone, Debug)]
pub struct NearToBtcTransferInfo {
    pub recipient: String,
    pub amount: u128,
    pub transfer_id: TransferId,
    pub max_gas_fee: Option<u64>,
}

#[derive(Debug, PartialEq, serde::Deserialize, serde::Serialize)]
enum UTXOChainMsg {
    MaxGasFee(U64),
}

impl NearBridgeClient {
    /// Signs a NEAR transfer to BTC by calling `sign_btc_transaction` on the BTC connector contract.
    #[tracing::instrument(skip_all, name = "NEAR SIGN BTC TRANSACTION")]
    pub async fn sign_btc_transaction(
        &self,
        chain: ChainKind,
        btc_pending_id: String,
        sign_index: u64,
        transaction_options: TransactionOptions,
    ) -> Result<CryptoHash> {
        let endpoint = self.endpoint()?;
        let btc_connector = self.utxo_chain_connector(chain)?;
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

    /// Signs a NEAR transfer to BTC by providing Near transaction hash
    #[tracing::instrument(skip_all, name = "NEAR SIGN BTC TRANSACTION")]
    pub async fn sign_btc_transaction_with_tx_hash(
        &self,
        chain: ChainKind,
        near_tx_hash: CryptoHash,
        user_account_id: Option<AccountId>,
        sign_index: u64,
        transaction_options: TransactionOptions,
    ) -> Result<CryptoHash> {
        let relayer_id = match user_account_id {
            Some(user_account_id) => user_account_id,
            None => self.satoshi_relayer(chain)?,
        };

        let log = self
            .extract_transfer_log(near_tx_hash, Some(relayer_id), "generate_btc_pending_info")
            .await?;
        let json_str = log
            .strip_prefix("EVENT_JSON:")
            .ok_or(BridgeSdkError::InvalidLog(
                "Missing EVENT_JSON prefix".to_string(),
            ))?;

        let v: Value = serde_json::from_str(json_str)?;
        let btc_pending_id = v["data"][0]["btc_pending_id"]
            .as_str()
            .ok_or(BridgeSdkError::InvalidLog(
                "btc_pending id not found".to_string(),
            ))?
            .to_string();

        self.sign_btc_transaction(chain, btc_pending_id, sign_index, transaction_options)
            .await
    }

    /// Sign BTC transfer on Omni Bridge
    #[tracing::instrument(skip_all, name = "NEAR SUBMIT BTC TRANSFER")]
    pub async fn submit_btc_transfer(
        &self,
        transfer_id: TransferId,
        msg: TokenReceiverMessage,
        transaction_options: TransactionOptions,
    ) -> Result<CryptoHash> {
        let endpoint = self.endpoint()?;
        let omni_bridge = self.omni_bridge_id()?;
        let tx_hash = near_rpc_client::change_and_wait(
            endpoint,
            ChangeRequest {
                signer: self.signer()?,
                nonce: transaction_options.nonce,
                receiver_id: omni_bridge,
                method_name: "submit_transfer_to_utxo_chain_connector".to_string(),
                args: serde_json::json!({
                    "transfer_id": transfer_id,
                    "msg": json!(msg).to_string(),
                })
                .to_string()
                .into_bytes(),
                gas: SUBMIT_BTC_TRANSFER_GAS,
                deposit: SUBMIT_BTC_TRANSFER_DEPOSIT,
            },
            transaction_options.wait_until,
            transaction_options.wait_final_outcome_timeout_sec,
        )
        .await?;

        tracing::info!(tx_hash = tx_hash.to_string(), "Sign BTC transfer");
        Ok(tx_hash)
    }

    pub async fn get_btc_pending_info(
        &self,
        chain: ChainKind,
        btc_tx_hash: String,
    ) -> Result<BTCPendingInfoPartial> {
        let endpoint = self.endpoint()?;
        let btc_connector = self.utxo_chain_connector(chain)?;

        let response = near_rpc_client::view(
            endpoint,
            ViewRequest {
                contract_account_id: btc_connector,
                method_name: "list_btc_pending_infos".to_string(),
                args: serde_json::json!({
                    "btc_pending_ids": [btc_tx_hash]
                }),
            },
        )
        .await?;

        let btc_pending_info =
            serde_json::from_slice::<HashMap<String, Option<BTCPendingInfoPartial>>>(&response)?;

        let btc_pending_info = btc_pending_info
            .get(&btc_tx_hash)
            .cloned()
            .flatten()
            .ok_or_else(|| {
                BridgeSdkError::InvalidArgument("BTC pending info not found".to_string())
            })?;

        Ok(btc_pending_info)
    }

    #[tracing::instrument(skip_all, name = "NEAR BTC RBF INCREASE GAS FEE")]
    pub async fn btc_rbf_increase_gas_fee(
        &self,
        chain: ChainKind,
        btc_tx_hash: String,
        outs: Vec<TxOut>,
        transaction_options: TransactionOptions,
    ) -> Result<CryptoHash> {
        let endpoint = self.endpoint()?;
        let omni_bridge = self.omni_bridge_id()?;
        let tx_hash = near_rpc_client::change_and_wait(
            endpoint,
            ChangeRequest {
                signer: self.signer()?,
                nonce: transaction_options.nonce,
                receiver_id: omni_bridge,
                method_name: "rbf_increase_gas_fee".to_string(),
                args: serde_json::json!({
                    "chain_kind": chain,
                    "original_btc_pending_verify_id": btc_tx_hash,
                    "output": outs
                })
                .to_string()
                .into_bytes(),
                gas: BTC_RBF_INCREASE_GAS_FEE_GAS,
                deposit: BTC_RBF_INCREASE_GAS_FEE_DEPOSIT,
            },
            transaction_options.wait_until,
            transaction_options.wait_final_outcome_timeout_sec,
        )
        .await?;

        tracing::info!(
            tx_hash = tx_hash.to_string(),
            "Sent BTC RBF Increase Gas Fee transaction"
        );
        Ok(tx_hash)
    }

    /// Finalizes a BTC transfer by calling `verify_deposit` or `verify_safe_deposit` on the BTC connector contract.
    #[tracing::instrument(skip_all, name = "NEAR FIN BTC TRANSFER")]
    pub async fn fin_btc_transfer(
        &self,
        chain: ChainKind,
        args: FinBtcTransferArgs,
        transaction_options: TransactionOptions,
    ) -> Result<CryptoHash> {
        let endpoint = self.endpoint()?;
        let btc_connector = self.utxo_chain_connector(chain)?;
        let (method_name, deposit) = if args.deposit_msg.safe_deposit.is_some() {
            (
                "safe_verify_deposit".to_string(),
                BTC_SAFE_VERIFY_DEPOSIT_DEPOSIT,
            )
        } else {
            ("verify_deposit".to_string(), BTC_VERIFY_DEPOSIT_DEPOSIT)
        };
        let tx_hash = near_rpc_client::change_and_wait(
            endpoint,
            ChangeRequest {
                signer: self.signer()?,
                nonce: transaction_options.nonce,
                receiver_id: btc_connector,
                method_name,
                args: serde_json::json!(args).to_string().into_bytes(),
                gas: BTC_VERIFY_DEPOSIT_GAS,
                deposit,
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
        chain: ChainKind,
        args: BtcVerifyWithdrawArgs,
        transaction_options: TransactionOptions,
    ) -> Result<CryptoHash> {
        let endpoint = self.endpoint()?;
        let btc_connector = self.utxo_chain_connector(chain)?;
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
        chain: ChainKind,
        tx_hash: String,
        transaction_options: TransactionOptions,
    ) -> Result<CryptoHash> {
        let endpoint = self.endpoint()?;
        let btc_connector = self.utxo_chain_connector(chain)?;
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
        chain: ChainKind,
        args: BtcVerifyWithdrawArgs,
        transaction_options: TransactionOptions,
    ) -> Result<CryptoHash> {
        let endpoint = self.endpoint()?;
        let btc_connector = self.utxo_chain_connector(chain)?;
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
        chain: ChainKind,
        input: Vec<OutPoint>,
        output: Vec<TxOut>,
        transaction_options: TransactionOptions,
    ) -> Result<CryptoHash> {
        let endpoint = self.endpoint()?;
        let btc_connector = self.utxo_chain_connector(chain)?;
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
        chain: ChainKind,
        amount: u128,
        msg: TokenReceiverMessage,
        transaction_options: TransactionOptions,
    ) -> Result<CryptoHash> {
        let endpoint = self.endpoint()?;
        let btc_connector = self.utxo_chain_connector(chain)?;
        let btc = self.utxo_chain_token(chain)?;

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
        chain: ChainKind,
        recipient_id: OmniAddress,
        fee: u128,
    ) -> Result<String> {
        let deposit_msg = self.get_deposit_msg_for_omni_bridge(recipient_id, fee)?;
        let endpoint = self.endpoint()?;
        let btc_connector = self.utxo_chain_connector(chain)?;

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

    pub async fn get_utxo_num(&self, chain: ChainKind) -> Result<u32> {
        let endpoint = self.endpoint()?;
        let btc_connector = self.utxo_chain_connector(chain)?;

        let response = near_rpc_client::view(
            endpoint,
            ViewRequest {
                contract_account_id: btc_connector,
                method_name: "get_metadata".to_string(),
                args: serde_json::json!({}),
            },
        )
        .await?;

        let metadata = serde_json::from_slice::<PartialMetadata>(&response)?;
        Ok(metadata.current_utxos_num)
    }

    pub async fn get_pk_raw(&self, chain: ChainKind, utxo: UTXO) -> String {
        let endpoint = self.endpoint().unwrap();
        let btc_connector = self.utxo_chain_connector(chain).unwrap();

        let response = near_rpc_client::view(
            endpoint,
            ViewRequest {
                contract_account_id: btc_connector,
                method_name: "get_public_key_by_path".to_string(),
                args: serde_json::json!({"path": utxo.path}),
            },
        )
        .await
        .unwrap();

        serde_json::from_slice::<String>(&response).unwrap()
    }

    pub async fn get_utxos(&self, chain: ChainKind) -> Result<HashMap<String, UTXO>> {
        let utxo_num = self.get_utxo_num(chain).await?;

        let endpoint = self.endpoint()?;
        let btc_connector = self.utxo_chain_connector(chain)?;
        let batch_num = utxo_num.div_ceil(UTXO_BATCH_SIZE);

        let mut futures = Vec::new();

        for i in 0..batch_num {
            let fut = near_rpc_client::view(
                endpoint,
                ViewRequest {
                    contract_account_id: btc_connector.clone(),
                    method_name: "get_utxos_paged".to_string(),
                    args: serde_json::json!({
                        "from_index": i * UTXO_BATCH_SIZE,
                        "limit": UTXO_BATCH_SIZE
                    }),
                },
            );
            futures.push(fut);
        }

        let responses = join_all(futures).await;

        let mut utxos_res: HashMap<String, UTXO> = HashMap::new();

        for resp in responses {
            let utxos: HashMap<String, UTXO> = serde_json::from_slice(&resp?)?;
            utxos_res.extend(utxos);
        }

        Ok(utxos_res)
    }

    pub async fn get_withdraw_fee(&self, chain: ChainKind) -> Result<u128> {
        let config = self.get_config(chain).await?;
        Ok(config.withdraw_bridge_fee.fee_min)
    }

    pub async fn get_change_address(&self, chain: ChainKind) -> Result<String> {
        let config = self.get_config(chain).await?;
        Ok(config.change_address)
    }

    pub async fn get_active_management_limit(
        &self,
        chain: ChainKind,
    ) -> Result<(u32, u32, u8, u8)> {
        let config = self.get_config(chain).await?;
        Ok((
            config.active_management_lower_limit,
            config.active_management_upper_limit,
            config.max_active_utxo_management_input_number,
            config.max_active_utxo_management_output_number,
        ))
    }

    pub async fn get_amount_to_transfer(&self, chain: ChainKind, amount: u128) -> Result<u128> {
        let config = self.get_config(chain).await?;
        Ok(max(
            config.deposit_bridge_fee.get_fee(amount) + amount,
            config.min_deposit_amount,
        ))
    }

    pub async fn get_min_deposit_amount(&self, chain: ChainKind) -> Result<u128> {
        let config = self.get_config(chain).await?;
        Ok(config.min_deposit_amount)
    }

    pub async fn get_confirmations(&self, chain: ChainKind) -> Result<u8> {
        let config = self.get_config(chain).await?;

        Ok(config
            .confirmations_strategy
            .values()
            .max()
            .copied()
            .unwrap_or(0)
            + config.confirmations_delta)
    }

    async fn get_config(&self, chain: ChainKind) -> Result<PartialConfig> {
        let endpoint = self.endpoint()?;
        let btc_connector = self.utxo_chain_connector(chain)?;
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
        recipient_id: OmniAddress,
        fee: u128,
    ) -> Result<DepositMsg> {
        if recipient_id.is_utxo_chain() {
            return Err(BridgeSdkError::InvalidArgument(
                "Cannot send directly to UTXO chains".to_string(),
            ));
        }

        if let OmniAddress::Near(recipient_id) = recipient_id {
            Ok(DepositMsg {
                recipient_id,
                post_actions: None,
                extra_msg: None,
                safe_deposit: None,
            })
        } else {
            let omni_bridge_id = self.omni_bridge_id()?;
            Ok(DepositMsg {
                recipient_id: omni_bridge_id,
                post_actions: None,
                extra_msg: None,
                safe_deposit: Some(SafeDepositMsg {
                    msg: json!({
                        "UtxoFinTransfer": {
                            "utxo_id": "{{UTXO_TX_ID}}",
                            "recipient": recipient_id.to_string(),
                            "relayer_fee": fee.to_string(),
                            "msg": "",
                        }
                    })
                    .to_string(),
                }),
            })
        }
    }

    pub async fn get_btc_tx_data(
        &self,
        chain: ChainKind,
        near_tx_hash: CryptoHash,
        relayer: Option<AccountId>,
    ) -> Result<Vec<u8>> {
        let relayer_id = match relayer {
            Some(relayer) => relayer,
            None => self.satoshi_relayer(chain)?,
        };

        let log = self
            .extract_transfer_log(near_tx_hash, Some(relayer_id), "signed_btc_transaction")
            .await?;

        let json_str = log
            .strip_prefix("EVENT_JSON:")
            .ok_or(BridgeSdkError::InvalidLog(
                "Missing EVENT_JSON prefix".to_string(),
            ))?;
        let v: Value = serde_json::from_str(json_str)?;

        let bytes = if let Some(_) = v["data"][0].get("tx_bytes_base64") {
            base64::engine::general_purpose::STANDARD
                .decode(v["data"][0]["tx_bytes_base64"].as_str().ok_or_else(|| {
                    BridgeSdkError::InvalidLog(
                        "Expected string value in 'tx_bytes_base64'".to_string(),
                    )
                })?)
                .map_err(|err| {
                    BridgeSdkError::InvalidLog(format!("Error on parsing base64: {err}"))
                })?
        } else {
            v["data"][0]["tx_bytes"]
                .as_array()
                .ok_or_else(|| {
                    BridgeSdkError::InvalidLog("Expected 'tx_bytes' to be an array".to_string())
                })?
                .iter()
                .map(|val| {
                    let num = val.as_u64().ok_or_else(|| {
                        BridgeSdkError::InvalidLog(format!(
                            "Expected u64 value in 'tx_bytes', got: {val}"
                        ))
                    })?;

                    u8::try_from(num).map_err(|e| {
                        BridgeSdkError::InvalidLog(format!(
                            "Value {num} in 'tx_bytes' is out of range for u8: {e}"
                        ))
                    })
                })
                .collect::<Result<Vec<u8>>>()?
        };

        Ok(bytes)
    }

    pub async fn extract_recipient_and_amount_from_logs(
        &self,
        near_tx_hash: CryptoHash,
        sender_id: Option<AccountId>,
    ) -> Result<NearToBtcTransferInfo> {
        let (log, event_name) = if let Ok(log) = self
            .extract_transfer_log(near_tx_hash, sender_id.clone(), "InitTransferEvent")
            .await
        {
            (log, "InitTransferEvent")
        } else {
            (
                self.extract_transfer_log(near_tx_hash, sender_id, "FinTransferEvent")
                    .await?,
                "FinTransferEvent",
            )
        };

        let v: Value = serde_json::from_str(&log)?;

        let amount_str = &v[event_name]["transfer_message"]["amount"];
        let amount: u128 = amount_str
            .as_str()
            .ok_or(BridgeSdkError::InvalidLog(format!(
                "'amount' not found in {event_name}"
            )))?
            .parse()
            .map_err(|err| {
                BridgeSdkError::InvalidLog(format!("Error on parsing 'amount' {err}"))
            })?;

        let fee_str = &v[event_name]["transfer_message"]["fee"]["fee"];
        let fee: u128 = fee_str
            .as_str()
            .ok_or(BridgeSdkError::InvalidLog(format!(
                "'fee' not found in {event_name}"
            )))?
            .parse()
            .map_err(|err| BridgeSdkError::InvalidLog(format!("Error on parsing 'fee' {err}")))?;

        let recipient_full = v[event_name]["transfer_message"]["recipient"]
            .as_str()
            .ok_or(BridgeSdkError::InvalidLog(format!(
                "'recipient' not found in {event_name}"
            )))?;

        let recipient = match OmniAddress::from_str(recipient_full) {
            Ok(OmniAddress::Btc(addr) | OmniAddress::Zcash(addr)) => addr,
            Ok(_) => {
                return Err(BridgeSdkError::InvalidArgument(
                    "Unsupported recipient chain".to_string(),
                ))
            }
            Err(_) => recipient_full.to_owned(),
        };

        let origin_id_str = &v[event_name]["transfer_message"]["origin_nonce"];
        let origin_id: u64 = origin_id_str.as_u64().ok_or(BridgeSdkError::InvalidLog(
            "Error on parsing origin_id".to_string(),
        ))?;

        let sender_str = &v[event_name]["transfer_message"]["sender"];
        let sender_chain: OmniAddress = OmniAddress::from_str(sender_str.as_str().ok_or(
            BridgeSdkError::InvalidLog("Error on parsing sender".to_string()),
        )?)
        .map_err(|err| BridgeSdkError::InvalidLog(format!("Error on parsing sender {err}")))?;

        let msg =
            v[event_name]["transfer_message"]["msg"]
                .as_str()
                .ok_or(BridgeSdkError::InvalidLog(
                    "Error on parsing message".to_string(),
                ))?;

        let max_gas_fee: Option<u64> = if msg.is_empty() {
            None
        } else {
            let utxo_chain_extra_info: UTXOChainMsg = serde_json::from_str(msg)?;
            let UTXOChainMsg::MaxGasFee(max_fee) = utxo_chain_extra_info;
            Some(max_fee.0)
        };

        Ok(NearToBtcTransferInfo {
            recipient,
            amount: amount - fee,
            transfer_id: TransferId {
                origin_chain: sender_chain.get_chain(),
                origin_nonce: origin_id,
            },
            max_gas_fee,
        })
    }

    pub async fn extract_transaction_id(
        &self,
        transaction_hash: CryptoHash,
        sender_id: Option<AccountId>,
    ) -> Result<TransferId> {
        let log = self
            .extract_transfer_log(transaction_hash, sender_id, "InitTransferEvent")
            .await?;
        let v: Value = serde_json::from_str(&log)?;

        let origin_nonce = &v["InitTransferEvent"]["transfer_message"]["origin_nonce"]
            .as_u64()
            .unwrap();
        let sender = OmniAddress::from_str(
            v["InitTransferEvent"]["transfer_message"]["sender"]
                .as_str()
                .unwrap(),
        )
        .unwrap();
        let origin_chain_id = sender.get_chain();

        Ok(TransferId {
            origin_chain: origin_chain_id,
            origin_nonce: *origin_nonce,
        })
    }

    pub fn utxo_chain_connector(&self, chain: ChainKind) -> Result<AccountId> {
        self.utxo_bridges
            .get(&chain)
            .ok_or(BridgeSdkError::ConfigError(
                "BTC accounts id is not set".to_string(),
            ))?
            .utxo_chain_connector
            .as_ref()
            .ok_or(BridgeSdkError::ConfigError(
                "BTC Connector account id is not set".to_string(),
            ))
            .map_err(|_| {
                BridgeSdkError::ConfigError("Invalid btc connector account id".to_string())
            })
            .cloned()
    }

    pub fn utxo_chain_token(&self, chain: ChainKind) -> Result<AccountId> {
        self.utxo_bridges
            .get(&chain)
            .ok_or(BridgeSdkError::ConfigError(
                "BTC accounts id is not set".to_string(),
            ))?
            .utxo_chain_token
            .as_ref()
            .ok_or(BridgeSdkError::ConfigError(
                "Bitcoin account id is not set".to_string(),
            ))
            .map_err(|_| BridgeSdkError::ConfigError("Invalid bitcoin account id".to_string()))
            .cloned()
    }

    pub fn satoshi_relayer(&self, chain: ChainKind) -> Result<AccountId> {
        self.utxo_bridges
            .get(&chain)
            .ok_or(BridgeSdkError::ConfigError(
                "BTC accounts id is not set".to_string(),
            ))?
            .satoshi_relayer
            .as_ref()
            .ok_or(BridgeSdkError::ConfigError(
                "Satoshi Relayer account id is not set".to_string(),
            ))
            .map_err(|_| {
                BridgeSdkError::ConfigError("Invalid Satoshi Relayer account id".to_string())
            })
            .cloned()
    }
}
