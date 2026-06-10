use crate::NearBridgeClient;
use crate::TransactionOptions;
use base64::Engine;
use bitcoin::{OutPoint, PublicKey as BtcPublicKey, TxOut};
use bridge_connector_common::result::{BridgeSdkError, Result};
use futures::future::join_all;
use k256::elliptic_curve::sec1::ToEncodedPoint;
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
const BTC_REQUEST_REFUND_GAS: u64 = 300_000_000_000_000;
const BTC_VERIFY_REFUND_FINALIZE_GAS: u64 = 300_000_000_000_000;
const SUBMIT_BTC_TRANSFER_GAS: u64 = 300_000_000_000_000;

const INIT_BTC_TRANSFER_DEPOSIT: u128 = 1;
const ACTIVE_UTXO_MANAGEMENT_DEPOSIT: u128 = 1;
const SIGN_BTC_TRANSACTION_DEPOSIT: u128 = 1;
const BTC_SAFE_VERIFY_DEPOSIT_DEPOSIT: u128 = 1_200_000_000_000_000_000_000;
const BTC_VERIFY_DEPOSIT_DEPOSIT: u128 = 0;
const BTC_VERIFY_WITHDRAW_DEPOSIT: u128 = 0;
const BTC_CANCEL_WITHDRAW_DEPOSIT: u128 = 1;
const BTC_RBF_INCREASE_GAS_FEE_DEPOSIT: u128 = 0;
const BTC_VERIFY_ACTIVE_UTXO_MANAGEMENT_DEPOSIT: u128 = 0;
const BTC_REQUEST_REFUND_DEPOSIT: u128 = 0;
const BTC_VERIFY_REFUND_FINALIZE_DEPOSIT: u128 = 0;
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
pub struct OriginalState {
    pub stage: PendingInfoStage,
    #[serde_as(as = "DisplayFromStr")]
    pub max_gas_fee: u128,
    pub last_rbf_time_sec: Option<u32>,
    pub cancel_rbf_reserved: Option<U128>,
}

#[serde_as]
#[derive(Clone, serde::Serialize, serde::Deserialize, Debug)]
pub enum PendingInfoStage {
    PendingSign,
    PendingVerify,
    PendingBurn,
}

#[serde_as]
#[derive(Clone, serde::Serialize, serde::Deserialize, Debug)]
pub struct RbfState {
    pub stage: PendingInfoStage,
    pub original_tx_id: String,
}

#[serde_as]
#[derive(Clone, serde::Serialize, serde::Deserialize, Debug)]
pub enum PendingInfoState {
    WithdrawOriginal(OriginalState),
    WithdrawUserRbf(RbfState),
    WithdrawCancelRbf(RbfState),
    ActiveUtxoManagementOriginal(OriginalState),
    ActiveUtxoManagementRbf(RbfState),
    ActiveUtxoManagementCancelRbf(RbfState),
    Refund(OriginalState),
}

impl PendingInfoState {
    pub fn is_active_utxo_management(&self) -> bool {
        matches!(
            self,
            PendingInfoState::ActiveUtxoManagementOriginal(_)
                | PendingInfoState::ActiveUtxoManagementRbf(_)
                | PendingInfoState::ActiveUtxoManagementCancelRbf(_)
        )
    }

    pub fn is_withdraw(&self) -> bool {
        matches!(
            self,
            PendingInfoState::WithdrawOriginal(_)
                | PendingInfoState::WithdrawUserRbf(_)
                | PendingInfoState::WithdrawCancelRbf(_)
        )
    }
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
    pub state: PendingInfoState,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refund_address: Option<String>,
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct TxInclusionProof {
    pub tx_block_blockhash: String,
    pub tx_index: u64,
    pub merkle_proof: Vec<String>,
    pub coinbase_tx_id: String,
    pub coinbase_merkle_proof: Vec<String>,
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct FinBtcTransferArgs {
    pub deposit_msg: DepositMsg,
    pub tx_bytes: Vec<u8>,
    pub vout: usize,
    pub proof: TxInclusionProof
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct BtcVerifyWithdrawArgs {
    pub tx_id: String,
    pub proof: TxInclusionProof
}

#[serde_as]
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct BtcRequestRefundArgs {
    pub deposit_msg: DepositMsg,
    pub refund_address: String,
    pub tx_bytes: Vec<u8>,
    pub vout: usize,
    pub proof: TxInclusionProof,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde_as(as = "Option<DisplayFromStr>")]
    pub gas_fee: Option<u128>,
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct BtcVerifyRefundFinalizeArgs {
    pub tx_id: String,
    pub proof: TxInclusionProof
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct ChainSpecificData {
    pub orchard_bundle_bytes: Base64VecU8,
    pub expiry_height: u32,
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
    #[serde_as(as = "DisplayFromStr")]
    min_change_amount: u128,
    #[serde_as(as = "DisplayFromStr")]
    max_change_amount: u128,
    max_withdrawal_input_number: u8,
    max_change_number: u8,
    passive_management_lower_limit: u32,
    passive_management_upper_limit: u32,
    max_active_utxo_management_input_number: u8,
    max_active_utxo_management_output_number: u8,
    active_management_lower_limit: u32,
    active_management_upper_limit: u32,
    confirmations_strategy: HashMap<String, u8>,
    confirmations_delta: u8,
    extra_msg_confirmations_delta: u8,
    expiry_height_gap: Option<u32>,
    chain_signatures_root_public_key: Option<near_sdk::PublicKey>,
}

#[serde_as]
#[derive(Clone, serde::Serialize, serde::Deserialize)]
struct PartialMetadata {
    pub current_utxos_num: u32,
}

#[derive(Clone, serde::Deserialize)]
struct WhitelistMetadata {
    relayer_white_list: Vec<AccountId>,
    extra_msg_relayer_white_list: Vec<AccountId>,
}

#[derive(Clone, Debug)]
pub struct BtcConfirmationContext {
    pub confirmations_strategy: HashMap<String, u8>,
    pub confirmations_delta: u8,
    pub extra_msg_confirmations_delta: u8,
    pub is_relayer_whitelisted: bool,
    pub is_extra_msg_relayer_whitelisted: bool,
}

impl BtcConfirmationContext {
    /// Compute required confirmations for a contract call.
    ///
    /// `uses_extra_msg_path` must be `true` only when the contract will dispatch
    /// to `get_extra_msg_confirmations` — that is, the SDK is calling
    /// `verify_deposit` AND `deposit_msg.extra_msg.is_some()`. All other paths
    /// (`safe_verify_deposit`, `verify_withdraw`, `verify_active_utxo_management`,
    /// and `verify_deposit` without `extra_msg`) dispatch to `get_confirmations`
    /// and must pass `false` here, even if the surrounding `DepositMsg` happens
    /// to carry an `extra_msg` field.
    pub fn required_confirmations(&self, amount: u128, uses_extra_msg_path: bool) -> Result<u64> {
        let base = base_confirmations(&self.confirmations_strategy, amount)?;

        let delta = if uses_extra_msg_path {
            if self.is_extra_msg_relayer_whitelisted {
                0
            } else {
                self.extra_msg_confirmations_delta
            }
        } else if self.is_relayer_whitelisted {
            0
        } else {
            self.confirmations_delta
        };

        Ok(u64::from(base) + u64::from(delta))
    }
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
#[derive(serde::Deserialize)]
struct Logs {
    data: Vec<LogsData>,
}

#[derive(serde::Deserialize)]
struct LogsData {
    #[serde(flatten)]
    tx: TxBytes,
}

#[derive(serde::Deserialize)]
#[serde(untagged)]
enum TxBytes {
    Base64 { tx_bytes_base64: String },
    Array { tx_bytes: Vec<u8> },
}

impl TxBytes {
    fn into_bytes(self) -> Result<Vec<u8>> {
        match self {
            TxBytes::Base64 { tx_bytes_base64 } => base64::engine::general_purpose::STANDARD
                .decode(tx_bytes_base64)
                .map_err(|e| BridgeSdkError::InvalidLog(format!("Error parsing base64: {e}"))),
            TxBytes::Array { tx_bytes } => Ok(tx_bytes),
        }
    }
}

/// Format a MaxGasFee message for UTXO chain transfers.
/// This produces JSON like: `{"MaxGasFee":"400"}`
pub fn format_max_gas_fee(gas_fee: u64) -> String {
    serde_json::to_string(&UTXOChainMsg::MaxGasFee(U64::from(gas_fee)))
        .expect("Failed to serialize UTXOChainMsg")
}

// Mirrors `Config::get_confirmations` from the satoshi-bridge contract: pick the
// confirmations value at the smallest threshold strictly greater than `amount`,
// falling back to the value at the largest threshold.
fn base_confirmations(strategy: &HashMap<String, u8>, amount: u128) -> Result<u8> {
    if strategy.is_empty() {
        return Err(BridgeSdkError::ContractConfigurationError(
            "confirmations_strategy is empty".to_string(),
        ));
    }

    let mut keys = strategy
        .keys()
        .map(|k| k.parse::<u128>())
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|e| {
            BridgeSdkError::ContractConfigurationError(format!(
                "Invalid confirmations_strategy key: {e}"
            ))
        })?;
    keys.sort_unstable();

    for key in &keys {
        if *key > amount {
            return Ok(*strategy
                .get(&key.to_string())
                .expect("key sourced from strategy"));
        }
    }

    let max_key = keys.last().expect("non-empty");
    Ok(*strategy
        .get(&max_key.to_string())
        .expect("key sourced from strategy"))
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
        orchard_bundle_hex: Option<String>,
        expiry_height: Option<u32>,
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
                    "output": outs,
                    "orchard_bundle_bytes": orchard_bundle_hex,
                    "expiry_height": expiry_height
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
        let deposit = if args.deposit_msg.safe_deposit.is_some() {
            BTC_SAFE_VERIFY_DEPOSIT_DEPOSIT
        } else {
            BTC_VERIFY_DEPOSIT_DEPOSIT
        };
        let tx_hash = near_rpc_client::change_and_wait(
            endpoint,
            ChangeRequest {
                signer: self.signer()?,
                nonce: transaction_options.nonce,
                receiver_id: btc_connector,
                method_name: "verify_deposit_v2".to_string(),
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
                method_name: "verify_withdraw_v2".to_string(),
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
                method_name: "verify_active_utxo_management_v2".to_string(),
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

    /// Submit a refund request for a never-finalized BTC deposit (Bitcoin only).
    #[tracing::instrument(skip_all, name = "NEAR BTC REQUEST REFUND")]
    pub async fn btc_request_refund(
        &self,
        args: BtcRequestRefundArgs,
        transaction_options: TransactionOptions,
    ) -> Result<CryptoHash> {
        let endpoint = self.endpoint()?;
        let btc_connector = self.utxo_chain_connector(ChainKind::Btc)?;
        let tx_hash = near_rpc_client::change_and_wait(
            endpoint,
            ChangeRequest {
                signer: self.signer()?,
                nonce: transaction_options.nonce,
                receiver_id: btc_connector,
                method_name: "request_refund".to_string(),
                args: serde_json::json!(args).to_string().into_bytes(),
                gas: BTC_REQUEST_REFUND_GAS,
                deposit: BTC_REQUEST_REFUND_DEPOSIT,
            },
            transaction_options.wait_until,
            transaction_options.wait_final_outcome_timeout_sec,
        )
        .await?;

        tracing::info!(
            tx_hash = tx_hash.to_string(),
            "Sent BTC Request Refund transaction"
        );
        Ok(tx_hash)
    }

    /// Verify that the refund BTC transaction has been confirmed (Bitcoin only).
    #[tracing::instrument(skip_all, name = "NEAR BTC VERIFY REFUND FINALIZE")]
    pub async fn btc_verify_refund_finalize(
        &self,
        args: BtcVerifyRefundFinalizeArgs,
        transaction_options: TransactionOptions,
    ) -> Result<CryptoHash> {
        let endpoint = self.endpoint()?;
        let btc_connector = self.utxo_chain_connector(ChainKind::Btc)?;
        let tx_hash = near_rpc_client::change_and_wait(
            endpoint,
            ChangeRequest {
                signer: self.signer()?,
                nonce: transaction_options.nonce,
                receiver_id: btc_connector,
                method_name: "verify_refund_finalize".to_string(),
                args: serde_json::json!(args).to_string().into_bytes(),
                gas: BTC_VERIFY_REFUND_FINALIZE_GAS,
                deposit: BTC_VERIFY_REFUND_FINALIZE_DEPOSIT,
            },
            transaction_options.wait_until,
            transaction_options.wait_final_outcome_timeout_sec,
        )
        .await?;

        tracing::info!(
            tx_hash = tx_hash.to_string(),
            "Sent BTC Verify Refund Finalize transaction"
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
        recipient_id: &OmniAddress,
        refund_address: Option<String>,
        fee: u128,
    ) -> Result<String> {
        let deposit_msg =
            self.get_deposit_msg_for_omni_bridge(recipient_id, refund_address, fee)?;
        self.get_btc_address_from_deposit_msg(chain, &deposit_msg)
            .await
    }

    /// Fetch the BTC deposit address for a `DepositMsg` that mints nBTC directly
    /// to a NEAR account (without the Omni Bridge wrapper).
    pub async fn get_btc_address_for_near_account(
        &self,
        chain: ChainKind,
        recipient_id: AccountId,
        refund_address: Option<String>,
    ) -> Result<String> {
        let deposit_msg = self.get_deposit_msg_for_near_account(recipient_id, refund_address);
        self.get_btc_address_from_deposit_msg(chain, &deposit_msg)
            .await
    }

    pub async fn get_btc_address_from_deposit_msg(
        &self,
        chain: ChainKind,
        deposit_msg: &DepositMsg,
    ) -> Result<String> {
        let api_url = self
            .bridge_indexer_api_url()?
            .join("api/v3/utxo/get_user_deposit_address")
            .map_err(|e| {
                BridgeSdkError::ConfigError(format!("Failed to construct api endpoint url: {e}"))
            })?;

        let chain_name = match chain {
            ChainKind::Btc => "btc",
            ChainKind::Zcash => "zcash",
            _ => {
                return Err(BridgeSdkError::InvalidArgument(format!(
                    "Unsupported UTXO chain: {chain:?}"
                )))
            }
        };

        #[derive(serde::Serialize)]
        struct DepositAddressRequest {
            chain: String,
            recipient: String,
            #[serde(skip_serializing_if = "Option::is_none")]
            safe_deposit: Option<SafeDepositMsg>,
            #[serde(skip_serializing_if = "Option::is_none")]
            refund_address: Option<String>,
        }

        let request_body = DepositAddressRequest {
            chain: chain_name.to_string(),
            recipient: deposit_msg.recipient_id.to_string(),
            safe_deposit: deposit_msg.safe_deposit.clone(),
            refund_address: deposit_msg.refund_address.clone(),
        };

        #[derive(serde::Deserialize)]
        struct DepositAddressResponse {
            address: String,
        }

        let body = send_indexer_request(
            reqwest::Client::new()
                .post(api_url)
                .timeout(std::time::Duration::from_secs(10))
                .json(&request_body),
        )
        .await?;
        let parsed: DepositAddressResponse = serde_json::from_str(&body)?;

        Ok(parsed.address)
    }

    /// Look up the `DepositMsg` that was stored by the bridge indexer when a
    /// deposit address was issued.
    ///
    /// Returns `Ok(None)` if the indexer does not know the address (HTTP 404)
    /// — caller treats this as "not a tracked deposit address". Any other
    /// non-success status is reported as an error.
    pub async fn get_deposit_msg_by_address(
        &self,
        chain: ChainKind,
        address: &str,
    ) -> Result<Option<DepositMsg>> {
        let api_url = self
            .bridge_indexer_api_url()?
            .join("api/v3/utxo/get_deposit_message")
            .map_err(|e| {
                BridgeSdkError::ConfigError(format!("Failed to construct api endpoint url: {e}"))
            })?;

        let chain_name = match chain {
            ChainKind::Btc => "btc",
            ChainKind::Zcash => "zcash",
            _ => {
                return Err(BridgeSdkError::InvalidArgument(format!(
                    "Unsupported UTXO chain: {chain:?}"
                )))
            }
        };

        let Some(body) = send_indexer_request_opt(
            reqwest::Client::new()
                .get(api_url)
                .timeout(std::time::Duration::from_secs(10))
                .query(&[("chain", chain_name), ("address", address)]),
        )
        .await?
        else {
            return Ok(None);
        };
        let parsed: DepositMsg = serde_json::from_str(&body)?;

        Ok(Some(parsed))
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

    pub async fn get_pk_for_utxo(&self, chain: ChainKind, utxo: UTXO) -> Result<String> {
        let config = self.get_config(chain).await?;
        let btc_connector = self.utxo_chain_connector(chain)?;
        let chain_signatures_root_public_key = config.chain_signatures_root_public_key.ok_or(
            BridgeSdkError::ContractConfigurationError(format!(
                "Chain signatures root public key is not set for chain {chain:?}",
            )),
        )?;

        let mpc_pk =
            crypto_shared::near_public_key_to_affine_point(chain_signatures_root_public_key);
        let epsilon =
            crypto_shared::derive_epsilon(&btc_connector.to_string().parse().unwrap(), &utxo.path);
        let user_pk = crypto_shared::derive_key(mpc_pk, epsilon);
        let user_pk_encoded_point = user_pk.to_encoded_point(false);
        let public_key_bytes = user_pk_encoded_point.as_bytes().to_vec();
        let uncompressed_btc_public_key =
            BtcPublicKey::from_slice(&public_key_bytes).expect("Invalid public key bytes");

        Ok(uncompressed_btc_public_key.inner.to_string())
    }

    pub async fn get_expiry_height_gap(&self, chain: ChainKind) -> Result<u32> {
        let config = self.get_config(chain).await?;
        Ok(config.expiry_height_gap.unwrap_or(0))
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
    ) -> Result<(u32, u32, u8, u8, u128)> {
        let config = self.get_config(chain).await?;
        Ok((
            config.active_management_lower_limit,
            config.active_management_upper_limit,
            config.max_active_utxo_management_input_number,
            config.max_active_utxo_management_output_number,
            config.max_change_amount,
        ))
    }

    pub async fn get_withdraw_selection_params(
        &self,
        chain: ChainKind,
    ) -> Result<utxo_utils::WithdrawSelectionParams> {
        let config = self.get_config(chain).await?;
        Ok(utxo_utils::WithdrawSelectionParams {
            min_change_amount: config.min_change_amount,
            max_change_amount: config.max_change_amount,
            max_withdrawal_input_number: config.max_withdrawal_input_number.into(),
            max_change_number: config.max_change_number.into(),
            passive_management_lower_limit: config.passive_management_lower_limit,
            passive_management_upper_limit: config.passive_management_upper_limit,
            active_management_upper_limit: config.active_management_upper_limit,
        })
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

    pub async fn get_btc_confirmation_context(
        &self,
        chain: ChainKind,
    ) -> Result<BtcConfirmationContext> {
        let signer_account_id = self.account_id()?;
        let (config, whitelist) =
            futures::try_join!(self.get_config(chain), self.get_whitelist_metadata(chain))?;

        Ok(BtcConfirmationContext {
            confirmations_strategy: config.confirmations_strategy,
            confirmations_delta: config.confirmations_delta,
            extra_msg_confirmations_delta: config.extra_msg_confirmations_delta,
            is_relayer_whitelisted: whitelist.relayer_white_list.contains(&signer_account_id),
            is_extra_msg_relayer_whitelisted: whitelist
                .extra_msg_relayer_white_list
                .contains(&signer_account_id),
        })
    }

    async fn get_whitelist_metadata(&self, chain: ChainKind) -> Result<WhitelistMetadata> {
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

        Ok(serde_json::from_slice::<WhitelistMetadata>(&response)?)
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
        recipient_id: &OmniAddress,
        refund_address: Option<String>,
        fee: u128,
    ) -> Result<DepositMsg> {
        if recipient_id.is_utxo_chain() {
            return Err(BridgeSdkError::InvalidArgument(
                "Cannot send directly to UTXO chains".to_string(),
            ));
        }
        let omni_bridge_id = self.omni_bridge_id()?;
        Ok(DepositMsg {
            recipient_id: omni_bridge_id,
            post_actions: None,
            extra_msg: None,
            refund_address,
            safe_deposit: Some(SafeDepositMsg {
                msg: json!({
                    "UtxoFinTransfer": {
                        "utxo_id": "will_be_replaced_by_the_bridge",
                        "recipient": recipient_id.to_string(),
                        "relayer_fee": fee.to_string(),
                        "msg": "",
                    }
                })
                .to_string(),
            }),
        })
    }

    /// Build a `DepositMsg` that mints nBTC directly to a NEAR account, bypassing
    /// the Omni Bridge safe-deposit wrapper.
    pub fn get_deposit_msg_for_near_account(
        &self,
        recipient_id: AccountId,
        refund_address: Option<String>,
    ) -> DepositMsg {
        DepositMsg {
            recipient_id,
            post_actions: None,
            extra_msg: None,
            safe_deposit: None,
            refund_address,
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

        let logs: Logs = serde_json::from_value(v)
            .map_err(|e| BridgeSdkError::InvalidLog(format!("Invalid log shape: {e}")))?;

        let entry = logs
            .data
            .into_iter()
            .next()
            .ok_or_else(|| BridgeSdkError::InvalidLog("Expected 'data[0]'".into()))?;

        let bytes = entry.tx.into_bytes()?;
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

fn indexer_request_err(e: reqwest::Error) -> BridgeSdkError {
    BridgeSdkError::BridgeIndexerError(e.to_string())
}

/// Send an HTTP request to the bridge indexer and return the response body
/// as text. Any non-success status (including 404) is reported as an error.
async fn send_indexer_request(request: reqwest::RequestBuilder) -> Result<String> {
    request
        .send()
        .await
        .map_err(indexer_request_err)?
        .error_for_status()
        .map_err(indexer_request_err)?
        .text()
        .await
        .map_err(indexer_request_err)
}

/// Like `send_indexer_request`, but maps HTTP 404 to `Ok(None)` so the caller
/// can distinguish "the indexer doesn't track this resource" from a real
/// transport / 5xx failure.
async fn send_indexer_request_opt(request: reqwest::RequestBuilder) -> Result<Option<String>> {
    let response = request.send().await.map_err(indexer_request_err)?;
    if response.status() == reqwest::StatusCode::NOT_FOUND {
        return Ok(None);
    }
    response
        .error_for_status()
        .map_err(indexer_request_err)?
        .text()
        .await
        .map(Some)
        .map_err(indexer_request_err)
}

#[cfg(test)]
mod tests {
    use bridge_connector_common::result::BridgeSdkError;
    use reqwest::Url;
    use std::collections::HashMap;
    use wiremock::matchers::{body_partial_json, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;
    use crate::NearBridgeClientBuilder;

    const DEPOSIT_ADDRESS_PATH: &str = "/api/v3/utxo/get_user_deposit_address";

    fn test_client(api_url: Option<Url>) -> NearBridgeClient {
        NearBridgeClientBuilder::default()
            .endpoint(None)
            .private_key(None)
            .signer(None)
            .omni_bridge_id(Some("omni.test.near".parse().unwrap()))
            .mpc_omni_prover_id(None)
            .utxo_bridges(HashMap::new())
            .bridge_indexer_api_url(api_url)
            .build()
            .unwrap()
    }

    fn near_recipient() -> OmniAddress {
        OmniAddress::Near("user.test.near".parse().unwrap())
    }

    #[tokio::test]
    async fn get_btc_address_returns_address_from_indexer() {
        let server = MockServer::start().await;
        let expected = "tb1qexampleaddress0000000000000000000000";
        Mock::given(method("POST"))
            .and(path(DEPOSIT_ADDRESS_PATH))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({"address": expected})),
            )
            .expect(1)
            .mount(&server)
            .await;

        let client = test_client(Some(server.uri().parse().unwrap()));
        let result = client
            .get_btc_address(ChainKind::Btc, &near_recipient(), None, 0)
            .await
            .expect("get_btc_address should succeed");

        assert_eq!(result, expected);
    }

    #[tokio::test]
    async fn get_btc_address_sends_btc_chain_in_request_body() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path(DEPOSIT_ADDRESS_PATH))
            .and(body_partial_json(serde_json::json!({
                "chain": "btc",
                "recipient": "omni.test.near",
            })))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({"address": "addr"})),
            )
            .expect(1)
            .mount(&server)
            .await;

        let client = test_client(Some(server.uri().parse().unwrap()));
        client
            .get_btc_address(ChainKind::Btc, &near_recipient(), None, 0)
            .await
            .expect("get_btc_address should succeed");
    }

    #[tokio::test]
    async fn get_btc_address_sends_zcash_chain_in_request_body() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path(DEPOSIT_ADDRESS_PATH))
            .and(body_partial_json(serde_json::json!({
                "chain": "zcash",
                "recipient": "omni.test.near",
            })))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({"address": "zaddr"})),
            )
            .expect(1)
            .mount(&server)
            .await;

        let client = test_client(Some(server.uri().parse().unwrap()));
        client
            .get_btc_address(ChainKind::Zcash, &near_recipient(), None, 0)
            .await
            .expect("get_btc_address should succeed");
    }

    #[tokio::test]
    async fn get_btc_address_includes_safe_deposit_with_relayer_fee() {
        let server = MockServer::start().await;
        let captured_body = std::sync::Arc::new(std::sync::Mutex::new(None::<serde_json::Value>));
        let captured_clone = captured_body.clone();

        Mock::given(method("POST"))
            .and(path(DEPOSIT_ADDRESS_PATH))
            .respond_with(move |req: &wiremock::Request| {
                *captured_clone.lock().unwrap() = Some(serde_json::from_slice(&req.body).unwrap());
                ResponseTemplate::new(200).set_body_json(serde_json::json!({"address": "addr"}))
            })
            .mount(&server)
            .await;

        let client = test_client(Some(server.uri().parse().unwrap()));
        client
            .get_btc_address(ChainKind::Btc, &near_recipient(), None, 4242)
            .await
            .expect("get_btc_address should succeed");

        let body = captured_body
            .lock()
            .unwrap()
            .clone()
            .expect("request captured");
        let safe_deposit_msg = body
            .pointer("/safe_deposit/msg")
            .and_then(|v| v.as_str())
            .expect("safe_deposit.msg present");
        let inner: serde_json::Value = serde_json::from_str(safe_deposit_msg).expect("inner json");
        assert_eq!(inner["UtxoFinTransfer"]["relayer_fee"], "4242");
    }

    #[tokio::test]
    async fn get_btc_address_unsupported_chain_returns_invalid_argument() {
        let server = MockServer::start().await;
        // No mock mounted: a successful HTTP call would fail. We expect early validation.
        let client = test_client(Some(server.uri().parse().unwrap()));
        let err = client
            .get_btc_address(ChainKind::Eth, &near_recipient(), None, 0)
            .await
            .expect_err("Eth is not a UTXO chain");

        assert!(
            matches!(err, BridgeSdkError::InvalidArgument(_)),
            "expected InvalidArgument, got {err:?}"
        );
    }

    #[tokio::test]
    async fn get_btc_address_missing_api_url_returns_config_error() {
        let client = test_client(None);
        let err = client
            .get_btc_address(ChainKind::Btc, &near_recipient(), None, 0)
            .await
            .expect_err("missing api url should fail");

        assert!(
            matches!(err, BridgeSdkError::ConfigError(_)),
            "expected ConfigError, got {err:?}"
        );
    }

    #[tokio::test]
    async fn get_btc_address_propagates_indexer_http_error() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path(DEPOSIT_ADDRESS_PATH))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;

        let client = test_client(Some(server.uri().parse().unwrap()));
        let err = client
            .get_btc_address(ChainKind::Btc, &near_recipient(), None, 0)
            .await
            .expect_err("500 status should fail");

        assert!(
            matches!(err, BridgeSdkError::BridgeIndexerError(_)),
            "expected BridgeIndexerError, got {err:?}"
        );
    }

    fn strategy(entries: &[(&str, u8)]) -> HashMap<String, u8> {
        entries
            .iter()
            .map(|(k, v)| ((*k).to_string(), *v))
            .collect()
    }

    #[test]
    fn empty_strategy_errors() {
        let result = base_confirmations(&HashMap::new(), 0);
        assert!(matches!(
            result,
            Err(BridgeSdkError::ContractConfigurationError(_))
        ));
    }

    #[test]
    fn single_tier_amount_below_threshold() {
        let s = strategy(&[("100000000", 2)]);
        assert_eq!(base_confirmations(&s, 50_000_000).unwrap(), 2);
    }

    #[test]
    fn single_tier_amount_at_threshold_falls_back_to_max() {
        let s = strategy(&[("100000000", 2)]);
        assert_eq!(base_confirmations(&s, 100_000_000).unwrap(), 2);
    }

    #[test]
    fn single_tier_amount_above_threshold() {
        let s = strategy(&[("100000000", 2)]);
        assert_eq!(base_confirmations(&s, 200_000_000).unwrap(), 2);
    }

    #[test]
    fn multi_tier_picks_first_threshold_above_amount() {
        let s = strategy(&[("100000000", 2), ("1000000000", 4), ("10000000000", 6)]);
        assert_eq!(base_confirmations(&s, 50_000_000).unwrap(), 2);
        assert_eq!(base_confirmations(&s, 500_000_000).unwrap(), 4);
        assert_eq!(base_confirmations(&s, 5_000_000_000).unwrap(), 6);
    }

    #[test]
    fn multi_tier_amount_equal_to_threshold_picks_next_tier() {
        let s = strategy(&[("100000000", 2), ("1000000000", 4)]);
        assert_eq!(base_confirmations(&s, 100_000_000).unwrap(), 4);
    }

    #[test]
    fn multi_tier_amount_above_largest_falls_back_to_max_key() {
        let s = strategy(&[("100000000", 2), ("1000000000", 4)]);
        assert_eq!(base_confirmations(&s, 50_000_000_000).unwrap(), 4);
    }

    #[test]
    fn invalid_key_returns_configuration_error() {
        let mut s = strategy(&[("100000000", 2)]);
        s.insert("not-a-number".to_string(), 3);
        assert!(matches!(
            base_confirmations(&s, 0),
            Err(BridgeSdkError::ContractConfigurationError(_))
        ));
    }
}
