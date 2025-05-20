use crate::NearBridgeClient;
use crate::TransactionOptions;
use bridge_connector_common::result::{BridgeSdkError, Result};
use near_primitives::types::Gas;
use near_primitives::{hash::CryptoHash, types::AccountId};
use near_rpc_client::{ChangeRequest, ViewRequest};
use serde_json::json;
use serde_with::{serde_as, DisplayFromStr};

const FIN_BTC_TRANSFER_GAS: u64 = 300_000_000_000_000;
const BTC_VERIFY_WITHDRAW_GAS: u64 = 300_000_000_000_000;

const FIN_BTC_TRANSFER_DEPOSIT: u128 = 0;
const BTC_VERIFY_WITHDRAW_DEPOSIT: u128 = 0;

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

    // Submit the proof to the btc_connector on NEAR that the withdraw transfer
    // to Bitcoin was successfully completed. It is needed in order to store the new change UTXO
    // and to ensure the relayer receives the fee.
    #[tracing::instrument(skip_all, name = "NEAR BTC VERIFY WITHDRAW")]
    pub async fn btc_verify_withdraw(
        &self,
        args: BtcVerifyWithdrawArgs,
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
                method_name: "verify_withdraw".to_string(),
                args: serde_json::json!(args).to_string().into_bytes(),
                gas: BTC_VERIFY_WITHDRAW_GAS,
                deposit: BTC_VERIFY_WITHDRAW_DEPOSIT,
            },
            transaction_options.wait_until,
            wait_final_outcome_timeout_sec,
        )
        .await?;

        tracing::info!(
            tx_hash = tx_hash.to_string(),
            "Sent BTC Verify Withdraw transaction"
        );
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
}
