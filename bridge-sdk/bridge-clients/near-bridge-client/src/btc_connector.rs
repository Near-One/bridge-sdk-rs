use crate::NearBridgeClient;
use crate::TransactionOptions;
use bridge_connector_common::result::{BridgeSdkError, Result};
use near_primitives::types::Gas;
use near_primitives::{hash::CryptoHash, types::AccountId};
use near_rpc_client::ChangeRequest;
use near_sdk::json_types::U128;

const FIN_BTC_TRANSFER_GAS: u64 = 300_000_000_000_000;

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

impl NearBridgeClient {
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
                deposit: 0,
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

    pub fn get_deposit_msg_by_recipient_id(
        &self,
        recipient_id: &str,
        amount: u128,
    ) -> Result<DepositMsg> {
        if recipient_id.contains(':') {
            let omni_bridge_id = self.omni_bridge_id()?;
            Ok(DepositMsg {
                recipient_id: omni_bridge_id.clone(),
                post_actions: Some(vec![PostAction {
                    receiver_id: omni_bridge_id,
                    amount: U128(amount),
                    memo: None,
                    msg: recipient_id.to_string(),
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
