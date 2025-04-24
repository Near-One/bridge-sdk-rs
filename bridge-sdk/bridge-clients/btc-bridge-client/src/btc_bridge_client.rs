use std::str::FromStr;
use bitcoincore_rpc::bitcoin;
use btc_relayer_lib::bitcoin_client::Client as BitcoinClient;
use btc_relayer_lib::near_client::NearClient;
use btc_relayer_lib::config::{BitcoinConfig, Config, NearConfig};
use bitcoin::consensus::serialize;
use near_sdk::{AccountId, CryptoHash, Gas};
use near_sdk::json_types::U128;
use near_rpc_client::{ChangeRequest};
use serde::{Serialize, Deserialize};

const VERIFY_DEPOSIT_GAS: u64 = 300_000_000_000_000;

#[derive(Debug)]
pub struct TxProof {
    tx_bytes: Vec<u8>,
    tx_block_blockhash: String,
    tx_index: u64,
    merkle_proof: Vec<String>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct PostAction {
    pub receiver_id: AccountId,
    pub amount: U128,
    pub memo: Option<String>,
    pub msg: String,
    pub gas: Option<Gas>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct DepositMsg {
    pub recipient_id: AccountId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub post_actions: Option<Vec<PostAction>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extra_msg: Option<String>,
}


pub struct BtcBridgeClient {
    bitcoin_client: BitcoinClient,
    near_client: NearClient
}

impl BtcBridgeClient {
    pub fn new(btc_endpoint: String) -> Self {
        let config = Config {
            max_fork_len: 500,
            sleep_time_on_fail_sec: 30,
            sleep_time_on_reach_last_block_sec: 60,
            sleep_time_after_sync_iteration_sec: 5,
            batch_size: 4,
            bitcoin: BitcoinConfig {
                endpoint: btc_endpoint,
                node_user: "".to_string(),
                node_password: "".to_string(),
            },
            near: NearConfig {
                endpoint: "https://rpc.testnet.near.org".to_string(),
                btc_light_client_account_id: "brg-dev.testnet".to_string(),
                account_name: None,
                secret_key: None,
                near_credentials_path: Some("/home/olga/.near-credentials/testnet/olga24912_3.testnet.json".to_string()),
                transaction_timeout_sec: 120,
            },
        };

        let bitcoin_client = BitcoinClient::new(&config);
        let near_client = NearClient::new(&config.near);
        BtcBridgeClient {
            bitcoin_client,
            near_client
        }
    }

    pub fn extract_btc_proof(&self, tx_hash: String, tx_block_height: usize) -> TxProof {
        let block = self.bitcoin_client
            .get_block_by_height(
                u64::try_from(tx_block_height).expect("correct transaction height"),
            )
            .unwrap();
        let tx_block_blockhash = block.header.block_hash();

        let transactions = block
            .txdata
            .iter()
            .map(|tx| tx.compute_txid().to_string())
            .collect::<Vec<_>>();

        let tx_index = transactions.iter().position(|hash| *hash == tx_hash).unwrap();

        let merkle_proof = BitcoinClient::compute_merkle_proof(&block, tx_index);
        let merkle_proof_str = merkle_proof.iter().map(|hash| hash.to_string()).collect();

        let tx_data = serialize(&block.txdata[tx_index]);

        println!("{:?}", &block.txdata[tx_index]);

        TxProof {
            tx_bytes: tx_data,
            tx_block_blockhash: tx_block_blockhash.to_string(),
            tx_index: tx_index as u64,
            merkle_proof: merkle_proof_str,
        }
    }

    pub async fn fin_btc_transfer(&self, btc_tx_hash: String, tx_block_height: usize, vout: usize, deposit_msg: DepositMsg) {
        let near_credentials_path = "/home/olga/.near-credentials/testnet/olga24912_3.testnet.json".to_string();
        let (signer_account_id, signer_secret_key) = {
                let data = std::fs::read_to_string(near_credentials_path).unwrap();
                let res: serde_json::Value = serde_json::from_str(&data).unwrap();

                let private_key = res["private_key"].to_string().replace('\"', "");
                let private_key = near_crypto::SecretKey::from_str(private_key.as_str()).unwrap();

                let account_id = res["account_id"].to_string().replace('\"', "");
                let account_id = AccountId::from_str(account_id.as_str()).unwrap();
                (account_id, private_key)
            };

        let signer = near_crypto::InMemorySigner::from_secret_key(
            signer_account_id.clone(),
            signer_secret_key,
        );

        let mem_signer = match signer {
            near_crypto::Signer::InMemory(mem_signer) => mem_signer,
            _ => panic!("Not in memory signer")
        };

        let proof_data = self.extract_btc_proof(btc_tx_hash, tx_block_height);

        let tx_hash = near_rpc_client::change_and_wait(
            "https://rpc.testnet.near.org",
            ChangeRequest {
                signer: mem_signer,
                nonce: None,
                receiver_id: "brg-dev.testnet".parse().unwrap(),
                method_name: "verify_deposit".to_string(),
                args: serde_json::json!({
                    "deposit_msg": deposit_msg,
                    "tx_bytes": proof_data.tx_bytes,
                    "vout": vout,
                    "tx_block_blockhash": proof_data.tx_block_blockhash,
                    "tx_index": proof_data.tx_index,
                    "merkle_proof": proof_data.merkle_proof,
                })
                    .to_string()
                    .into_bytes(),
                gas: VERIFY_DEPOSIT_GAS,
                deposit: 0,
            },
            near_primitives::views::TxExecutionStatus::Final,
            None,
        )
            .await.unwrap();

        println!("tx hash: {:?}", tx_hash);
    }

}

#[cfg(test)]
mod tests {
    use crate::{BtcBridgeClient, DepositMsg};
    pub const BTC_ENDPOINT_TESTNET: &str = "https://bitcoin-testnet-rpc.publicnode.com";

    #[tokio::test]
    async fn test_get_proof() {
        let btc_client = BtcBridgeClient::new(BTC_ENDPOINT_TESTNET.to_string());
        btc_client.fin_btc_transfer("eac6198e86cda16867ac7ad81ba93eedb0ec4db9efd6b3b24bf581f8549cb3cb".to_string(), 4297082, 0, DepositMsg {
            recipient_id: "olga24912_3.testnet".parse().unwrap(),
            post_actions: None,
            extra_msg: None,
        }).await;
    }
}
