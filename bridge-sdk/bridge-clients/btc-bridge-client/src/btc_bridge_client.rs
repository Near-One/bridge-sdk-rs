use bitcoin::consensus::serialize;
use bitcoincore_rpc::bitcoin;
use bridge_connector_common::result::{BridgeSdkError, Result};
use btc_relayer_lib::bitcoin_client::Client as BitcoinClient;
use btc_relayer_lib::config::{BitcoinConfig, Config, NearConfig};

#[derive(Debug)]
pub struct TxProof {
    pub tx_bytes: Vec<u8>,
    pub tx_block_blockhash: String,
    pub tx_index: u64,
    pub merkle_proof: Vec<String>,
}

pub struct BtcBridgeClient {
    bitcoin_client: BitcoinClient,
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
                node_user: String::new(),
                node_password: String::new(),
            },
            near: NearConfig {
                endpoint: String::new(),
                btc_light_client_account_id: String::new(),
                account_name: None,
                secret_key: None,
                near_credentials_path: None,
                transaction_timeout_sec: 0,
            },
        };

        let bitcoin_client = BitcoinClient::new(&config);
        BtcBridgeClient { bitcoin_client }
    }

    pub fn extract_btc_proof(&self, tx_hash: &str, tx_block_height: usize) -> Result<TxProof> {
        let block = self
            .bitcoin_client
            .get_block_by_height(tx_block_height.try_into().unwrap())
            .map_err(|err| {
                BridgeSdkError::BtcClientError(format!("error on getting block by height: {err}"))
            })?;
        let tx_block_blockhash = block.header.block_hash();

        let transactions = block
            .txdata
            .iter()
            .map(|tx| tx.compute_txid().to_string())
            .collect::<Vec<_>>();

        let tx_index = transactions
            .iter()
            .position(|hash| *hash == tx_hash)
            .ok_or(BridgeSdkError::InvalidArgument(
                "btc tx not found in block".to_string(),
            ))?;

        let merkle_proof = BitcoinClient::compute_merkle_proof(&block, tx_index);
        let merkle_proof_str = merkle_proof
            .iter()
            .map(std::string::ToString::to_string)
            .collect();

        let tx_data = serialize(&block.txdata[tx_index]);

        Ok(TxProof {
            tx_bytes: tx_data,
            tx_block_blockhash: tx_block_blockhash.to_string(),
            tx_index: tx_index.try_into().unwrap(),
            merkle_proof: merkle_proof_str,
        })
    }
}
