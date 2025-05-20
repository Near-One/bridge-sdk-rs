use bitcoin::consensus::{deserialize, serialize};
use bitcoin::{BlockHash, Transaction};
use bitcoincore_rpc::bitcoin::hashes::Hash;
use bitcoincore_rpc::{bitcoin, jsonrpc, RpcApi};
use bridge_connector_common::result::{BridgeSdkError, Result};
use std::str::FromStr;

#[derive(Debug)]
pub struct TxProof {
    pub tx_bytes: Vec<u8>,
    pub tx_block_blockhash: String,
    pub tx_index: u64,
    pub merkle_proof: Vec<String>,
}

pub struct BtcBridgeClient {
    bitcoin_client: bitcoincore_rpc::Client,
}

impl BtcBridgeClient {
    pub fn new(btc_endpoint: &str) -> Self {
        let mut builder = jsonrpc::minreq_http::Builder::new()
            .url(btc_endpoint)
            .expect("Incorrect BTC endpoint");
        builder = builder.basic_auth(String::new(), Some(String::new()));

        BtcBridgeClient {
            bitcoin_client: bitcoincore_rpc::Client::from_jsonrpc(builder.build().into()),
        }
    }

    pub fn get_block_hash_by_tx_hash(&self, tx_hash: &str) -> Result<BlockHash> {
        let tx_raw = self
            .bitcoin_client
            .get_raw_transaction_info(
                &bitcoin::Txid::from_str(tx_hash).map_err(|err| {
                    BridgeSdkError::BtcClientError(format!("Incorrect tx_hash: {err}"))
                })?,
                None,
            )
            .map_err(|err| {
                BridgeSdkError::BtcClientError(format!("Error on get raw tx info: {err}"))
            })?;

        tx_raw
            .blockhash
            .ok_or(BridgeSdkError::BtcClientError("Tx not finalized yet".to_string()))
    }

    pub fn extract_btc_proof(&self, tx_hash: &str) -> Result<TxProof> {
        let block_hash = self.get_block_hash_by_tx_hash(tx_hash)?;
        let block = self
            .bitcoin_client
            .get_block(&block_hash)
            .map_err(|err| BridgeSdkError::BtcClientError(format!("Error on get block: {err}")))?;
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

        let merkle_proof = Self::compute_merkle_proof(&block, tx_index);
        let merkle_proof_str = merkle_proof
            .iter()
            .map(std::string::ToString::to_string)
            .collect();

        let tx_data = serialize(&block.txdata[tx_index]);

        Ok(TxProof {
            tx_bytes: tx_data,
            tx_block_blockhash: tx_block_blockhash.to_string(),
            tx_index: tx_index
                .try_into()
                .expect("Error on convert usize into u64"),
            merkle_proof: merkle_proof_str,
        })
    }

    pub fn get_fee_rate(&self) -> Result<u64> {
        let fee_rate = self
            .bitcoin_client
            .estimate_smart_fee(2, None)
            .map_err(|err| {
                BridgeSdkError::BtcClientError(format!("Error on estimate smart fee: {err}"))
            })?
            .fee_rate
            .ok_or(BridgeSdkError::BtcClientError(
                "Error on estimate fee_rate".to_string(),
            ))?;

        Ok(fee_rate.to_sat())
    }

    pub fn send_tx(&self, tx_bytes: &[u8]) -> Result<String> {
        let tx: Transaction = deserialize(tx_bytes).expect("Failed to deserialize transaction");
        let tx_hash = self
            .bitcoin_client
            .send_raw_transaction(&tx)
            .map_err(|err| {
                BridgeSdkError::BtcClientError(format!("Error on sending BTC transaction: {err}"))
            })?;
        Ok(tx_hash.to_string())
    }

    #[must_use]
    #[allow(dead_code)]
    pub fn compute_merkle_proof(
        block: &bitcoincore_rpc::bitcoin::Block,
        transaction_position: usize,
    ) -> Vec<merkle_tools::H256> {
        let transactions = block
            .txdata
            .iter()
            .map(|tx| tx.compute_txid().to_byte_array().into())
            .collect();

        merkle_tools::merkle_proof_calculator(transactions, transaction_position)
    }
}
