use bitcoin::consensus::serialize;
use bitcoincore_rpc::bitcoin::hashes::Hash;
use bitcoincore_rpc::json::EstimateSmartFeeResult;
use bitcoincore_rpc::bitcoin;
use bridge_connector_common::result::{BridgeSdkError, Result};
use reqwest::Client;
use serde_json::{json, Value};

use crate::UTXOBridgeClient;

#[derive(Debug)]
pub struct TxProof {
    pub tx_bytes: Vec<u8>,
    pub tx_block_blockhash: String,
    pub tx_index: u64,
    pub merkle_proof: Vec<String>,
}

pub struct BtcBridgeClient {
    endpoint_url: String,
    http_client: Client,
}

impl BtcBridgeClient {
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

impl UTXOBridgeClient for BtcBridgeClient {
    fn new(btc_endpoint: String, api_key: Option<&str>) -> Self {
        BtcBridgeClient {
            endpoint_url: btc_endpoint,
            http_client: Self::build_client(api_key),
        }
    }

    fn http_post(&self) -> reqwest::RequestBuilder {
        self.http_client.post(&self.endpoint_url)
            .header("Content-Type", "application/json")
    }

    async fn extract_btc_proof(&self, tx_hash: &str) -> Result<TxProof> {
        let block_hash = self.get_block_hash_by_tx_hash(tx_hash).await?;
        let response = self
            .http_post()
            .json(&json!({
                "id": 1,
                "jsonrpc": "2.0",
                "method": "getblock",
                "params": [block_hash.to_string(), 2],
            }))
            .send()
            .await
            .map_err(|e| {
                BridgeSdkError::BtcClientError(format!("Failed to send getblock request: {e}"))
            })?
            .text()
            .await
            .map_err(|e| {
                BridgeSdkError::BtcClientError(format!("Failed to read getblock response: {e}"))
            })?;

        let value: Value = serde_json::from_str(&response)?;
        let block: bitcoin::Block = serde_json::from_value(value["result"].clone())
            .map_err(|e| BridgeSdkError::BtcClientError(format!("Failed to parse block: {e}")))?;

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

    async fn get_fee_rate(&self) -> Result<u64> {
        let response = self
            .http_post()
            .json(&json!({
                "id": 1,
                "jsonrpc": "2.0",
                "method": "estimatesmartfee",
                "params": [2]
            }))
            .send()
            .await
            .map_err(|e| {
                BridgeSdkError::BtcClientError(format!("Faield to send estimatesmartfee request: {e}"))
            })?
            .text()
            .await
            .map_err(|e| {
                BridgeSdkError::BtcClientError(format!("Failed to read estimatesmartfee response: {e}"))
            })?;

        println!("Response: {response}");

        let value: Value = serde_json::from_str(&response)?;
        let result: EstimateSmartFeeResult = serde_json::from_value(value["result"].clone())
            .map_err(|e| BridgeSdkError::BtcClientError(format!("Failed to parse block: {e}")))?;

        Ok(result.fee_rate.ok_or(BridgeSdkError::BtcClientError(
            "Failed to estimate fee_rate".to_string(),
        ))?.to_sat())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_fee_rate() {
        let client = BtcBridgeClient {
            endpoint_url: "https://bitcoin-testnet.gateway.tatum.io/".to_string(),
            http_client: BtcBridgeClient::build_client(Some("t-682d8651b332cd4387ac0270-9c4b05ca2c0d4456a1dcd5ea")),
        };

        let fee_rate = client.get_fee_rate().await.unwrap();
        assert!(fee_rate > 0, "Fee rate should be greater than zero");
    }
}