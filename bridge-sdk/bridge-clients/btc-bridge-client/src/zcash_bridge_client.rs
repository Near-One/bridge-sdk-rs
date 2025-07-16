use bitcoin::BlockHash;
use bridge_connector_common::result::{BridgeSdkError, Result};
use reqwest::{header::{HeaderMap, HeaderValue}, Client, ClientBuilder};
use serde_json::{json, Value};
use zebra_rpc::client::BlockObject;
use std::str::FromStr;

#[derive(Debug)]
pub struct TxProof {
    pub tx_bytes: Vec<u8>,
    pub tx_block_blockhash: String,
    pub tx_index: u64,
    pub merkle_proof: Vec<String>,
}

pub struct ZcashBridgeClient {
    endpoint_url: String,
    http_client: Client,
}

impl ZcashBridgeClient {
    pub fn new(zcash_endpoint: String, api_key: Option<&str>) -> Self {
        let mut headers = HeaderMap::new();
        if let Some(key) = api_key {
            headers.insert("x-api-key", HeaderValue::from_str(key).unwrap());
        }
        ZcashBridgeClient { 
            endpoint_url: zcash_endpoint,
            http_client: ClientBuilder::new()
                .default_headers(headers)
                .build()
                .unwrap(),
        }
    }

    pub async fn get_block_hash_by_tx_hash(&self, tx_hash: &str) -> Result<BlockHash> {
        let response = self
            .http_client
            .post(&self.endpoint_url)
            .json(&json!({
                "id": 1,
                "jsonrpc": "2.0",
                "method": "getrawtransaction",
                "params": [tx_hash, 1]
            }))
            .send()
            .await
            .map_err(|e| {
                BridgeSdkError::BtcClientError(format!("Failed to send getrawtransaction request: {e}"))
            })?
            .text()
            .await
            .map_err(|e| {
                BridgeSdkError::BtcClientError(format!("Failed to read getrawtransaction response: {e}"))
            })?;

        let val: Value = serde_json::from_str(&response)?;

        let hash_str = val["result"]["blockhash"].as_str()
            .ok_or_else(|| BridgeSdkError::BtcClientError("Block hash not found in transaction data".to_string()))?;
        
        let receipt = BlockHash::from_str(hash_str).map_err(|e| {
            BridgeSdkError::BtcClientError(format!("Block hash parsing error: {e}"))
        })?;

        Ok(receipt)
    }

    pub async fn extract_btc_proof(&self, tx_hash: &str) -> Result<TxProof> {
        let block_hash = self.get_block_hash_by_tx_hash(tx_hash).await?;

        let response = self
            .http_client
            .post(&self.endpoint_url)
            .json(&json!({
                "id": 1,
                "jsonrpc": "2.0",
                "method": "getblock",
                "params": [block_hash.to_string(), 1]
            }))
            .send()
            .await
            .map_err(|e| BridgeSdkError::BtcClientError(format!("Failed to send getblock request: {e}")))?
            .text()
            .await
            .map_err(|e| BridgeSdkError::BtcClientError(format!("Failed to read getblock response: {e}")))?;

        let value: Value = serde_json::from_str(&response)?;

        let block: BlockObject = serde_json::from_value(value["result"].clone())
            .map_err(|e| BridgeSdkError::BtcClientError(format!("Failed to deserialize block: {e}")))?;

        let tx_block_blockhash = block.hash();

        unimplemented!()
    }

    pub async fn get_fee_rate(&self) -> Result<u64> {
        Ok(1000)
    }

    pub async fn send_tx(&self, tx_bytes: &[u8]) -> Result<String> {
        let tx_hash = self
            .http_client
            .post(&self.endpoint_url)
            .json(&json!({
                "id": 1,
                "jsonrpc": "2.0",
                "method": "sendrawtransaction",
                "params": [tx_bytes]
            }))
            .send()
            .await
            .map_err(|e| {
                BridgeSdkError::BtcClientError(format!("Failed to send transaction: {e}"))
            })?
            .text()
            .await
            .map_err(|e| {
                BridgeSdkError::BtcClientError(format!("Failed to read sendrawtransaction response: {e}"))
            })?;

        Ok(tx_hash.to_string())
    }

    #[must_use]
    #[allow(dead_code)]
    pub fn compute_merkle_proof(
        block: &bitcoincore_rpc::bitcoin::Block,
        transaction_position: usize,
    ) -> Vec<merkle_tools::H256> {
        unimplemented!()
    }
}
