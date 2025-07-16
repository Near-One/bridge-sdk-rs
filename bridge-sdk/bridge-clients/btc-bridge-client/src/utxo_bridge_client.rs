use std::{future::Future, str::FromStr};

use bitcoin::BlockHash;
use reqwest::{header::{HeaderMap, HeaderValue}, Client, ClientBuilder, RequestBuilder};
use bridge_connector_common::result::{BridgeSdkError, Result};
use serde_json::{json, Value};

use crate::btc_bridge_client::TxProof;

pub mod btc_bridge_client;
pub mod zcash_bridge_client;

pub trait UTXOBridgeClient {
    fn new(rpc_endpoint: String, api_key: Option<&str>) -> Self;
    fn http_post(&self) -> RequestBuilder;
    fn build_client(api_key: Option<&str>) -> Client {
        let mut headers = HeaderMap::new();
        if let Some(key) = api_key {
            headers.insert("x-api-key", HeaderValue::from_str(key).unwrap());
        }
        ClientBuilder::new()
            .default_headers(headers)
            .build()
            .unwrap()
    }

    fn get_block_hash_by_tx_hash(&self, tx_hash: &str) -> impl Future<Output = Result<BlockHash>> + Send where Self: Sync {
        async move {
            let response = self
                .http_post()
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
    }

    fn extract_btc_proof(&self, tx_hash: &str) -> impl Future<Output = Result<TxProof>> + Send;
    fn get_fee_rate(&self) -> impl Future<Output = Result<u64>> + Send;

    fn send_tx(&self, tx_bytes: &[u8]) -> impl Future<Output = Result<String>> + Send where Self: Sync {
        async move {
            let tx_hash = self
                .http_post()
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
    }
}