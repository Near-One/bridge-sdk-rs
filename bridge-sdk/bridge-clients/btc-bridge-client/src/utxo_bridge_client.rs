use bitcoin::{
    consensus::{encode, serialize}, hex::FromHex, BlockHash
};
use bitcoincore_rpc::bitcoin;
use bitcoincore_rpc::bitcoin::hashes::Hash;
use bitcoincore_rpc::json::EstimateSmartFeeResult;
use bridge_connector_common::result::{BridgeSdkError, Result};
use merkle_tools::H256;
use reqwest::{
    header::{HeaderMap, HeaderValue},
    Client, ClientBuilder,
};
use serde_json::{json, Value};
use zebra_rpc::client::zebra_chain;
use zebra_chain::serialization::{ZcashDeserialize, ZcashSerialize};
use std::str::FromStr;

#[derive(Debug)]
pub struct TxProof {
    pub tx_bytes: Vec<u8>,
    pub tx_block_blockhash: String,
    pub tx_index: u64,
    pub merkle_proof: Vec<String>,
}

#[allow(dead_code)]
#[derive(serde::Deserialize, Debug)]
struct JsonRpcResponse<T> {
    jsonrpc: String,
    id: u64,
    result: T,
}

pub struct UTXOBridgeClient {
    endpoint_url: String,
    http_client: Client,
    // TODO: Change to ChainKind
    is_zcash: bool,
}

impl UTXOBridgeClient {
    pub fn new(rpc_endpoint: String, api_key: Option<&str>, is_zcash: bool) -> Self {
        let mut headers = HeaderMap::new();
        if let Some(key) = api_key {
            headers.insert("x-api-key", HeaderValue::from_str(key).unwrap());
        }

        UTXOBridgeClient {
            endpoint_url: rpc_endpoint,
            http_client: ClientBuilder::new()
                .default_headers(headers)
                .build()
                .unwrap(),
            is_zcash,
        }
    }

    pub async fn get_block_hash_by_tx_hash(&self, tx_hash: &str) -> Result<BlockHash> {
        let args = if self.is_zcash {
            json!([tx_hash, 1])
        } else {
            json!([tx_hash, true])
        };

        let response: JsonRpcResponse<Value> = self
            .http_client
            .post(&self.endpoint_url)
            .json(&json!({
                "id": 1,
                "jsonrpc": "2.0",
                "method": "getrawtransaction",
                "params": args
            }))
            .send()
            .await
            .map_err(|e| {
                BridgeSdkError::BtcClientError(format!(
                    "Failed to send getrawtransaction request: {e}"
                ))
            })?
            .json()
            .await
            .map_err(|e| {
                BridgeSdkError::BtcClientError(format!(
                    "Failed to read getrawtransaction response: {e}"
                ))
            })?;

        let hash_str = response.result["blockhash"].as_str().ok_or_else(|| {
            BridgeSdkError::BtcClientError("Block hash not found in transaction data".to_string())
        })?;

        let receipt = BlockHash::from_str(hash_str).map_err(|e| {
            BridgeSdkError::BtcClientError(format!("Block hash parsing error: {e}"))
        })?;

        Ok(receipt)
    }

    pub async fn extract_btc_proof(&self, tx_hash: &str) -> Result<TxProof> {
        let block_hash = self.get_block_hash_by_tx_hash(tx_hash).await?;

        let response: JsonRpcResponse<String> = self
            .http_client
            .post(&self.endpoint_url)
            .json(&json!({
                "id": 1,
                "jsonrpc": "2.0",
                "method": "getblock",
                "params": [block_hash.to_string(), 0],
            }))
            .send()
            .await
            .map_err(|e| {
                BridgeSdkError::BtcClientError(format!("Failed to send getblock request: {e}"))
            })?
            .json()
            .await
            .map_err(|e| {
                BridgeSdkError::BtcClientError(format!("Failed to read getblock response: {e}"))
            })?;

        if self.is_zcash {
            let bytes = Vec::from_hex(&response.result).expect("Invalid hex");
            let mut cursor = std::io::Cursor::new(bytes);
            let block = zebra_chain::block::Block::zcash_deserialize(&mut cursor)
                .expect("Deserialization failed");

            let tx_block_blockhash = block.header.hash();

            let transactions = block
                .transactions
                .iter()
                .map(|tx| tx.hash().0.into())
                .collect::<Vec<H256>>();

            let tx_index = transactions
                .iter()
                .position(|hash| hash.to_string() == tx_hash)
                .ok_or(BridgeSdkError::InvalidArgument(
                    "btc tx not found in block".to_string(),
                ))?;

            let merkle_proof = merkle_tools::merkle_proof_calculator(transactions, tx_index);

            let merkle_proof_str = merkle_proof
                .iter()
                .map(std::string::ToString::to_string)
                .collect();
            
            let mut tx_data = Vec::new();
            block.transactions[tx_index]
                .zcash_serialize(&mut tx_data)
                .expect("Serialization failed");

            Ok(TxProof {
                tx_bytes: tx_data,
                tx_block_blockhash: tx_block_blockhash.to_string(),
                tx_index: tx_index
                    .try_into()
                    .expect("Error on convert usize into u64"),
                merkle_proof: merkle_proof_str,
            })
        } else {
            let block: bitcoin::Block = encode::deserialize_hex(&response.result).map_err(|e| {
                BridgeSdkError::BtcClientError(format!("Failed to parse block: {e}"))
            })?;

            let tx_block_blockhash = block.header.block_hash();

            let transactions = block
                .txdata
                .iter()
                .map(|tx| tx.compute_txid().to_byte_array().into())
                .collect::<Vec<H256>>();

            let tx_index = transactions
                .iter()
                .position(|hash| hash.to_string() == tx_hash)
                .ok_or(BridgeSdkError::InvalidArgument(
                    "btc tx not found in block".to_string(),
                ))?;

            let merkle_proof = merkle_tools::merkle_proof_calculator(transactions, tx_index);
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
    }

    pub async fn get_fee_rate(&self) -> Result<u64> {
        if self.is_zcash {
            return Ok(1000);
        }

        let response: JsonRpcResponse<Value> = self
            .http_client
            .post(&self.endpoint_url)
            .json(&json!({
                "id": 1,
                "jsonrpc": "2.0",
                "method": "estimatesmartfee",
                "params": [2]
            }))
            .send()
            .await
            .map_err(|e| {
                BridgeSdkError::BtcClientError(format!(
                    "Faield to send estimatesmartfee request: {e}"
                ))
            })?
            .json()
            .await
            .map_err(|e| {
                BridgeSdkError::BtcClientError(format!(
                    "Failed to read estimatesmartfee response: {e}"
                ))
            })?;

        let result: EstimateSmartFeeResult = serde_json::from_value(response.result)
            .map_err(|e| BridgeSdkError::BtcClientError(format!("Failed to parse block: {e}")))?;

        Ok(result
            .fee_rate
            .ok_or(BridgeSdkError::BtcClientError(
                "Failed to estimate fee_rate".to_string(),
            ))?
            .to_sat())
    }

    pub async fn send_tx(&self, tx_bytes: &[u8]) -> Result<String> {
        let response: JsonRpcResponse<String> = self
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
            .json()
            .await
            .map_err(|e| {
                BridgeSdkError::BtcClientError(format!(
                    "Failed to read sendrawtransaction response: {e}"
                ))
            })?;

        Ok(response.result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_get_fee_rate() {
        let client = UTXOBridgeClient::new(
            "https://zcash-testnet.gateway.tatum.io/".to_string(),
            "t-682d8651b332cd4387ac0270-9c4b05ca2c0d4456a1dcd5ea".into(),
            true,
        );

        let proof = client
            .extract_btc_proof("e54da658a61074eb36ac8c9353da3348f899e9c012fd3ba11f22dca30ce9cf11")
            .await
            .unwrap();
        println!("Proof: {:?}", proof);
        // let fee = client.get_fee_rate().await.unwrap();
        // println!("Fee rate: {}", fee);
    }
}
