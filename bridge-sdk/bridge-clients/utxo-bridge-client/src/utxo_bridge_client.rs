use bitcoin::BlockHash;
use bitcoincore_rpc::json::EstimateSmartFeeResult;
use bitcoincore_rpc::{bitcoin, jsonrpc::base64};
use bridge_connector_common::result::{BridgeSdkError, Result};
use reqwest::{
    header::{HeaderMap, HeaderValue},
    Client, ClientBuilder,
};
use serde_json::{json, Value};
use std::{marker::PhantomData, str::FromStr};

use crate::types::{TxProof, UTXOChain, UTXOChainBlock};

pub mod types;

pub enum AuthOptions {
    None,
    XApiKey(String),
    BasicAuth(String, String),
}

#[allow(dead_code)]
#[derive(serde::Deserialize, Debug)]
struct JsonRpcResponse<T> {
    jsonrpc: String,
    id: u64,
    result: T,
}

pub struct UTXOBridgeClient<T: UTXOChain> {
    endpoint_url: String,
    http_client: Client,
    _phantom: PhantomData<T>,
}

impl<T: UTXOChain> UTXOBridgeClient<T> {
    pub fn new(rpc_endpoint: String, auth: AuthOptions) -> Self {
        let mut headers = HeaderMap::new();

        match auth {
            AuthOptions::None => {}
            AuthOptions::XApiKey(api_key) => {
                headers.insert("x-api-key", HeaderValue::from_str(&api_key).unwrap());
            }
            AuthOptions::BasicAuth(username, password) => {
                let auth_value =
                    format!("Basic {}", base64::encode(format!("{username}:{password}")));
                headers.insert("Authorization", HeaderValue::from_str(&auth_value).unwrap());
            }
        }

        UTXOBridgeClient::<T> {
            endpoint_url: rpc_endpoint,
            http_client: ClientBuilder::new()
                .default_headers(headers)
                .build()
                .unwrap(),
            _phantom: PhantomData,
        }
    }

    pub async fn get_block_hash_by_tx_hash(&self, tx_hash: &str) -> Result<BlockHash> {
        let args = if T::is_zcash() {
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

        let block = T::Block::from_str(&response.result)?;
        let transactions = block.transactions();

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

        Ok(TxProof {
            tx_bytes: block.tx_data(tx_index),
            tx_block_blockhash: block.hash(),
            tx_index: tx_index
                .try_into()
                .expect("Error on convert usize into u64"),
            merkle_proof: merkle_proof_str,
        })
    }

    pub async fn get_fee_rate(&self) -> Result<u64> {
        if T::is_zcash() {
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
        let hex_str = hex::encode(tx_bytes);
        let response_tmp = self
            .http_client
            .post(&self.endpoint_url)
            .json(&json!({
                "id": 1,
                "jsonrpc": "2.0",
                "method": "sendrawtransaction",
                "params": [hex_str]
            }))
            .send()
            .await
            .map_err(|e| BridgeSdkError::BtcClientError(format!("Failed to send transaction: {e}")))
            .unwrap();

        let response_txt = response_tmp.text().await.unwrap();

        println!("Response: {:?}", response_txt);
        Ok(response_txt)

        /*let response: JsonRpcResponse<bitcoin::Txid> = response_tmp
            .json()
            .await
            .map_err(|e| {
                BridgeSdkError::BtcClientError(format!(
                    "Failed to read sendrawtransaction response: {e}"
                ))
            })
            .unwrap();

        Ok(response.result.to_string())*/
    }

    pub async fn get_tree_state(&self, current_h: u64) -> String {
        /*let response_tmp = self
            .http_client
            .post(&self.endpoint_url)
            .json(&json!({
                "id": "curltest",
                "jsonrpc": "1.0",
                "method": "z_gettreestate",
                "params": [current_h]
            }))
            .send()
            .await
            .map_err(|e| BridgeSdkError::BtcClientError(format!("Failed to send transaction: {e}")))
            .unwrap();

        let response_txt = response_tmp.text().await.unwrap();

        println!("Response: {:?}", response_txt);*/

        //grpcurl -insecure \
        //   -d '{"height": 3420618}' \
        //   lightwalletd.testnet.electriccoin.co:9067 \
        //   cash.z.wallet.sdk.rpc.CompactTxStreamer/GetTreeState

        //grpcurl -insecure -d '{"height": 3723909}' testnet.zec.rocks:443 cash.z.wallet.sdk.rpc.CompactTxStreamer/GetTreeState
        "01353e6d0c0533b23256bee162aff079bd852e6ba72e771c989d8d1f3199e45d0b01ec3de1b5252483bd1b44b969fb32e1275cef86cba8deb3242f68680909d925261f00000000017440d32c765f6564ea7b2de261d348ce90820f530d19c950bd301b7f6891d9000140a6298ea2d7f93eca65a638652c90d4448399f04937e2b8809ef6636860f92500000000000155e51aaff7e2c8958c6ac42f78bf8b1004f2dbe1fe0b0576734374f79677d926000143275cd7061891f321cdeaebcb38811ed37d02d490e475ddcd9c3b6e6f721003017f93215cf466b333690a951c86254d6729672189dc06160f378267efb70b580a0125934a8c8cde7b4ba7e51d78f2321c7e286d140811a192f692f29d3f0ecce510000000000000000000000000000000".to_string()
    }
}
