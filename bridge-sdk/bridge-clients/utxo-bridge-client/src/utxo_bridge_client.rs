use bitcoin::BlockHash;
use bitcoincore_rpc::json::EstimateSmartFeeResult;
use bitcoincore_rpc::{bitcoin, jsonrpc::base64};
use reqwest::{
    header::{HeaderMap, HeaderValue},
    Client, ClientBuilder,
};
use serde_json::{json, Value};
use std::{marker::PhantomData, str::FromStr};

use crate::error::UtxoClientError;
use crate::types::{TxOutputView, TxProof, UTXOChain, UTXOChainBlock, UtxoBridgeTransactionData};

pub mod error;
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

    pub async fn get_block_hash_by_tx_hash(
        &self,
        tx_hash: &str,
    ) -> Result<BlockHash, UtxoClientError> {
        let raw_tx = self.get_raw_transaction(tx_hash).await?;
        parse_block_hash(&raw_tx)
    }

    pub async fn get_block_height_by_block_hash(
        &self,
        block_hash: &str,
    ) -> Result<u64, UtxoClientError> {
        let response_text = self
            .http_client
            .post(&self.endpoint_url)
            .json(&json!({
                "id": 1,
                "jsonrpc": "2.0",
                "method": "getblockheader",
                "params": [block_hash.to_string(), true],
            }))
            .send()
            .await
            .map_err(|e| {
                UtxoClientError::RpcError(format!("Failed to send getblock request: {e}"))
            })?
            .text()
            .await
            .map_err(|e| {
                UtxoClientError::RpcError(format!("Failed to read getblock response: {e}"))
            })?;

        let response = serde_json::from_str::<Value>(&response_text).map_err(|_| {
            UtxoClientError::RpcError(format!(
                "Failed to send getblock. Response: {response_text}"
            ))
        })?;

        let result: Value = serde_json::from_value(response["result"].clone()).map_err(|e| {
            UtxoClientError::RpcError(format!(
                "Failed to parse send getblock result: {e}. Response: {response_text}"
            ))
        })?;

        let block_height = result["height"].as_u64().ok_or_else(|| {
            UtxoClientError::RpcError(format!("Block height not found. Response: {response_text}"))
        })?;

        Ok(block_height)
    }

    pub async fn get_bridge_transaction_data(
        &self,
        tx_hash: &str,
        deposit_address: &str,
    ) -> Result<UtxoBridgeTransactionData, UtxoClientError> {
        let result = self.get_raw_transaction(tx_hash).await?;

        let vout = result["vout"].as_array().ok_or_else(|| {
            UtxoClientError::RpcError(format!(
                "vout not found in transaction data. Data: {result}",
            ))
        })?;

        let (output_index, output) = vout
            .iter()
            .enumerate()
            .find(|(_, output)| {
                output["scriptPubKey"]["address"]
                    .as_str()
                    .is_some_and(|addr| addr == deposit_address)
            })
            .ok_or_else(|| {
                UtxoClientError::RpcError(format!(
                    "No output found for deposit_address: {deposit_address}",
                ))
            })?;

        let amount_btc = output["value"].as_f64().ok_or_else(|| {
            UtxoClientError::RpcError(format!(
                "Amount not found in output. Transaction data: {result}",
            ))
        })?;
        let amount = bitcoin::Amount::from_btc(amount_btc)
            .map_err(|e| {
                UtxoClientError::RpcError(format!(
                    "Invalid output value {amount_btc}: {e}. Transaction data: {result}"
                ))
            })?
            .to_sat();

        let vout: u32 = output_index.try_into().map_err(|_| {
            UtxoClientError::RpcError(format!("Output index too large: {output_index}"))
        })?;

        Ok(UtxoBridgeTransactionData {
            deposit_address: deposit_address.to_string(),
            amount,
            tx_hash: tx_hash.to_string(),
            vout,
        })
    }

    pub async fn extract_btc_proof(&self, tx_hash: &str) -> Result<TxProof, UtxoClientError> {
        let raw_tx = self.get_raw_transaction(tx_hash).await?;
        let block_hash = parse_block_hash(&raw_tx)?;
        let outputs = parse_outputs(&raw_tx)?;
        let block_height = self
            .get_block_height_by_block_hash(&block_hash.to_string())
            .await?;

        let response_text = self
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
                UtxoClientError::RpcError(format!("Failed to send getblock request: {e}"))
            })?
            .text()
            .await
            .map_err(|e| {
                UtxoClientError::RpcError(format!("Failed to read getblock response: {e}"))
            })?;

        let response = serde_json::from_str::<Value>(&response_text).map_err(|_| {
            UtxoClientError::RpcError(format!(
                "Failed to read getblock. Response: {response_text}"
            ))
        })?;

        let result: String = serde_json::from_value(response["result"].clone()).map_err(|e| {
            UtxoClientError::RpcError(format!(
                "Failed to parse read getblock result: {e}. Response: {response_text}"
            ))
        })?;

        let block = T::Block::from_str(&result)?;
        let transactions = block.transactions();

        let tx_index = transactions
            .iter()
            .position(|hash| hash.to_string() == tx_hash)
            .ok_or(UtxoClientError::Other(
                "btc tx not found in block".to_string(),
            ))?;

        let merkle_proof = merkle_tools::merkle_proof_calculator(transactions.clone(), tx_index);
        let merkle_proof_str = merkle_proof
            .iter()
            .map(std::string::ToString::to_string)
            .collect();

        let coinbase_tx_id = transactions[0].to_string();
        let coinbase_merkle_proof = merkle_tools::merkle_proof_calculator(transactions, 0);
        let coinbase_merkle_proof_str = coinbase_merkle_proof
            .iter()
            .map(std::string::ToString::to_string)
            .collect();

        Ok(TxProof {
            block_height,
            tx_bytes: block.tx_data(tx_index),
            tx_block_blockhash: block.hash(),
            tx_index: tx_index
                .try_into()
                .expect("Error on convert usize into u64"),
            merkle_proof: merkle_proof_str,
            coinbase_tx_id,
            coinbase_merkle_proof: coinbase_merkle_proof_str,
            outputs,
        })
    }

    pub async fn get_fee_rate(&self) -> Result<u64, UtxoClientError> {
        if T::is_zcash() {
            return Ok(1000);
        }

        let response_text = self
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
                UtxoClientError::RpcError(format!("Failed to send estimatesmartfee request: {e}"))
            })?
            .text()
            .await
            .map_err(|e| {
                UtxoClientError::RpcError(format!("Failed to read estimatesmartfee response: {e}"))
            })?;

        let response = serde_json::from_str::<Value>(&response_text).map_err(|_| {
            UtxoClientError::RpcError(format!(
                "Failed to read estimatesmartfee. Response: {response_text}"
            ))
        })?;

        let result: EstimateSmartFeeResult = serde_json::from_value(response["result"].clone())
            .map_err(|e| {
                UtxoClientError::RpcError(format!(
                    "Failed to parse estimatesmartfee result: {e}. Response: {response_text}"
                ))
            })?;

        Ok(result
            .fee_rate
            .ok_or(UtxoClientError::RpcError(format!(
                "Failed to estimate fee_rate: {:?}",
                result.errors
            )))?
            .to_sat())
    }

    pub async fn send_tx(&self, tx_bytes: &[u8]) -> Result<String, UtxoClientError> {
        let hex_str = hex::encode(tx_bytes);
        let response_text = self
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
            .map_err(|e| UtxoClientError::RpcError(format!("Failed to send transaction: {e}")))?
            .text()
            .await
            .map_err(|e| {
                UtxoClientError::RpcError(format!(
                    "Failed to read sendrawtransaction response: {e}"
                ))
            })?;

        let response = serde_json::from_str::<Value>(&response_text).map_err(|_| {
            UtxoClientError::RpcError(format!(
                "Failed to read sendrawtransaction. Response: {response_text}"
            ))
        })?;

        let result: String = serde_json::from_value(response["result"].clone()).map_err(|e| {
            UtxoClientError::RpcError(format!(
                "Failed to parse sendrawtransaction result: {e}. Response: {response_text}"
            ))
        })?;

        Ok(result)
    }

    pub async fn get_current_height(&self) -> Result<u64, UtxoClientError> {
        let count_response: JsonRpcResponse<Value> = self
            .http_client
            .post(&self.endpoint_url)
            .json(&json!({
                "id": 1,
                "jsonrpc": "2.0",

                        "method": "getblockcount",
                "params": []
            }))
            .send()
            .await
            .map_err(|e| UtxoClientError::RpcError(format!("Failed to send getblockcount: {e}")))?
            .json()
            .await
            .map_err(|e| UtxoClientError::Other(format!("Failed to parse getblockcount: {e}")))?;

        let last_block_height = count_response
            .result
            .as_u64()
            .ok_or_else(|| UtxoClientError::Other("Invalid getblockcount result".to_string()))?;

        Ok(last_block_height)
    }
    async fn get_raw_transaction(&self, tx_hash: &str) -> Result<Value, UtxoClientError> {
        let args = if T::is_zcash() {
            json!([tx_hash, 1])
        } else {
            json!([tx_hash, true])
        };

        let response_text = self
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
                UtxoClientError::RpcError(format!("Failed to send getrawtransaction request: {e}"))
            })?
            .text()
            .await
            .map_err(|e| {
                UtxoClientError::RpcError(format!("Failed to read getrawtransaction response: {e}"))
            })?;

        let response = serde_json::from_str::<Value>(&response_text).map_err(|_| {
            UtxoClientError::RpcError(format!(
                "Failed to read getrawtransaction. Response: {response_text}"
            ))
        })?;

        serde_json::from_value(response["result"].clone()).map_err(|e| {
            UtxoClientError::RpcError(format!(
                "Failed to parse getrawtransaction result: {e}. Response: {response_text}"
            ))
        })
    }
}

fn parse_block_hash(raw_tx: &Value) -> Result<BlockHash, UtxoClientError> {
    let hash_str = raw_tx["blockhash"].as_str().ok_or_else(|| {
        UtxoClientError::RpcError(format!(
            "Block hash not found in transaction data. Data: {raw_tx}",
        ))
    })?;

    BlockHash::from_str(hash_str).map_err(|e| {
        UtxoClientError::RpcError(format!("Block hash parsing error: {e}. Data: {raw_tx}",))
    })
}

/// Build a chain-agnostic view of a transaction's transparent outputs from
/// the verbose `getrawtransaction` JSON. Reading from the JSON (rather than
/// re-deserializing `tx_bytes`) is the only practical path that works for
/// both Bitcoin and Zcash, whose whole-tx serializations are incompatible.
fn parse_outputs(raw_tx: &Value) -> Result<Vec<TxOutputView>, UtxoClientError> {
    let vout = raw_tx["vout"].as_array().ok_or_else(|| {
        UtxoClientError::RpcError(format!(
            "vout not found in transaction data. Data: {raw_tx}"
        ))
    })?;

    vout.iter()
        .enumerate()
        .map(|(i, out)| {
            let value_btc = out["value"].as_f64().ok_or_else(|| {
                UtxoClientError::RpcError(format!(
                    "vout[{i}] has no value. Transaction data: {raw_tx}"
                ))
            })?;
            // `bitcoin::Amount::from_btc` does the f64 → sat conversion with
            // a round-to-nearest step (avoiding the `(0.07 * 1e8) as u64 ==
            // 6_999_999` off-by-one) and rejects negative / NaN / over-supply
            // inputs. f64 mantissa precision is still the ceiling — values
            // with more than ~15 significant decimal digits may still drop a
            // sat — but BTC/ZEC RPC amounts are well under that bound.
            let value_sat = bitcoin::Amount::from_btc(value_btc)
                .map_err(|e| {
                    UtxoClientError::RpcError(format!(
                        "vout[{i}] has invalid value {value_btc}: {e}. Transaction data: {raw_tx}"
                    ))
                })?
                .to_sat();

            let script_hex = out["scriptPubKey"]["hex"].as_str().ok_or_else(|| {
                UtxoClientError::RpcError(format!(
                    "vout[{i}] missing scriptPubKey.hex. Transaction data: {raw_tx}"
                ))
            })?;
            let script_pubkey = hex::decode(script_hex).map_err(|e| {
                UtxoClientError::RpcError(format!(
                    "vout[{i}] has invalid scriptPubKey.hex: {e}. Transaction data: {raw_tx}"
                ))
            })?;

            Ok(TxOutputView {
                value_sat,
                script_pubkey,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_outputs_bitcoin_style() {
        // Shape returned by bitcoind getrawtransaction verbose=true.
        let raw = serde_json::json!({
            "vout": [
                {
                    "value": 0.001,
                    "n": 0,
                    "scriptPubKey": {
                        "hex": "76a91489abcdefabbaabbaabbaabbaabbaabbaabbaabba88ac",
                        "type": "pubkeyhash"
                    }
                },
                {
                    "value": 0.5,
                    "n": 1,
                    "scriptPubKey": {
                        "hex": "0014751e76e8199196d454941c45d1b3a323f1433bd6",
                        "type": "witness_v0_keyhash"
                    }
                }
            ]
        });

        let outs = parse_outputs(&raw).unwrap();
        assert_eq!(outs.len(), 2);
        assert_eq!(outs[0].value_sat, 100_000);
        assert_eq!(
            outs[0].script_pubkey,
            hex::decode("76a91489abcdefabbaabbaabbaabbaabbaabbaabbaabba88ac").unwrap()
        );
        assert_eq!(outs[1].value_sat, 50_000_000);
    }

    #[test]
    fn parse_outputs_zcash_style() {
        // Shape returned by zcashd / zebrad getrawtransaction verbose=1: same
        // schema for the transparent vout we care about.
        let raw = serde_json::json!({
            "vout": [
                {
                    "value": 0.00001,
                    "n": 0,
                    "scriptPubKey": {
                        "hex": "76a914a0b0c0d0e0f000112233445566778899aabbccdd88ac",
                        "type": "pubkeyhash",
                        "addresses": ["t1abcdef"]
                    }
                }
            ]
        });

        let outs = parse_outputs(&raw).unwrap();
        assert_eq!(outs.len(), 1);
        assert_eq!(outs[0].value_sat, 1000);
        assert_eq!(outs[0].script_pubkey.len(), 25);
    }

    #[test]
    fn parse_outputs_handles_float_precision_landmine() {
        // 0.07_f64 * 1e8 == 6_999_999.999_999_998 in IEEE-754. A naive
        // `(value * 1e8) as u64` truncates to 6_999_999; `Amount::from_btc`
        // rounds to nearest and returns 7_000_000.
        let raw = serde_json::json!({
            "vout": [{
                "value": 0.07,
                "scriptPubKey": {"hex": "00"}
            }]
        });
        let outs = parse_outputs(&raw).unwrap();
        assert_eq!(outs[0].value_sat, 7_000_000);
    }

    #[test]
    fn parse_outputs_rejects_negative_value() {
        let raw = serde_json::json!({
            "vout": [{
                "value": -0.5,
                "scriptPubKey": {"hex": "00"}
            }]
        });
        assert!(parse_outputs(&raw).is_err());
    }

    #[test]
    fn parse_outputs_rejects_missing_vout() {
        let raw = serde_json::json!({});
        assert!(parse_outputs(&raw).is_err());
    }

    #[test]
    fn parse_outputs_rejects_missing_script_hex() {
        let raw = serde_json::json!({
            "vout": [{"value": 0.1, "scriptPubKey": {}}]
        });
        assert!(parse_outputs(&raw).is_err());
    }

    #[test]
    fn parse_outputs_rejects_invalid_script_hex() {
        let raw = serde_json::json!({
            "vout": [{"value": 0.1, "scriptPubKey": {"hex": "not-hex"}}]
        });
        assert!(parse_outputs(&raw).is_err());
    }
}
