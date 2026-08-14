use bitcoin::BlockHash;
use bitcoincore_rpc::json::EstimateSmartFeeResult;
use bitcoincore_rpc::{bitcoin, jsonrpc::base64};
use reqwest::{
    header::{HeaderMap, HeaderValue},
    Client, ClientBuilder,
};
use serde_json::{json, Value};
use std::{marker::PhantomData, str::FromStr, time::Duration};

use crate::error::UtxoClientError;
use crate::types::{TxOutputView, TxProof, UTXOChain, UTXOChainBlock, UtxoBridgeTransactionData};

pub mod error;
pub mod types;

pub enum AuthOptions {
    None,
    XApiKey(String),
    BasicAuth(String, String),
}

/// How many times a rate-limited RPC request is retried before giving up.
/// A 75s delay outlasts a full per-minute quota window (e.g. Tatum's free
/// tier of 5 requests/minute), so a single retry usually goes through.
const RATE_LIMIT_RETRIES: u32 = 6;
const RATE_LIMIT_RETRY_DELAY: Duration = Duration::from_secs(75);

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

    /// Sends a JSON-RPC request and returns the parsed response body.
    /// Managed RPC providers (e.g. Tatum) throttle with HTTP 429 and a
    /// `{"statusCode": 429, ...}` body that carries no `result` field; such
    /// responses are retried with a delay instead of being misread as a null
    /// result ("transaction not found").
    async fn rpc_call(&self, method: &str, params: Value) -> Result<Value, UtxoClientError> {
        let request_body = json!({
            "id": 1,
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
        });

        let mut attempt = 0;
        loop {
            let response = self
                .http_client
                .post(&self.endpoint_url)
                .json(&request_body)
                .send()
                .await
                .map_err(|e| {
                    UtxoClientError::RpcError(format!("Failed to send {method} request: {e}"))
                })?;

            let status = response.status();
            let response_text = response.text().await.map_err(|e| {
                UtxoClientError::RpcError(format!("Failed to read {method} response: {e}"))
            })?;

            let body = serde_json::from_str::<Value>(&response_text).map_err(|_| {
                UtxoClientError::RpcError(format!(
                    "Failed to parse {method} response. Response: {response_text}"
                ))
            });

            let rate_limited = status == reqwest::StatusCode::TOO_MANY_REQUESTS
                || body
                    .as_ref()
                    .is_ok_and(|body| body["statusCode"].as_u64() == Some(429));
            if !rate_limited {
                return body;
            }
            if attempt >= RATE_LIMIT_RETRIES {
                return Err(UtxoClientError::RpcError(format!(
                    "{method} still rate-limited by the RPC node after {RATE_LIMIT_RETRIES} retries. Response: {response_text}"
                )));
            }
            attempt += 1;
            tracing::warn!(
                "{method} rate-limited by the RPC node, retrying in {}s ({attempt}/{RATE_LIMIT_RETRIES})",
                RATE_LIMIT_RETRY_DELAY.as_secs()
            );
            tokio::time::sleep(RATE_LIMIT_RETRY_DELAY).await;
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
        let response = self
            .rpc_call("getblockheader", json!([block_hash.to_string(), true]))
            .await?;

        let block_height = response["result"]["height"].as_u64().ok_or_else(|| {
            UtxoClientError::RpcError(format!("Block height not found. Response: {response}"))
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

        let response = self
            .rpc_call("getblock", json!([block_hash.to_string(), 0]))
            .await?;

        let result: String = serde_json::from_value(response["result"].clone()).map_err(|e| {
            UtxoClientError::RpcError(format!(
                "Failed to parse getblock result: {e}. Response: {response}"
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

        let response = self.rpc_call("estimatesmartfee", json!([2])).await?;

        let result: EstimateSmartFeeResult = serde_json::from_value(response["result"].clone())
            .map_err(|e| {
                UtxoClientError::RpcError(format!(
                    "Failed to parse estimatesmartfee result: {e}. Response: {response}"
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
        let response = self
            .rpc_call("sendrawtransaction", json!([hex_str]))
            .await?;

        let result: String = serde_json::from_value(response["result"].clone()).map_err(|e| {
            UtxoClientError::RpcError(format!(
                "Failed to parse sendrawtransaction result: {e}. Response: {response}"
            ))
        })?;

        Ok(result)
    }

    pub async fn get_current_height(&self) -> Result<u64, UtxoClientError> {
        let response = self.rpc_call("getblockcount", json!([])).await?;

        let last_block_height = response["result"]
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

        let response = self.rpc_call("getrawtransaction", args).await?;

        if !response["error"].is_null() {
            return Err(UtxoClientError::RpcError(format!(
                "getrawtransaction failed for tx {tx_hash}: {}",
                response["error"]
            )));
        }

        if response["result"].is_null() {
            return Err(UtxoClientError::RpcError(format!(
                "Transaction {tx_hash} not found by the RPC node. Check that the tx hash and RPC endpoint match the expected network, the tx has been broadcast, and the node has txindex enabled."
            )));
        }

        serde_json::from_value(response["result"].clone()).map_err(|e| {
            UtxoClientError::RpcError(format!(
                "Failed to parse getrawtransaction result: {e}. Response: {response}"
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
