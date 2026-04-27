use async_trait::async_trait;
use reqwest::{Client, Url};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::Value;
use starknet::providers::{
    jsonrpc::{HttpTransportError, JsonRpcError, JsonRpcMethod, JsonRpcResponse, JsonRpcTransport},
    ProviderRequestData,
};

/// HTTP transport that serializes params as a positional array and tolerates
/// id-less error bodies. Required for gateways (e.g. Infura) that only accept
/// by-position JSON-RPC params and omit `id` on bad-request errors.
#[derive(Debug, Clone)]
pub struct PositionalHttpTransport {
    client: Client,
    url: Url,
}

impl PositionalHttpTransport {
    pub fn new(url: impl Into<Url>) -> Self {
        Self {
            client: Client::new(),
            url: url.into(),
        }
    }
}

#[derive(Serialize)]
struct PositionalRequest {
    id: u64,
    jsonrpc: &'static str,
    method: JsonRpcMethod,
    params: Value,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum LooseResponse<T> {
    Success {
        #[serde(default)]
        id: Option<u64>,
        result: T,
    },
    Error {
        #[serde(default)]
        id: Option<u64>,
        error: LooseError,
    },
}

#[derive(Deserialize)]
struct LooseError {
    code: i64,
    message: String,
    #[serde(default)]
    data: Option<Value>,
}

// Normalize params to a positional array.
// - Arrays pass through (some requests, e.g. BlockNumberRequest, already serialize positionally).
// - Objects are flipped values-only (for single-named-parameter methods used here).
// - Null becomes `[]` (no-argument methods).
// - Any other scalar is wrapped in a 1-element array.
//
// Multi-field by-name params would alphabetize via serde_json::Map — not a concern
// for the methods used by this bridge client (at most one named parameter).
fn to_positional<P: Serialize>(params: P) -> Result<Value, serde_json::Error> {
    match serde_json::to_value(params)? {
        Value::Array(a) => Ok(Value::Array(a)),
        Value::Object(map) => Ok(Value::Array(map.into_values().collect())),
        Value::Null => Ok(Value::Array(vec![])),
        other => Ok(Value::Array(vec![other])),
    }
}

#[async_trait]
impl JsonRpcTransport for PositionalHttpTransport {
    type Error = HttpTransportError;

    async fn send_request<P, R>(
        &self,
        method: JsonRpcMethod,
        params: P,
    ) -> Result<JsonRpcResponse<R>, Self::Error>
    where
        P: Serialize + Send + Sync,
        R: DeserializeOwned + Send,
    {
        let params = to_positional(params).map_err(HttpTransportError::Json)?;
        let body = serde_json::to_string(&PositionalRequest {
            id: 1,
            jsonrpc: "2.0",
            method,
            params,
        })
        .map_err(HttpTransportError::Json)?;

        tracing::trace!("Sending request via JSON-RPC (positional): {body}");

        let text = self
            .client
            .post(self.url.clone())
            .header("Content-Type", "application/json")
            .body(body)
            .send()
            .await
            .map_err(HttpTransportError::Reqwest)?
            .text()
            .await
            .map_err(HttpTransportError::Reqwest)?;

        tracing::trace!("Response from JSON-RPC: {text}");

        let loose: LooseResponse<R> =
            serde_json::from_str(&text).map_err(HttpTransportError::Json)?;

        Ok(match loose {
            LooseResponse::Success { id, result } => JsonRpcResponse::Success {
                id: id.unwrap_or(1),
                result,
            },
            LooseResponse::Error { id, error } => JsonRpcResponse::Error {
                id: id.unwrap_or(1),
                error: JsonRpcError {
                    code: error.code,
                    message: error.message,
                    data: error.data,
                },
            },
        })
    }

    async fn send_requests<R>(
        &self,
        _requests: R,
    ) -> Result<Vec<JsonRpcResponse<Value>>, Self::Error>
    where
        R: AsRef<[ProviderRequestData]> + Send + Sync,
    {
        unimplemented!("batch JSON-RPC is not used by the starknet bridge client")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use starknet::{
        core::types::{BlockId, BlockTag, Felt, FunctionCall},
        macros::selector,
        providers::{JsonRpcClient, Provider},
    };

    const PUBLIC_RPC: &str = "https://starknet-rpc.publicnode.com";

    // STRK fee token on Starknet mainnet — a stable well-known contract.
    const STRK_TOKEN: Felt = Felt::from_hex_unchecked(
        "0x04718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d",
    );

    #[tokio::test]
    async fn send_request_block_number_against_public_rpc() {
        let url: Url = PUBLIC_RPC.parse().unwrap();
        let provider = JsonRpcClient::new(PositionalHttpTransport::new(url));

        // `starknet_call` takes two named params (request, block_id) — exercises
        // the Object → positional-Array conversion end-to-end, mirroring what
        // `is_transfer_finalised` does in the bridge client.
        let result = provider
            .call(
                FunctionCall {
                    contract_address: STRK_TOKEN,
                    entry_point_selector: selector!("name"),
                    calldata: vec![],
                },
                BlockId::Tag(BlockTag::Latest),
            )
            .await
            .expect("starknet_call failed");

        // ByteArray layout: [num_full_words, ...word_felts, pending_word, pending_len]
        // For "Starknet Token" (14 bytes): [0, 0x537461726b6e657420546f6b656e, 14]
        assert_eq!(result.len(), 3, "unexpected result shape: {result:?}");
        assert_eq!(result[0], Felt::ZERO);
        assert_eq!(
            result[1],
            Felt::from_hex_unchecked("0x537461726b6e657420546f6b656e")
        );
        assert_eq!(result[2], Felt::from(14u64));
    }
}
