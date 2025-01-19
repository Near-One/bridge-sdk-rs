use bridge_connector_common::result::{BridgeSdkError, Result};
use derive_builder::Builder;
use near_primitives::serialize::from_base64;

#[derive(Debug, serde::Deserialize)]
struct WormholeApiResponse {
    data: WormholeApiData,
}

#[derive(Debug, serde::Deserialize)]
struct WormholeTxApiResponse {
    data: Vec<WormholeApiData>,
}

#[derive(Debug, serde::Deserialize, Clone)]
struct WormholeApiData {
    vaa: String,
}

/// WormholeBridgeClient is a client for interacting with the Wormhole API
#[derive(Builder, Default, Clone)]
pub struct WormholeBridgeClient {
    #[doc = r"Wormhole API endpoint. Required for retrieving `vaa`"]
    pub endpoint: Option<String>,
}

impl WormholeBridgeClient {
    /// Creates an empty instance of the bridging client. Property values can be set separately depending on the required use case.
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn get_vaa<E>(&self, chain_id: u64, emitter: E, sequence: u64) -> Result<String>
    where
        E: std::fmt::Display + Send,
    {
        let endpoint = self.endpoint()?;
        let sanitized_endpoint = endpoint.trim_end_matches('/');

        let url = format!(
            "{}/api/v1/vaas/{}/{}/{}",
            sanitized_endpoint, chain_id, emitter, sequence
        );

        let response = reqwest::get(url)
            .await
            .map_err(|_| BridgeSdkError::UnknownError)?;

        let vaa = response
            .json::<WormholeApiResponse>()
            .await
            .map_err(|_| BridgeSdkError::UnknownError)?
            .data
            .vaa;
        Ok(hex::encode(from_base64(&vaa).unwrap()))
    }

    pub async fn get_vaa_by_tx_hash(&self, tx_hash: String) -> Result<String> {
        let endpoint = self.endpoint()?;
        let sanitized_endpoint = endpoint.trim_end_matches('/');

        let url = format!("{}/api/v1/vaas/?txHash={}", sanitized_endpoint, tx_hash);

        let response = reqwest::get(url)
            .await
            .map_err(|e| BridgeSdkError::WormholeClientError(e.to_string()))?;

        let vaa = response
            .json::<WormholeTxApiResponse>()
            .await
            .map_err(|e| BridgeSdkError::WormholeClientError(e.to_string()))?
            .data
            .first()
            .cloned()
            .ok_or(BridgeSdkError::WormholeClientError(
                "No VAA found".to_string(),
            ))?
            .vaa;

        Ok(hex::encode(from_base64(&vaa).unwrap()))
    }

    fn endpoint(&self) -> Result<&str> {
        Ok(self.endpoint.as_ref().ok_or(BridgeSdkError::ConfigError(
            "Wormhole api endpoint is not set".to_string(),
        ))?)
    }
}
