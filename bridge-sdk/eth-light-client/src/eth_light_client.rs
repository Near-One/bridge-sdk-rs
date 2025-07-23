use borsh::BorshDeserialize;
use bridge_connector_common::result::{BridgeSdkError, Result};
use derive_builder::Builder;
use near_primitives::types::AccountId;
use near_rpc_client::ViewRequest;

#[derive(BorshDeserialize)]
struct EthLightClientResponse {
    last_block_number: u64,
}

/// Ethereum light client NEAR
#[derive(Builder, Default, Clone)]
pub struct EthLightClient {
    #[doc = r"NEAR RPC endpoint"]
    endpoint: Option<String>,
    #[doc = r"Eth light client account id on Near"]
    eth_light_client_id: Option<String>,
}

impl EthLightClient {
    pub async fn get_last_block_number(&self) -> Result<u64> {
        let endpoint = self.endpoint()?;

        let response = near_rpc_client::view(
            endpoint,
            ViewRequest {
                contract_account_id: self.light_client_id()?,
                method_name: "last_block_number".to_string(),
                args: serde_json::Value::Null,
            },
        )
        .await?;

        let parsed_response: EthLightClientResponse = borsh::from_slice(&response)
            .map_err(|err| BridgeSdkError::UnknownError(err.to_string()))?;
        Ok(parsed_response.last_block_number)
    }

    pub fn light_client_id(&self) -> Result<AccountId> {
        self.eth_light_client_id
            .as_ref()
            .ok_or(BridgeSdkError::ConfigError(
                "Eth light client account id is not set".to_string(),
            ))?
            .parse::<AccountId>()
            .map_err(|_| {
                BridgeSdkError::ConfigError("Invalid Eth light client account id".to_string())
            })
    }

    pub fn endpoint(&self) -> Result<&str> {
        Ok(self.endpoint.as_ref().ok_or(BridgeSdkError::ConfigError(
            "Near rpc endpoint is not set".to_string(),
        ))?)
    }
}
