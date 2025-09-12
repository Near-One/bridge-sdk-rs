use borsh::BorshDeserialize;
use bridge_connector_common::result::{BridgeSdkError, Result};
use derive_builder::Builder;
use near_primitives::types::AccountId;
use near_rpc_client::ViewRequest;
use omni_types::ChainKind;
use serde::Deserialize;

#[derive(BorshDeserialize)]
struct EthLightClientResponse {
    last_block_number: u64,
}

#[derive(Deserialize)]
struct UtxoLastHeaderResponse {
    block_height: u64,
}

/// Ethereum light client NEAR
#[derive(Builder, Default, Clone)]
pub struct LightClient {
    #[doc = r"NEAR RPC endpoint"]
    endpoint: Option<String>,
    #[doc = r"Chain kind"]
    chain: Option<ChainKind>,
    #[doc = r"Eth light client account id on Near"]
    light_client_id: Option<AccountId>,
}

impl LightClient {
    pub fn get_method_name(&self) -> Result<String> {
        match self.chain {
            Some(ChainKind::Eth) => Ok("last_block_number".to_string()),
            Some(ChainKind::Btc | ChainKind::Zcash) => Ok("get_last_block_header".to_string()),
            _ => Err(BridgeSdkError::ConfigError(format!(
                "Unsupported chain kind: {:?}",
                self.chain
            ))),
        }
    }

    pub async fn get_last_block_number(&self) -> Result<u64> {
        let endpoint = self.endpoint()?;

        let response = near_rpc_client::view(
            endpoint,
            ViewRequest {
                contract_account_id: self.light_client_id()?.clone(),
                method_name: self.get_method_name()?,
                args: serde_json::Value::Null,
            },
        )
        .await?;

        match self.chain {
            Some(ChainKind::Eth) => {
                let parsed_response: EthLightClientResponse = borsh::from_slice(&response)
                    .map_err(|err| BridgeSdkError::UnknownError(err.to_string()))?;
                Ok(parsed_response.last_block_number)
            }
            Some(ChainKind::Btc | ChainKind::Zcash) => {
                let parsed_response: UtxoLastHeaderResponse = serde_json::from_slice(&response)?;
                Ok(parsed_response.block_height)
            }
            _ => Err(BridgeSdkError::ConfigError(format!(
                "Unsupported chain kind: {:?}",
                self.chain
            ))),
        }
    }

    pub fn light_client_id(&self) -> Result<&AccountId> {
        self.light_client_id
            .as_ref()
            .ok_or(BridgeSdkError::ConfigError(
                "Eth light client account id is not set".to_string(),
            ))
    }

    pub fn endpoint(&self) -> Result<&str> {
        Ok(self.endpoint.as_ref().ok_or(BridgeSdkError::ConfigError(
            "Near rpc endpoint is not set".to_string(),
        ))?)
    }
}
