use std::str::FromStr;

use alloy::network::EthereumWallet;
use alloy::primitives::Address;
use alloy::providers::{Provider, ProviderBuilder};
use alloy::signers::local::PrivateKeySigner;
use alloy::transports::http::reqwest::Url;

use crate::error::{EvmBridgeClientError, Result};
use crate::EvmBridgeClient;

#[derive(Default)]
pub struct EvmBridgeClientBuilder {
    #[doc = r"EVM RPC endpoint"]
    endpoint: Option<String>,
    #[doc = r"EVM private key. Required for `deploy_token`, `mint`, `burn`"]
    private_key: Option<String>,
    #[doc = r"`OmniBridge` address on EVM. Required for `deploy_token`, `mint`, `burn`"]
    omni_bridge_address: Option<String>,
    #[doc = r"Wormhole core address on EVM. Required to get wormhole fee"]
    wormhole_core_address: Option<String>,
}

impl EvmBridgeClientBuilder {
    pub fn endpoint(mut self, endpoint: Option<String>) -> Self {
        self.endpoint = endpoint;
        self
    }

    pub fn private_key(mut self, private_key: Option<String>) -> Self {
        self.private_key = private_key;
        self
    }

    pub fn omni_bridge_address(mut self, omni_bridge_address: Option<String>) -> Self {
        self.omni_bridge_address = omni_bridge_address;
        self
    }

    pub fn wormhole_core_address(mut self, wormhole_core_address: Option<String>) -> Self {
        self.wormhole_core_address = wormhole_core_address;
        self
    }

    pub fn build(self) -> Result<EvmBridgeClient> {
        let endpoint = self
            .endpoint
            .ok_or_else(|| EvmBridgeClientError::ConfigError("endpoint is required".to_string()))?;

        let url: Url = endpoint.parse().map_err(|_| {
            EvmBridgeClientError::ConfigError("Invalid EVM rpc endpoint url".to_string())
        })?;
        let provider = ProviderBuilder::new().connect_http(url.clone()).erased();

        let wallet = self
            .private_key
            .map(|pk| {
                PrivateKeySigner::from_str(&pk)
                    .map(EthereumWallet::from)
                    .map_err(|_| {
                        EvmBridgeClientError::ConfigError("Invalid EVM private key".to_string())
                    })
            })
            .transpose()?;

        let signer_address = wallet.as_ref().map(|w| w.default_signer().address());
        let signer_provider =
            wallet.map(|w| ProviderBuilder::new().wallet(w).connect_http(url).erased());

        let omni_bridge_address = self
            .omni_bridge_address
            .map(|address| {
                Address::from_str(&address).map_err(|_| {
                    EvmBridgeClientError::ConfigError(
                        "omni_bridge_address is not a valid EVM address".to_string(),
                    )
                })
            })
            .transpose()?;

        let wormhole_core_address = self
            .wormhole_core_address
            .map(|address| {
                Address::from_str(&address).map_err(|_| {
                    EvmBridgeClientError::ConfigError(
                        "wormhole_core_address is not a valid EVM address".to_string(),
                    )
                })
            })
            .transpose()?;

        Ok(EvmBridgeClient {
            endpoint,
            provider,
            signer_provider,
            signer_address,
            omni_bridge_address,
            wormhole_core_address,
        })
    }
}
