use std::sync::Arc;

use starknet::{
    accounts::{ExecutionEncoding, SingleOwnerAccount},
    core::types::{BlockId, BlockTag, Felt},
    providers::{jsonrpc::HttpTransport, JsonRpcClient},
    signers::{LocalWallet, SigningKey},
};
use url::Url;

use crate::error::{Result, StarknetBridgeClientError};
use crate::StarknetBridgeClient;

#[derive(Default)]
pub struct StarknetBridgeClientBuilder {
    #[doc = r"Required. Starknet JSON-RPC endpoint."]
    endpoint: Option<String>,
    #[doc = r"Optional. Hex-encoded private key (Felt) for signing transactions."]
    private_key: Option<String>,
    #[doc = r"Optional. Starknet account contract address (hex Felt)."]
    account_address: Option<String>,
    #[doc = r"Optional. OmniBridge contract address on Starknet (hex Felt)."]
    omni_bridge_address: Option<String>,
    #[doc = r"Optional. Chain ID string (e.g. `SN_MAIN`, `SN_SEPOLIA`)."]
    chain_id: Option<String>,
}

impl StarknetBridgeClientBuilder {
    #[must_use]
    pub fn endpoint(mut self, endpoint: Option<String>) -> Self {
        self.endpoint = endpoint;
        self
    }

    #[must_use]
    pub fn private_key(mut self, private_key: Option<String>) -> Self {
        self.private_key = private_key;
        self
    }

    #[must_use]
    pub fn account_address(mut self, account_address: Option<String>) -> Self {
        self.account_address = account_address;
        self
    }

    #[must_use]
    pub fn omni_bridge_address(mut self, omni_bridge_address: Option<String>) -> Self {
        self.omni_bridge_address = omni_bridge_address;
        self
    }

    #[must_use]
    pub fn chain_id(mut self, chain_id: Option<String>) -> Self {
        self.chain_id = chain_id;
        self
    }

    pub fn build(self) -> Result<StarknetBridgeClient> {
        let endpoint = self.endpoint.ok_or_else(|| {
            StarknetBridgeClientError::ConfigError("endpoint is required".to_string())
        })?;

        let url: Url = endpoint.parse().map_err(|_| {
            StarknetBridgeClientError::ConfigError("Invalid Starknet RPC endpoint URL".to_string())
        })?;

        let provider = Arc::new(JsonRpcClient::new(HttpTransport::new(url)));

        let account = if let (Some(pk), Some(addr)) = (self.private_key, self.account_address) {
            let private_key = parse_felt(&pk).map_err(|_| {
                StarknetBridgeClientError::ConfigError("Invalid Starknet private key".to_string())
            })?;

            let account_address = parse_felt(&addr).map_err(|_| {
                StarknetBridgeClientError::ConfigError(
                    "Invalid Starknet account address".to_string(),
                )
            })?;

            let chain_id_str = self.chain_id.as_deref().unwrap_or("SN_MAIN");
            let chain_id = Felt::from_bytes_be_slice(chain_id_str.as_bytes());

            let signer = LocalWallet::from(SigningKey::from_secret_scalar(private_key));
            let mut account = SingleOwnerAccount::new(
                Arc::clone(&provider),
                signer,
                account_address,
                chain_id,
                ExecutionEncoding::New,
            );
            account.set_block_id(BlockId::Tag(BlockTag::Latest));

            Some(Arc::new(account))
        } else {
            None
        };

        let omni_bridge_address = self
            .omni_bridge_address
            .map(|addr| {
                parse_felt(&addr).map_err(|_| {
                    StarknetBridgeClientError::ConfigError(
                        "Invalid Starknet bridge address".to_string(),
                    )
                })
            })
            .transpose()?;

        Ok(StarknetBridgeClient {
            provider,
            account,
            omni_bridge_address,
        })
    }
}

fn parse_felt(s: &str) -> std::result::Result<Felt, String> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    Felt::from_hex(&format!("0x{s}")).map_err(|e| e.to_string())
}
