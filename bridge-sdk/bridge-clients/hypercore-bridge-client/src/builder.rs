use std::str::FromStr;
use std::time::Duration;

use alloy::providers::{Provider, ProviderBuilder};
use alloy::signers::local::PrivateKeySigner;
use alloy::transports::http::reqwest::Url;

use crate::action::HyperliquidNetwork;
use crate::error::{HyperCoreBridgeClientError, Result};
use crate::HyperCoreBridgeClient;

/// Default Arbitrum-Sepolia chain id for `signatureChainId`, matching the
/// Hyperliquid Python SDK default (signing.py:250).
const DEFAULT_SIGNATURE_CHAIN_ID: &str = "0x66eee";

const DEFAULT_POLL_INTERVAL_MS: u64 = 1500;
const DEFAULT_POLL_TIMEOUT_SECS: u64 = 60;
const DEFAULT_HTTP_TIMEOUT_SECS: u64 = 30;

#[derive(Default)]
pub struct HyperCoreBridgeClientBuilder {
    network: Option<HyperliquidNetwork>,
    api_url: Option<String>,
    hyperevm_rpc_url: Option<String>,
    private_key: Option<String>,
    signature_chain_id: Option<String>,
    poll_interval: Option<Duration>,
    poll_timeout: Option<Duration>,
    http_timeout: Option<Duration>,
}

impl HyperCoreBridgeClientBuilder {
    #[must_use]
    pub fn network(mut self, network: HyperliquidNetwork) -> Self {
        self.network = Some(network);
        self
    }

    /// Hyperliquid REST base URL. Required. Provide the BASE URL without the
    /// `/exchange` suffix. The caller is the source of truth — see
    /// `bridge-cli/src/defaults.rs::HYPERCORE_API_*`.
    #[must_use]
    pub fn api_url(mut self, api_url: Option<String>) -> Self {
        self.api_url = api_url;
        self
    }

    /// HyperEVM RPC URL used for the post-action `CoreReceived` poll.
    /// Required. The caller is the source of truth — see
    /// `bridge-cli/src/defaults.rs::HYPEREVM_RPC_*`.
    #[must_use]
    pub fn hyperevm_rpc_url(mut self, hyperevm_rpc_url: Option<String>) -> Self {
        self.hyperevm_rpc_url = hyperevm_rpc_url;
        self
    }

    /// EOA private key (hex, optionally `0x`-prefixed). Same key the user uses
    /// for HyperEVM transactions — Hyperliquid action signing reuses it.
    #[must_use]
    pub fn private_key(mut self, private_key: Option<String>) -> Self {
        self.private_key = private_key;
        self
    }

    /// Wallet chain id encoded as a hex string (e.g. `"0xa4b1"` for Arbitrum).
    /// This goes into the action `signatureChainId` field and the EIP-712 domain;
    /// the constraint is only that signatures don't replay across chains.
    /// Defaults to `0x66eee` (Arb-Sepolia), matching the Python SDK default.
    #[must_use]
    pub fn signature_chain_id(mut self, signature_chain_id: Option<String>) -> Self {
        self.signature_chain_id = signature_chain_id;
        self
    }

    #[must_use]
    pub fn poll_interval(mut self, poll_interval: Option<Duration>) -> Self {
        self.poll_interval = poll_interval;
        self
    }

    #[must_use]
    pub fn poll_timeout(mut self, poll_timeout: Option<Duration>) -> Self {
        self.poll_timeout = poll_timeout;
        self
    }

    /// Per-request timeout applied to `/exchange` POSTs. Without this, a hung
    /// Hyperliquid API connection would block the call indefinitely (the poll
    /// timeout only covers the EVM-side wait). Default 30s.
    #[must_use]
    pub fn http_timeout(mut self, http_timeout: Option<Duration>) -> Self {
        self.http_timeout = http_timeout;
        self
    }

    pub fn build(self) -> Result<HyperCoreBridgeClient> {
        let network = self.network.ok_or_else(|| {
            HyperCoreBridgeClientError::ConfigError("network is required".to_string())
        })?;

        let private_key = self.private_key.ok_or_else(|| {
            HyperCoreBridgeClientError::ConfigError("private_key is required".to_string())
        })?;
        let signer = PrivateKeySigner::from_str(&private_key).map_err(|_| {
            HyperCoreBridgeClientError::ConfigError("Invalid HyperCore private key".to_string())
        })?;

        let api_url = self.api_url.ok_or_else(|| {
            HyperCoreBridgeClientError::ConfigError(
                "Hyperliquid api_url is required".to_string(),
            )
        })?;
        let hyperevm_rpc_url = self.hyperevm_rpc_url.ok_or_else(|| {
            HyperCoreBridgeClientError::ConfigError(
                "hyperevm_rpc_url is required (used for CoreReceived polling)".to_string(),
            )
        })?;

        let rpc_url: Url = hyperevm_rpc_url.parse().map_err(|_| {
            HyperCoreBridgeClientError::ConfigError(
                "Invalid HyperEVM RPC URL for HyperCore polling".to_string(),
            )
        })?;
        let hyperevm_provider = ProviderBuilder::new().connect_http(rpc_url).erased();

        let http_timeout = self
            .http_timeout
            .unwrap_or_else(|| Duration::from_secs(DEFAULT_HTTP_TIMEOUT_SECS));
        let http_client = reqwest::Client::builder()
            .timeout(http_timeout)
            .build()
            .map_err(|e| HyperCoreBridgeClientError::Http(e.to_string()))?;

        let signature_chain_id = self
            .signature_chain_id
            .unwrap_or_else(|| DEFAULT_SIGNATURE_CHAIN_ID.to_string());

        let poll_interval = self
            .poll_interval
            .unwrap_or_else(|| Duration::from_millis(DEFAULT_POLL_INTERVAL_MS));
        let poll_timeout = self
            .poll_timeout
            .unwrap_or_else(|| Duration::from_secs(DEFAULT_POLL_TIMEOUT_SECS));

        Ok(HyperCoreBridgeClient {
            network,
            api_url,
            hyperevm_provider,
            signer,
            http_client,
            signature_chain_id,
            poll_interval,
            poll_timeout,
        })
    }
}
