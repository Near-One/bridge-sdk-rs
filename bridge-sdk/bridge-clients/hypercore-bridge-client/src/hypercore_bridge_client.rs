use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use alloy::primitives::{keccak256, Address, FixedBytes, TxHash, U256};
use alloy::providers::{DynProvider, Provider};
use alloy::rpc::types::Filter;
use alloy::signers::local::PrivateKeySigner;
use alloy::sol;
use alloy::sol_types::SolEvent;
use serde::Serialize;

use crate::action::SendToEvmWithDataAction;
use crate::error::{HyperCoreBridgeClientError, Result};
use crate::signing::{sign_action, ActionSignature};

pub use action::{format_amount, HyperliquidNetwork};
pub use builder::HyperCoreBridgeClientBuilder;
pub use encoders::{
    encode_init_transfer_action, encode_transfer_action, ACTION_INIT_TRANSFER, ACTION_TRANSFER,
};

mod action;
mod builder;
pub mod encoders;
pub mod error;
mod signing;

sol! {
    #[allow(missing_docs)]
    interface HlBridgeToken {
        event CoreReceived(address indexed sender, uint8 indexed action, uint256 amount, bytes data);
    }
}

const DEFAULT_GAS_LIMIT_INIT_TRANSFER: u64 = 800_000;
const DEFAULT_GAS_LIMIT_TRANSFER: u64 = 300_000;

/// One Hyperliquid Core user, scoped to a specific network and HyperEVM RPC.
///
/// Builds, signs (EIP-712 user-signed action), and posts `sendToEvmWithData`
/// actions to `/exchange`, then polls HyperEVM for the resulting `CoreReceived`
/// log emitted by the target `HlBridgeToken` contract.
///
/// `Clone` is cheap: provider/signer/reqwest are all `Arc`-backed internally.
#[derive(Clone)]
pub struct HyperCoreBridgeClient {
    pub(crate) network: HyperliquidNetwork,
    pub(crate) api_url: String,
    pub(crate) hyperevm_provider: DynProvider,
    pub(crate) signer: PrivateKeySigner,
    pub(crate) http_client: reqwest::Client,
    pub(crate) signature_chain_id: String,
    pub(crate) poll_interval: Duration,
    pub(crate) poll_timeout: Duration,
}

#[derive(Debug, Clone)]
pub struct CoreReceivedLog {
    pub sender: Address,
    pub action: u8,
    pub amount: U256,
    pub data: alloy::primitives::Bytes,
    pub transaction_hash: TxHash,
    pub block_number: u64,
}

impl HyperCoreBridgeClient {
    #[must_use]
    pub fn network(&self) -> HyperliquidNetwork {
        self.network
    }

    #[must_use]
    pub fn signer_address(&self) -> Address {
        self.signer.address()
    }

    pub fn default_gas_limit(action_tag: u8) -> u64 {
        match action_tag {
            encoders::ACTION_INIT_TRANSFER => DEFAULT_GAS_LIMIT_INIT_TRANSFER,
            _ => DEFAULT_GAS_LIMIT_TRANSFER,
        }
    }

    /// Builds, signs, and posts a `sendToEvmWithData` action targeting `hl_bridge_token`
    /// on HyperEVM, then polls for the resulting `CoreReceived` log.
    ///
    /// Returns the HyperEVM `TxHash` that emitted the log. The `data` payload is
    /// expected to already encode `tag || abi.encoded payload` (use the encoders
    /// in this crate).
    pub async fn send_to_evm_with_data(
        &self,
        token: String,
        amount: String,
        hl_bridge_token: Address,
        data: Vec<u8>,
        gas_limit: Option<u64>,
    ) -> Result<TxHash> {
        self.send_to_evm_with_data_detailed(token, amount, hl_bridge_token, data, gas_limit)
            .await
            .map(|log| log.transaction_hash)
    }

    /// Detailed variant returning the full `CoreReceivedLog` (sender, action
    /// tag, amount, data, tx hash, block). The single source of truth for
    /// action construction; [`send_to_evm_with_data`] is a thin wrapper.
    #[tracing::instrument(skip_all, name = "HYPERCORE SEND TO EVM WITH DATA")]
    pub async fn send_to_evm_with_data_detailed(
        &self,
        token: String,
        amount: String,
        hl_bridge_token: Address,
        data: Vec<u8>,
        gas_limit: Option<u64>,
    ) -> Result<CoreReceivedLog> {
        let action_tag = data.first().copied().ok_or_else(|| {
            HyperCoreBridgeClientError::InvalidArgument(
                "action `data` must be non-empty (at least the action tag)".to_string(),
            )
        })?;
        let nonce = current_ms_nonce();
        let action = SendToEvmWithDataAction {
            action_type: "sendToEvmWithData",
            hyperliquid_chain: self.network.hyperliquid_chain(),
            signature_chain_id: self.signature_chain_id.clone(),
            token,
            amount,
            source_dex: "spot".to_string(),
            destination_recipient: format!("0x{}", hex::encode(hl_bridge_token.as_slice())),
            address_encoding: "hex".to_string(),
            destination_chain_id: self.network.hyperevm_chain_id(),
            gas_limit: gas_limit.unwrap_or_else(|| Self::default_gas_limit(action_tag)),
            data: format!("0x{}", hex::encode(&data)),
            nonce,
        };

        let signature = sign_action(&self.signer, &action)?;
        self.post_action(&action, &signature, nonce).await?;
        self.poll_core_received(hl_bridge_token, &data).await
    }

    async fn post_action(
        &self,
        action: &SendToEvmWithDataAction,
        signature: &ActionSignature,
        nonce: u64,
    ) -> Result<()> {
        #[derive(Serialize)]
        struct Envelope<'a> {
            action: &'a SendToEvmWithDataAction,
            nonce: u64,
            signature: &'a ActionSignature,
        }

        let body = Envelope {
            action,
            nonce,
            signature,
        };

        let url = format!("{}/exchange", self.api_url);
        let response = self
            .http_client
            .post(&url)
            .json(&body)
            .send()
            .await
            .map_err(|e| HyperCoreBridgeClientError::Http(e.to_string()))?;

        let status = response.status();
        let text = response
            .text()
            .await
            .map_err(|e| HyperCoreBridgeClientError::Http(e.to_string()))?;

        if !status.is_success() {
            return Err(HyperCoreBridgeClientError::ExchangeRejected(format!(
                "HTTP {status}: {text}"
            )));
        }

        let parsed: serde_json::Value = serde_json::from_str(&text).map_err(|e| {
            HyperCoreBridgeClientError::ExchangeRejected(format!(
                "could not parse /exchange response as JSON ({e}): {text}"
            ))
        })?;

        match parsed.get("status").and_then(|s| s.as_str()) {
            Some("ok") => {
                tracing::info!(?nonce, "Hyperliquid /exchange accepted sendToEvmWithData");
                Ok(())
            }
            Some("err") => {
                let msg = parsed
                    .get("response")
                    .and_then(|r| r.as_str())
                    .unwrap_or(text.as_str())
                    .to_string();
                Err(HyperCoreBridgeClientError::ExchangeRejected(msg))
            }
            _ => Err(HyperCoreBridgeClientError::ExchangeRejected(format!(
                "unexpected /exchange response shape: {text}"
            ))),
        }
    }

    /// Polls HyperEVM for the `CoreReceived` log emitted by our `sendToEvmWithData`
    /// action. Filter is `address + topic0 + topic1=signer`. Disambiguation
    /// across concurrent calls from the same signer relies on `expected_data`
    /// matching `log.data`: the encoded `tag || abi.encode(payload)` bytes are
    /// effectively a unique identifier per call *unless* the caller fires two
    /// calls with identical parameters in flight at once — in that case the
    /// protocol can't disambiguate them either.
    async fn poll_core_received(
        &self,
        hl_bridge_token: Address,
        expected_data: &[u8],
    ) -> Result<CoreReceivedLog> {
        let topic0 = keccak256(HlBridgeToken::CoreReceived::SIGNATURE.as_bytes());
        let signer_address = self.signer.address();
        let mut topic1 = [0u8; 32];
        topic1[12..].copy_from_slice(signer_address.as_slice());
        let topic1 = FixedBytes::<32>::from(topic1);

        let mut head = self
            .hyperevm_provider
            .get_block_number()
            .await
            .map_err(|e| HyperCoreBridgeClientError::Rpc(e.to_string()))?;
        // Look back ~10 blocks in case the system tx already landed during the
        // POST round-trip; HyperEVM small blocks are 1s.
        let mut from_block = head.saturating_sub(10);

        let start = Instant::now();
        loop {
            if head >= from_block {
                let filter = Filter::new()
                    .address(hl_bridge_token)
                    .event_signature(topic0)
                    .topic1(topic1)
                    .from_block(from_block)
                    .to_block(head);

                let logs = self
                    .hyperevm_provider
                    .get_logs(&filter)
                    .await
                    .map_err(|e| HyperCoreBridgeClientError::Rpc(e.to_string()))?;

                for log in logs {
                    let inner = log.inner.clone();
                    let decoded = HlBridgeToken::CoreReceived::decode_log(&inner).map_err(|e| {
                        HyperCoreBridgeClientError::Rpc(format!(
                            "failed to decode CoreReceived log: {e}"
                        ))
                    })?;
                    if decoded.data.data.as_ref() != expected_data {
                        continue;
                    }
                    let tx_hash = log.transaction_hash.ok_or_else(|| {
                        HyperCoreBridgeClientError::Rpc(
                            "CoreReceived log missing transaction_hash".to_string(),
                        )
                    })?;
                    let block_number = log.block_number.ok_or_else(|| {
                        HyperCoreBridgeClientError::Rpc(
                            "CoreReceived log missing block_number".to_string(),
                        )
                    })?;
                    let HlBridgeToken::CoreReceived {
                        sender,
                        action,
                        amount,
                        data,
                    } = decoded.data;
                    return Ok(CoreReceivedLog {
                        sender,
                        action,
                        amount,
                        data,
                        transaction_hash: tx_hash,
                        block_number,
                    });
                }

                from_block = head.saturating_add(1);
            }

            if start.elapsed() >= self.poll_timeout {
                return Err(HyperCoreBridgeClientError::PollTimeout);
            }
            tokio::time::sleep(self.poll_interval).await;
            head = self
                .hyperevm_provider
                .get_block_number()
                .await
                .map_err(|e| HyperCoreBridgeClientError::Rpc(e.to_string()))?;
        }
    }
}

fn current_ms_nonce() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}
