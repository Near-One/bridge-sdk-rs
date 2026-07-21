use ed25519_dalek::SigningKey;
use near_mpc_contract_interface::types::AptosFinality;

use crate::error::{AptosBridgeClientError, Result};
use crate::{AptosAccount, AptosBridgeClient};

#[derive(Default)]
pub struct AptosBridgeClientBuilder {
    #[doc = r"Required. Aptos fullnode REST endpoint, including the `/v1` segment."]
    endpoint: Option<String>,
    #[doc = r"Optional. Hex-encoded 32-byte Ed25519 private key (seed) for signing transactions."]
    private_key: Option<String>,
    #[doc = r"Optional. Aptos account address (32-byte hex) matching the private key."]
    account_address: Option<String>,
    #[doc = r"Optional. Account the `omni_bridge` Move package is published under (32-byte hex)."]
    omni_bridge_address: Option<String>,
    #[doc = r"Optional. MPC finality level required before an MPC sign payload can be built."]
    mpc_finality: Option<AptosFinality>,
}

impl AptosBridgeClientBuilder {
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
    pub fn mpc_finality(mut self, mpc_finality: Option<AptosFinality>) -> Self {
        self.mpc_finality = mpc_finality;
        self
    }

    pub fn build(self) -> Result<AptosBridgeClient> {
        let base_url = self.endpoint.ok_or_else(|| {
            AptosBridgeClientError::ConfigError("endpoint is required".to_string())
        })?;

        let account = if let (Some(pk), Some(addr)) = (self.private_key, self.account_address) {
            let seed = parse_seed(&pk)?;
            let address = parse_address(&addr).map_err(|e| {
                AptosBridgeClientError::ConfigError(format!("Invalid Aptos account address: {e}"))
            })?;
            Some(AptosAccount {
                signing_key: SigningKey::from_bytes(&seed),
                address,
            })
        } else {
            None
        };

        let omni_bridge_address = self
            .omni_bridge_address
            .map(|addr| {
                parse_address(&addr).map_err(|e| {
                    AptosBridgeClientError::ConfigError(format!(
                        "Invalid Aptos bridge address: {e}"
                    ))
                })
            })
            .transpose()?;

        Ok(AptosBridgeClient {
            http_client: reqwest::Client::new(),
            base_url,
            account,
            omni_bridge_address,
            mpc_finality: self.mpc_finality,
        })
    }
}

/// Parse a 32-byte Ed25519 seed from hex (exactly 32 bytes, no padding).
fn parse_seed(s: &str) -> Result<[u8; 32]> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    let bytes = hex::decode(s).map_err(|e| {
        AptosBridgeClientError::ConfigError(format!("Invalid Aptos private key: {e}"))
    })?;
    bytes.try_into().map_err(|_| {
        AptosBridgeClientError::ConfigError(
            "Aptos private key must be a 32-byte Ed25519 seed".to_string(),
        )
    })
}

/// Parse an Aptos address from hex, left-zero-padding short forms (e.g. "0x1")
/// to 32 bytes — matching the node-side `parse_aptos_address`.
pub(crate) fn parse_address(s: &str) -> std::result::Result<[u8; 32], String> {
    let hex_str = s.strip_prefix("0x").unwrap_or(s);
    if hex_str.is_empty() {
        return Err(format!("empty Aptos address: {s:?}"));
    }
    if hex_str.len() > 64 {
        return Err(format!("address hex string too long: {s}"));
    }
    let padded = format!("{hex_str:0>64}");
    let bytes = hex::decode(&padded).map_err(|e| format!("invalid hex in address '{s}': {e}"))?;
    bytes
        .try_into()
        .map_err(|_| "address did not decode to 32 bytes".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_address_left_pads_short_form() {
        let mut expected = [0u8; 32];
        expected[31] = 0x01;
        assert_eq!(parse_address("0x1").unwrap(), expected);
        assert_eq!(parse_address("0xa").unwrap()[31], 0x0a);
    }

    #[test]
    fn parse_address_rejects_too_long() {
        assert!(parse_address(&format!("0x{}", "0".repeat(65))).is_err());
    }

    #[test]
    fn parse_seed_requires_32_bytes() {
        assert!(parse_seed(&format!("0x{}", "11".repeat(32))).is_ok());
        assert!(parse_seed("0x1122").is_err());
    }
}
