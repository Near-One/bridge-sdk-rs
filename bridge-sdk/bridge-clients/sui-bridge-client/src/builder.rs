use near_mpc_contract_interface::types::SuiFinality;
use sui_crypto::ed25519::Ed25519PrivateKey;
use sui_sdk_types::Address;

use crate::error::{Result, SuiBridgeClientError};
use crate::{SuiAccount, SuiBridgeClient};

/// Builder for [`SuiBridgeClient`]. Only `endpoint` is required; signing and
/// bridge addressing are optional so read-only flows work unsigned. Setters
/// take `Option`s so CLI/config values pass straight through.
#[derive(Default)]
pub struct SuiBridgeClientBuilder {
    endpoint: Option<String>,
    private_key: Option<String>,
    bridge_address: Option<String>,
    state_object_id: Option<String>,
    mpc_finality: Option<SuiFinality>,
}

impl SuiBridgeClientBuilder {
    /// gRPC fullnode endpoint, e.g. `https://fullnode.mainnet.sui.io`.
    #[must_use]
    pub fn endpoint(mut self, endpoint: Option<String>) -> Self {
        self.endpoint = endpoint;
        self
    }

    /// Ed25519 key: either a hex 32-byte seed (`0x` optional) or a Sui CLI
    /// `suiprivkey1...` bech32 string. The account address is derived from
    /// the public key.
    #[must_use]
    pub fn private_key(mut self, private_key: Option<String>) -> Self {
        self.private_key = private_key;
        self
    }

    /// Package id the `omni_bridge` Move module is published under.
    #[must_use]
    pub fn bridge_address(mut self, bridge_address: Option<String>) -> Self {
        self.bridge_address = bridge_address;
        self
    }

    /// Object id of the shared `BridgeState`.
    #[must_use]
    pub fn state_object_id(mut self, state_object_id: Option<String>) -> Self {
        self.state_object_id = state_object_id;
        self
    }

    /// MPC finality level required before building an MPC sign payload.
    #[must_use]
    pub fn mpc_finality(mut self, mpc_finality: Option<SuiFinality>) -> Self {
        self.mpc_finality = mpc_finality;
        self
    }

    pub fn build(self) -> Result<SuiBridgeClient> {
        let endpoint = self
            .endpoint
            .ok_or_else(|| SuiBridgeClientError::ConfigError("endpoint is required".to_string()))?;
        let rpc = sui_rpc::Client::new(endpoint.clone()).map_err(|e| {
            SuiBridgeClientError::ConfigError(format!("invalid Sui endpoint {endpoint:?}: {e}"))
        })?;

        let account = self
            .private_key
            .as_deref()
            .map(parse_private_key)
            .transpose()?
            .map(|key| {
                let address = key.public_key().derive_address();
                SuiAccount { key, address }
            });

        Ok(SuiBridgeClient {
            rpc,
            account,
            bridge_address: self
                .bridge_address
                .as_deref()
                .map(|s| parse_address(s, "bridge address"))
                .transpose()?,
            state_object_id: self
                .state_object_id
                .as_deref()
                .map(|s| parse_address(s, "state object id"))
                .transpose()?,
            mpc_finality: self.mpc_finality,
        })
    }
}

fn parse_private_key(key: &str) -> Result<Ed25519PrivateKey> {
    let key = key.trim();
    if key.starts_with("suiprivkey") {
        return Ed25519PrivateKey::from_suiprivkey(key).map_err(|e| {
            SuiBridgeClientError::ConfigError(format!("invalid suiprivkey string: {e}"))
        });
    }
    let hex_str = key.strip_prefix("0x").unwrap_or(key);
    let bytes = hex::decode(hex_str)
        .map_err(|e| SuiBridgeClientError::ConfigError(format!("invalid private key hex: {e}")))?;
    let seed: [u8; 32] = bytes.try_into().map_err(|_| {
        SuiBridgeClientError::ConfigError("private key seed must be exactly 32 bytes".to_string())
    })?;
    Ok(Ed25519PrivateKey::new(seed))
}

fn parse_address(s: &str, what: &str) -> Result<Address> {
    s.trim()
        .parse()
        .map_err(|e| SuiBridgeClientError::ConfigError(format!("invalid {what} {s:?}: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn requires_endpoint() {
        assert!(matches!(
            SuiBridgeClientBuilder::default().build(),
            Err(SuiBridgeClientError::ConfigError(_))
        ));
    }

    #[tokio::test]
    async fn builds_readonly_client_without_signer() {
        let client = SuiBridgeClientBuilder::default()
            .endpoint(Some("https://fullnode.testnet.sui.io".to_string()))
            .build()
            .unwrap();
        assert!(client.account.is_none());
        assert!(client.account().is_err());
    }

    #[tokio::test]
    async fn parses_hex_private_key_and_derives_address() {
        let client = SuiBridgeClientBuilder::default()
            .endpoint(Some("https://fullnode.testnet.sui.io".to_string()))
            .private_key(Some(format!("0x{}", hex::encode([7u8; 32]))))
            .bridge_address(Some(
                "0x587d69879cb01f62a88526a7448424c37cf767387473c1e610bd007dc95fa6ba".to_string(),
            ))
            .state_object_id(Some("0xcbe9".to_string()))
            .build()
            .unwrap();
        let account = client.account.as_ref().unwrap();
        // Address = Blake2b256(0x00 || pubkey) — deterministic for a fixed seed.
        let expected = Ed25519PrivateKey::new([7u8; 32])
            .public_key()
            .derive_address();
        assert_eq!(account.address, expected);
        assert!(client.bridge_address.is_some());
    }

    #[tokio::test]
    async fn rejects_bad_keys_and_addresses() {
        let base = || {
            SuiBridgeClientBuilder::default()
                .endpoint(Some("https://fullnode.testnet.sui.io".to_string()))
        };
        assert!(base().private_key(Some("0xzz".into())).build().is_err());
        assert!(base().private_key(Some("0x0102".into())).build().is_err());
        assert!(base()
            .bridge_address(Some("not-an-address".into()))
            .build()
            .is_err());
    }
}
