use alloy::primitives::Address;
use serde::Deserialize;

use crate::error::{HyperCoreBridgeClientError, Result};

/// Subset of `POST /info {"type":"spotMeta"}` we care about.
///
/// Hyperliquid's response has many more fields (universe, fullName, etc.);
/// the unused ones are dropped via `#[serde(default)]` and field skipping.
#[derive(Debug, Clone, Deserialize)]
pub struct SpotMetaResponse {
    pub tokens: Vec<SpotMetaToken>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SpotMetaToken {
    pub name: String,
    #[serde(rename = "tokenId")]
    pub token_id: String,
    #[serde(rename = "weiDecimals")]
    pub wei_decimals: i16,
    /// `None` for tokens that aren't linked to a HyperEVM ERC20.
    #[serde(rename = "evmContract")]
    pub evm_contract: Option<EvmContract>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct EvmContract {
    pub address: Address,
    /// Signed offset; final ERC20 decimals = `weiDecimals + evm_extra_wei_decimals`.
    /// e.g. USDC: weiDecimals=8, evm_extra_wei_decimals=-2 → ERC20 has 6 decimals.
    pub evm_extra_wei_decimals: i16,
}

/// Resolved metadata for a single Hyperliquid spot token.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResolvedSpotToken {
    /// HlBridgeToken (or generic linked ERC20) address on HyperEVM.
    pub hl_bridge_token: Address,
    /// Bridge ERC20's decimals (used to format wire amounts).
    pub decimals: u8,
}

/// Parses `"NAME:0x<32-hex>"` (or `"NAME:<32-hex>"`) into `(name, normalized tokenId)`.
pub(crate) fn parse_token_identifier(token: &str) -> Result<(&str, String)> {
    let (name, token_id) = token.split_once(':').ok_or_else(|| {
        HyperCoreBridgeClientError::InvalidArgument(format!(
            "token must be in form `NAME:0x<32hex>`, got `{token}`"
        ))
    })?;
    let stripped = token_id.strip_prefix("0x").unwrap_or(token_id);
    Ok((name, format!("0x{}", stripped.to_lowercase())))
}

/// Locate a token in a `SpotMetaResponse` by name+tokenId and convert its
/// linked EVM contract entry into a `ResolvedSpotToken`.
pub(crate) fn pick_resolved_token(
    meta: &SpotMetaResponse,
    name: &str,
    token_id: &str,
) -> Result<ResolvedSpotToken> {
    let token = meta
        .tokens
        .iter()
        .find(|t| t.name == name && t.token_id.eq_ignore_ascii_case(token_id))
        .ok_or_else(|| {
            HyperCoreBridgeClientError::InvalidArgument(format!(
                "spotMeta has no token matching `{name}:{token_id}`"
            ))
        })?;

    let evm = token.evm_contract.as_ref().ok_or_else(|| {
        HyperCoreBridgeClientError::InvalidArgument(format!(
            "token `{name}:{token_id}` is not linked to a HyperEVM ERC20"
        ))
    })?;

    let decimals_i32 = i32::from(token.wei_decimals) + i32::from(evm.evm_extra_wei_decimals);
    let decimals = u8::try_from(decimals_i32).map_err(|_| {
        HyperCoreBridgeClientError::Encoding(format!(
            "resolved decimals {decimals_i32} for `{name}:{token_id}` is out of u8 range"
        ))
    })?;

    Ok(ResolvedSpotToken {
        hl_bridge_token: evm.address,
        decimals,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"{
        "universe": [],
        "tokens": [
            {
                "name": "USDC",
                "szDecimals": 8,
                "weiDecimals": 8,
                "index": 0,
                "tokenId": "0xeb62eee3685fc4c43992febcd9e75443",
                "isCanonical": true,
                "evmContract": {
                    "address": "0x0b80659a4076e9e93c7dbe0f10675a16a3e5c206",
                    "evm_extra_wei_decimals": -2
                },
                "fullName": null
            },
            {
                "name": "PURR",
                "szDecimals": 0,
                "weiDecimals": 5,
                "index": 1,
                "tokenId": "0xc4bf3f870c0e9465323c0b6ed28096c2",
                "isCanonical": true,
                "evmContract": null,
                "fullName": null
            }
        ]
    }"#;

    #[test]
    fn parses_real_spot_meta_subset() {
        let meta: SpotMetaResponse = serde_json::from_str(SAMPLE).unwrap();
        assert_eq!(meta.tokens.len(), 2);
        assert_eq!(meta.tokens[0].name, "USDC");
        let usdc_evm = meta.tokens[0].evm_contract.as_ref().unwrap();
        assert_eq!(
            usdc_evm.address,
            "0x0b80659a4076e9e93c7dbe0f10675a16a3e5c206"
                .parse::<Address>()
                .unwrap()
        );
        assert_eq!(usdc_evm.evm_extra_wei_decimals, -2);
        assert!(meta.tokens[1].evm_contract.is_none());
    }

    #[test]
    fn picks_token_and_computes_decimals() {
        let meta: SpotMetaResponse = serde_json::from_str(SAMPLE).unwrap();
        let resolved =
            pick_resolved_token(&meta, "USDC", "0xeb62eee3685fc4c43992febcd9e75443").unwrap();
        assert_eq!(resolved.decimals, 6); // 8 + (-2)
        assert_eq!(
            resolved.hl_bridge_token,
            "0x0b80659a4076e9e93c7dbe0f10675a16a3e5c206"
                .parse::<Address>()
                .unwrap()
        );
    }

    #[test]
    fn picks_token_id_case_insensitive() {
        let meta: SpotMetaResponse = serde_json::from_str(SAMPLE).unwrap();
        let resolved =
            pick_resolved_token(&meta, "USDC", "0xEB62EEE3685FC4C43992FEBCD9E75443").unwrap();
        assert_eq!(resolved.decimals, 6);
    }

    #[test]
    fn rejects_unlinked_token() {
        let meta: SpotMetaResponse = serde_json::from_str(SAMPLE).unwrap();
        let err =
            pick_resolved_token(&meta, "PURR", "0xc4bf3f870c0e9465323c0b6ed28096c2").unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("not linked"), "got: {msg}");
    }

    #[test]
    fn rejects_unknown_token() {
        let meta: SpotMetaResponse = serde_json::from_str(SAMPLE).unwrap();
        let err = pick_resolved_token(&meta, "DOES_NOT_EXIST", "0xdeadbeef").unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("no token matching"), "got: {msg}");
    }

    #[test]
    fn parse_token_identifier_normalizes() {
        let (name, id) = parse_token_identifier("USDC:0xEB62EEE3").unwrap();
        assert_eq!(name, "USDC");
        assert_eq!(id, "0xeb62eee3");

        let (name, id) = parse_token_identifier("PURR:c4bf").unwrap();
        assert_eq!(name, "PURR");
        assert_eq!(id, "0xc4bf");

        assert!(parse_token_identifier("malformed").is_err());
    }

    /// End-to-end check against the live testnet `/info` endpoint:
    /// confirms the real response still parses cleanly into our subset of
    /// fields and that USDC's evmContract / decimal math matches expectations.
    ///
    /// Ignored by default. Run with:
    ///   `cargo test -p hypercore-bridge-client info::tests::testnet_spotmeta_parses -- --ignored --nocapture`
    #[tokio::test]
    #[ignore = "hits Hyperliquid testnet /info"]
    async fn testnet_spotmeta_parses() {
        let response = reqwest::Client::new()
            .post("https://api.hyperliquid-testnet.xyz/info")
            .json(&serde_json::json!({"type": "spotMeta"}))
            .send()
            .await
            .expect("POST failed");
        assert!(
            response.status().is_success(),
            "status: {}",
            response.status()
        );
        let meta: SpotMetaResponse = response.json().await.expect("invalid spotMeta JSON");
        assert!(!meta.tokens.is_empty(), "tokens array empty");

        // USDC is canonical and stable across testnet redeploys — use it as a
        // structural fixture point. Skip the assertion if the testnet topology
        // ever changes (don't want this to break on legitimate evolution).
        let usdc = meta.tokens.iter().find(|t| t.name == "USDC");
        if let Some(usdc) = usdc {
            println!("USDC: {usdc:?}");
            if let Some(evm) = &usdc.evm_contract {
                let resolved = pick_resolved_token(&meta, "USDC", &usdc.token_id).unwrap();
                println!(
                    "Resolved: erc20={:?}, decimals={} (weiDecimals={} + extra={})",
                    resolved.hl_bridge_token,
                    resolved.decimals,
                    usdc.wei_decimals,
                    evm.evm_extra_wei_decimals,
                );
            }
        }
    }
}
