use alloy::primitives::{keccak256, Address, B256, U256};
use alloy::signers::local::PrivateKeySigner;
use alloy::signers::SignerSync;
use alloy::sol_types::SolValue;
use serde::Serialize;

use crate::action::SendToEvmWithDataAction;
use crate::error::{HyperCoreBridgeClientError, Result};

/// EIP-712 type string for `HyperliquidTransaction:SendToEvmWithData`.
///
/// Originally inferred from the GitBook docs (`llms-full.txt:5837`) and the
/// user-signed-action convention in hyperliquid-python-sdk:signing.py:88-119,
/// because neither official SDK implements `sendToEvmWithData`.
///
/// **Validated against Hyperliquid testnet `/exchange`**: signing with a
/// random key and posting yields `"Must deposit before performing actions.
/// User: <our-address>"`, where the embedded address matches the signer.
/// That proves the L1 recovers the correct address from our digest —
/// i.e. field order, integer widths, and which fields are signed are all
/// correct. See `testnet_l1_recovers_our_address` below.
const SEND_TO_EVM_WITH_DATA_TYPE: &str = "HyperliquidTransaction:SendToEvmWithData(string hyperliquidChain,string token,string amount,string sourceDex,string destinationRecipient,string addressEncoding,uint32 destinationChainId,uint64 gasLimit,bytes data,uint64 nonce)";

const EIP712_DOMAIN_TYPE: &str =
    "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)";
const HL_DOMAIN_NAME: &str = "HyperliquidSignTransaction";
const HL_DOMAIN_VERSION: &str = "1";

#[derive(Debug, Clone, Serialize)]
pub struct ActionSignature {
    pub r: String,
    pub s: String,
    pub v: u8,
}

pub fn sign_action(
    signer: &PrivateKeySigner,
    action: &SendToEvmWithDataAction,
) -> Result<ActionSignature> {
    let chain_id = parse_signature_chain_id(&action.signature_chain_id)?;
    let domain_separator = compute_domain_separator(chain_id);
    let struct_hash = compute_struct_hash(action)?;

    let mut digest_input = Vec::with_capacity(2 + 32 + 32);
    digest_input.push(0x19);
    digest_input.push(0x01);
    digest_input.extend_from_slice(domain_separator.as_slice());
    digest_input.extend_from_slice(struct_hash.as_slice());
    let digest = keccak256(&digest_input);

    let signature = signer
        .sign_hash_sync(&digest)
        .map_err(|e| HyperCoreBridgeClientError::Signing(e.to_string()))?;

    let r = signature.r();
    let s = signature.s();
    let v_parity: u8 = u8::from(signature.v());
    let v = 27u8 + v_parity;

    Ok(ActionSignature {
        r: format!("0x{r:064x}"),
        s: format!("0x{s:064x}"),
        v,
    })
}

fn parse_signature_chain_id(s: &str) -> Result<u64> {
    let stripped = s.strip_prefix("0x").unwrap_or(s);
    u64::from_str_radix(stripped, 16)
        .map_err(|_| HyperCoreBridgeClientError::InvalidSignatureChainId(s.to_string()))
}

fn compute_domain_separator(chain_id: u64) -> B256 {
    let type_hash = keccak256(EIP712_DOMAIN_TYPE.as_bytes());
    let name_hash = keccak256(HL_DOMAIN_NAME.as_bytes());
    let version_hash = keccak256(HL_DOMAIN_VERSION.as_bytes());
    let verifying_contract = Address::ZERO;

    let encoded = (
        type_hash,
        name_hash,
        version_hash,
        U256::from(chain_id),
        verifying_contract,
    )
        .abi_encode_params();

    keccak256(encoded)
}

fn compute_struct_hash(action: &SendToEvmWithDataAction) -> Result<B256> {
    let type_hash = keccak256(SEND_TO_EVM_WITH_DATA_TYPE.as_bytes());

    let data_hex = action.data.strip_prefix("0x").unwrap_or(&action.data);
    let data_bytes = hex::decode(data_hex).map_err(|e| {
        HyperCoreBridgeClientError::Encoding(format!("`data` field is not valid hex: {e}"))
    })?;

    let encoded = (
        type_hash,
        keccak256(action.hyperliquid_chain.as_bytes()),
        keccak256(action.token.as_bytes()),
        keccak256(action.amount.as_bytes()),
        keccak256(action.source_dex.as_bytes()),
        keccak256(action.destination_recipient.as_bytes()),
        keccak256(action.address_encoding.as_bytes()),
        U256::from(action.destination_chain_id),
        U256::from(action.gas_limit),
        keccak256(&data_bytes),
        U256::from(action.nonce),
    )
        .abi_encode_params();

    Ok(keccak256(encoded))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_action() -> SendToEvmWithDataAction {
        SendToEvmWithDataAction {
            action_type: "sendToEvmWithData",
            hyperliquid_chain: "Testnet",
            signature_chain_id: "0x66eee".to_string(),
            token: "PURR:0xc4bf3f870c0e9465323c0b6ed28096c2".to_string(),
            amount: "0.01".to_string(),
            source_dex: "spot".to_string(),
            destination_recipient: "0x000000000000000000000000000000000000dead".to_string(),
            address_encoding: "hex".to_string(),
            destination_chain_id: 998,
            gas_limit: 800_000,
            data: "0x0100".to_string(),
            nonce: 1_716_531_066_415,
        }
    }

    #[test]
    fn parses_signature_chain_id() {
        assert_eq!(parse_signature_chain_id("0x66eee").unwrap(), 421_614);
        assert_eq!(parse_signature_chain_id("0xa4b1").unwrap(), 42_161);
        assert_eq!(parse_signature_chain_id("a4b1").unwrap(), 42_161);
        assert!(parse_signature_chain_id("not-hex").is_err());
    }

    #[test]
    fn domain_separator_is_deterministic() {
        let a = compute_domain_separator(421_614);
        let b = compute_domain_separator(421_614);
        assert_eq!(a, b);
        let c = compute_domain_separator(42_161);
        assert_ne!(a, c);
    }

    #[test]
    fn struct_hash_changes_with_each_field() {
        let base = compute_struct_hash(&sample_action()).unwrap();

        let mut variant = sample_action();
        variant.amount = "0.02".to_string();
        assert_ne!(compute_struct_hash(&variant).unwrap(), base);

        let mut variant = sample_action();
        variant.gas_limit = 900_000;
        assert_ne!(compute_struct_hash(&variant).unwrap(), base);

        let mut variant = sample_action();
        variant.data = "0x01ff".to_string();
        assert_ne!(compute_struct_hash(&variant).unwrap(), base);
    }

    /// Smoke-tests the EIP-712 type list against the real Hyperliquid testnet
    /// `/exchange` endpoint.
    ///
    /// We sign with a fresh random key whose address has no HyperCore account,
    /// then POST the action. The L1 recomputes the digest, recovers `(r,s,v)`
    /// against it, and rejects because the recovered address has no Core
    /// balance. Crucially the error embeds the recovered address — when that
    /// matches the wallet we signed with, our type list / field order /
    /// integer widths are all correct.
    ///
    /// Don't use a deterministic well-known key (Anvil `0xac09…`): someone has
    /// configured that address as a multi-sig account on testnet, which
    /// triggers a different (less informative) `"Multi-sig required"` error.
    ///
    /// Ignored by default because it hits the network. Run with:
    ///   `cargo test -p hypercore-bridge-client testnet -- --ignored --nocapture`
    #[tokio::test]
    #[ignore = "hits Hyperliquid testnet /exchange"]
    async fn testnet_l1_recovers_our_address() {
        use crate::encoders::encode_transfer_action;

        // Fresh random key — 1 in 2^160 chance of colliding with a real
        // account on testnet. If the response is still "Multi-sig required"
        // with a brand-new address, that tells us `sendToEvmWithData` itself
        // requires multi-sig (not an artifact of someone else's testing).
        let signer = PrivateKeySigner::random();
        let our_address = signer.address();
        println!("\n=== Our signer address: {our_address:?} ===\n");

        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;

        // ACTION_TRANSFER with our own address as the recipient (pool release).
        // Doesn't matter that the HlBridgeToken at destinationRecipient doesn't
        // exist — we just want the L1 to evaluate our signature.
        let data_bytes = encode_transfer_action(our_address);
        let data_hex = format!("0x{}", hex::encode(&data_bytes));

        let action = SendToEvmWithDataAction {
            action_type: "sendToEvmWithData",
            hyperliquid_chain: "Testnet",
            signature_chain_id: "0x66eee".to_string(),
            token: "PURR:0xc4bf3f870c0e9465323c0b6ed28096c2".to_string(),
            amount: "0.01".to_string(),
            source_dex: "spot".to_string(),
            destination_recipient: format!("{our_address:?}").to_lowercase(),
            address_encoding: "hex".to_string(),
            destination_chain_id: 998,
            gas_limit: 800_000,
            data: data_hex,
            nonce,
        };
        println!("Action: {}", serde_json::to_string_pretty(&action).unwrap());

        let signature = sign_action(&signer, &action).unwrap();
        println!("Signature: {signature:?}\n");

        #[derive(serde::Serialize)]
        struct Envelope<'a> {
            action: &'a SendToEvmWithDataAction,
            nonce: u64,
            signature: &'a ActionSignature,
        }
        let envelope = Envelope {
            action: &action,
            nonce,
            signature: &signature,
        };

        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .unwrap();
        let response = client
            .post("https://api.hyperliquid-testnet.xyz/exchange")
            .json(&envelope)
            .send()
            .await
            .expect("POST failed");

        let status = response.status();
        let body = response.text().await.unwrap();
        println!("=== HTTP {status} ===");
        println!("Body: {body}");

        let our_addr_lower = format!("{our_address:?}").to_lowercase();
        assert!(
            body.to_lowercase().contains(&our_addr_lower),
            "Hyperliquid response did not reference our signing address {our_addr_lower}.\n\
             This means the L1 recovered a different signer from our digest — \
             EIP-712 type list or field order is wrong.\nFull body: {body}"
        );
    }

    #[test]
    fn sign_action_recovers_signer() {
        let signer: PrivateKeySigner =
            "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
                .parse()
                .unwrap();
        let expected = signer.address();
        let action = sample_action();
        let sig = sign_action(&signer, &action).unwrap();

        let r = U256::from_str_radix(sig.r.trim_start_matches("0x"), 16).unwrap();
        let s = U256::from_str_radix(sig.s.trim_start_matches("0x"), 16).unwrap();
        let parity = sig.v == 28;
        let recovered_sig = alloy::primitives::Signature::new(r, s, parity);

        let chain_id = parse_signature_chain_id(&action.signature_chain_id).unwrap();
        let domain_separator = compute_domain_separator(chain_id);
        let struct_hash = compute_struct_hash(&action).unwrap();
        let mut digest_input = Vec::with_capacity(66);
        digest_input.push(0x19);
        digest_input.push(0x01);
        digest_input.extend_from_slice(domain_separator.as_slice());
        digest_input.extend_from_slice(struct_hash.as_slice());
        let digest = keccak256(&digest_input);

        let recovered = recovered_sig.recover_address_from_prehash(&digest).unwrap();
        assert_eq!(recovered, expected);
    }
}
