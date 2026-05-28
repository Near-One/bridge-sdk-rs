use alloy::primitives::{keccak256, Address, B256, U256};
use alloy::signers::local::PrivateKeySigner;
use alloy::signers::SignerSync;
use alloy::sol_types::SolValue;
use serde::Serialize;

use crate::action::SendToEvmWithDataAction;
use crate::error::{HyperCoreBridgeClientError, Result};

/// EIP-712 type string for `HyperliquidTransaction:SendToEvmWithData`.
///
/// **Inferred** from the JSON shape (GitBook docs llms-full.txt:5837) and the
/// user-signed-action convention in hyperliquid-python-sdk:signing.py:88-119.
/// Hyperliquid's own SDKs do not implement this action; until we validate
/// signer recovery on testnet, treat field order and integer widths as the
/// primary suspects if the L1 rejects with a signature/user-not-found error.
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
