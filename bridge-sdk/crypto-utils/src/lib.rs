use crypto_shared::{derive_epsilon, derive_key};
use k256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use k256::{AffinePoint, EncodedPoint};
use near_crypto::PublicKey;
use near_primitives::types::AccountId;
use std::str::FromStr;

/// NEAR mainnet MPC root public key (signer account `v1.signer`).
pub const MPC_ROOT_PUBLIC_KEY_MAINNET: &str =
    "secp256k1:3tFRbMqmoa6AAALMrEFAYCEoHcqKxeW38YptwowBVBtXK1vo36HDbUWuR6EZmoK4JcH6HDkNMGGqP1ouV7VZUWya";

/// NEAR testnet MPC root public key (signer account `v1.signer-prod.testnet`).
/// Also used for the devnet cluster, which shares the testnet MPC contract.
pub const MPC_ROOT_PUBLIC_KEY_TESTNET: &str =
    "secp256k1:4NfTiv3UsGahebgTaHyD9vF8KYKMBnfd6kh94mK6xv8fGBiJB8TBtFMP5WWXz6B89Ac1fbpzPwAvoyQebemHFwx3";

pub fn derive_address(
    near_account_id: &AccountId,
    path: &str,
    mpc_root_public_key: &str,
) -> [u8; 64] {
    let mpc_key = PublicKey::from_str(mpc_root_public_key).unwrap();

    let mut bytes = vec![0x04];
    bytes.extend(mpc_key.key_data());
    let point = EncodedPoint::from_bytes(bytes).unwrap();
    let mpc_key = AffinePoint::from_encoded_point(&point).unwrap();

    // TODO: remove when mpc starts using `near-sdk-rs` version 5.20.0 or higher
    let epsilon = derive_epsilon(&near_account_id.to_string().parse().unwrap(), path);
    let derived_public_key = derive_key(mpc_key, epsilon);
    let encoded_point = derived_public_key.to_encoded_point(false);
    let slice: &[u8] = &encoded_point.as_bytes()[1..65];

    slice.try_into().unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;

    // Pinned to the value stored in the `omni.bridge.near` mainnet bridge `config`
    // PDA at `2iANpDh96GgithLPTVMZjZFtnbrYBUCLqnEvaytbwTQq` on Solana mainnet — i.e.
    // what NEAR's MPC actually signs `omni.bridge.near` payloads as. Locks the
    // (mainnet root key, derive_epsilon, derive_key) tuple against accidental drift;
    // if this assertion ever fails, every SVM bridge initialized via `svm_initialize`
    // against mainnet will reject NEAR's signatures with `SignatureVerificationFailed`
    // (6001).
    #[test]
    fn derive_address_matches_mainnet_omni_bridge() {
        let derived = derive_address(
            &"omni.bridge.near".parse().unwrap(),
            "bridge-1",
            MPC_ROOT_PUBLIC_KEY_MAINNET,
        );
        let expected: [u8; 64] = hex_literal::hex!(
            "afb94f0268153a7e381646308de7e3ee2c77eb314357ef748016ceace6da9553\
             f25ce6c8d3691b39cf80854a7c377c3a1b9598b0219806140aed2d7bc3f8e04d"
        );
        assert_eq!(derived, expected);
    }

    // Pinned to the value stored in the `omni.n-bridge.testnet` bridge `config`
    // PDA at `81Eece1nhvt1RhJFo7iPci8oJN7TMjihwevH5WA3tk31` on the Solana testnet
    // (devnet RPC) deployment. Same regression guard as the mainnet test, but for
    // the testnet MPC root (signer account `v1.signer-prod.testnet`).
    #[test]
    fn derive_address_matches_testnet_omni_bridge() {
        let derived = derive_address(
            &"omni.n-bridge.testnet".parse().unwrap(),
            "bridge-1",
            MPC_ROOT_PUBLIC_KEY_TESTNET,
        );
        let expected: [u8; 64] = hex_literal::hex!(
            "f378e7100c5c0d62b1e80bf32f8e7e22ef924f309eef1cee4df5f66b2043d862\
             ba882ece34a38d9d6656355f9537058a93b77f3f6503fe0085b5e15aa47e6f7e"
        );
        assert_eq!(derived, expected);
    }
}
