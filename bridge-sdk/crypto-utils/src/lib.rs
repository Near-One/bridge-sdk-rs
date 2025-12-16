use crypto_shared::{derive_epsilon, derive_key};
use ethers::core::k256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use ethers::core::k256::{AffinePoint, EncodedPoint};
use near_crypto::PublicKey;
use near_primitives::types::AccountId;
use std::str::FromStr;

const MPC_KEY: &str = "secp256k1:4NfTiv3UsGahebgTaHyD9vF8KYKMBnfd6kh94mK6xv8fGBiJB8TBtFMP5WWXz6B89Ac1fbpzPwAvoyQebemHFwx3";

pub fn derive_address(near_account_id: &AccountId, path: &str) -> [u8; 64] {
    let mpc_key = PublicKey::from_str(MPC_KEY).unwrap();

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
