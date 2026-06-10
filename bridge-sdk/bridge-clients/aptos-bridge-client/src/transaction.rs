//! Minimal Aptos transaction model and BCS encoding needed to sign and submit
//! entry-function calls. Mirrors the layout of `aptos-core`'s
//! `aptos_types::transaction` so the BCS bytes (and therefore the signing
//! message) are byte-identical, without depending on the heavy `aptos-sdk`.

use ed25519_dalek::{Signer, SigningKey};
use serde::Serialize;
use sha3::{Digest, Sha3_256};

/// A 32-byte Aptos account / object address. Serializes as 32 raw bytes (no
/// length prefix), matching `aptos_types::account_address::AccountAddress`.
#[derive(Clone, Copy, Debug, Serialize)]
pub struct AccountAddress(pub [u8; 32]);

/// `aptos_types::transaction::Module`-id: the on-chain module a call targets.
#[derive(Clone, Debug, Serialize)]
pub struct ModuleId {
    pub address: AccountAddress,
    /// Module name as a Move `Identifier` (BCS string).
    pub name: String,
}

/// Move type arguments. The omni-bridge entry functions take none, so this is
/// always empty; the variants exist only to give the empty `Vec` a faithful
/// element type and are never constructed.
#[allow(dead_code)]
#[derive(Clone, Debug, Serialize)]
pub enum TypeTag {
    Bool,
    U8,
    U64,
    U128,
    Address,
    Signer,
    Vector(Box<TypeTag>),
    Struct(Box<StructTag>),
    U16,
    U32,
    U256,
}

#[allow(dead_code)]
#[derive(Clone, Debug, Serialize)]
pub struct StructTag {
    pub address: AccountAddress,
    pub module: String,
    pub name: String,
    pub type_args: Vec<TypeTag>,
}

/// `aptos_types::transaction::EntryFunction`. Each entry in `args` is the
/// independently BCS-encoded bytes of one Move argument.
#[derive(Clone, Debug, Serialize)]
pub struct EntryFunction {
    pub module: ModuleId,
    pub function: String,
    pub ty_args: Vec<TypeTag>,
    pub args: Vec<Vec<u8>>,
}

/// `aptos_types::transaction::TransactionPayload`. Only the `EntryFunction`
/// variant (index 2) is used; `Script`/`ModuleBundle` exist solely to pin the
/// BCS variant index of `EntryFunction` to 2.
#[derive(Clone, Debug, Serialize)]
pub enum TransactionPayload {
    #[allow(dead_code)]
    Script,
    #[allow(dead_code)]
    ModuleBundle,
    EntryFunction(EntryFunction),
}

/// `aptos_types::transaction::RawTransaction`. Field order is significant: it
/// defines the BCS bytes that get signed.
#[derive(Clone, Debug, Serialize)]
pub struct RawTransaction {
    pub sender: AccountAddress,
    pub sequence_number: u64,
    pub payload: TransactionPayload,
    pub max_gas_amount: u64,
    pub gas_unit_price: u64,
    pub expiration_timestamp_secs: u64,
    pub chain_id: u8,
}

/// `aptos_types::transaction::authenticator::TransactionAuthenticator`. Only
/// the single-signer Ed25519 variant (index 0) is used. `public_key` and
/// `signature` serialize as length-prefixed byte strings, exactly like
/// aptos's `Ed25519PublicKey`/`Ed25519Signature`.
#[derive(Clone, Debug, Serialize)]
pub enum TransactionAuthenticator {
    Ed25519 {
        public_key: Vec<u8>,
        signature: Vec<u8>,
    },
}

#[derive(Clone, Debug, Serialize)]
pub struct SignedTransaction {
    pub raw_txn: RawTransaction,
    pub authenticator: TransactionAuthenticator,
}

/// The salt aptos prepends to a `RawTransaction`'s BCS bytes before signing,
/// `sha3_256("APTOS::RawTransaction")`.
fn raw_transaction_signing_salt() -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(b"APTOS::RawTransaction");
    hasher.finalize().into()
}

impl RawTransaction {
    /// The bytes that are signed: `sha3_256("APTOS::RawTransaction") || bcs(self)`.
    pub fn signing_message(&self) -> Result<Vec<u8>, bcs::Error> {
        let mut message = raw_transaction_signing_salt().to_vec();
        message.extend(bcs::to_bytes(self)?);
        Ok(message)
    }

    /// Sign with an Ed25519 key and wrap into a submittable `SignedTransaction`.
    pub fn sign(self, signing_key: &SigningKey) -> Result<SignedTransaction, bcs::Error> {
        let message = self.signing_message()?;
        let signature = signing_key.sign(&message);
        Ok(SignedTransaction {
            raw_txn: self,
            authenticator: TransactionAuthenticator::Ed25519 {
                public_key: signing_key.verifying_key().to_bytes().to_vec(),
                signature: signature.to_bytes().to_vec(),
            },
        })
    }
}

/// Helpers that BCS-encode a single Move argument for `EntryFunction.args`.
pub mod args {
    pub fn address(addr: [u8; 32]) -> Vec<u8> {
        bcs::to_bytes(&super::AccountAddress(addr)).expect("bcs address")
    }
    pub fn u8(v: u8) -> Vec<u8> {
        bcs::to_bytes(&v).expect("bcs u8")
    }
    pub fn u64(v: u64) -> Vec<u8> {
        bcs::to_bytes(&v).expect("bcs u64")
    }
    pub fn u128(v: u128) -> Vec<u8> {
        bcs::to_bytes(&v).expect("bcs u128")
    }
    pub fn string(v: &str) -> Vec<u8> {
        bcs::to_bytes(&v.to_string()).expect("bcs string")
    }
    pub fn bytes(v: &[u8]) -> Vec<u8> {
        bcs::to_bytes(&v.to_vec()).expect("bcs vector<u8>")
    }
    pub fn option_string(v: Option<&str>) -> Vec<u8> {
        bcs::to_bytes(&v).expect("bcs option<string>")
    }
    pub fn option_bytes(v: Option<&[u8]>) -> Vec<u8> {
        bcs::to_bytes(&v).expect("bcs option<vector<u8>>")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_entry(args: Vec<Vec<u8>>) -> EntryFunction {
        EntryFunction {
            module: ModuleId {
                address: AccountAddress([0xCA; 32]),
                name: "omni_bridge".to_string(),
            },
            function: "log_metadata".to_string(),
            ty_args: Vec::new(),
            args,
        }
    }

    #[test]
    fn bcs_primitive_args_are_little_endian_and_length_prefixed() {
        assert_eq!(args::u64(1), vec![1, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(
            args::u128(1),
            vec![1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        );
        assert_eq!(args::u8(7), vec![7]);
        // String / vector<u8>: ULEB128 length prefix + bytes.
        assert_eq!(args::string("hi"), vec![2, b'h', b'i']);
        assert_eq!(args::bytes(&[0xde, 0xad]), vec![2, 0xde, 0xad]);
        // Option: 0x00 = None, 0x01 + value = Some.
        assert_eq!(args::option_string(None), vec![0]);
        assert_eq!(args::option_string(Some("a")), vec![1, 1, b'a']);
        assert_eq!(args::option_bytes(None), vec![0]);
    }

    #[test]
    fn address_arg_is_32_raw_bytes() {
        let bytes = args::address([0xAB; 32]);
        assert_eq!(bytes, vec![0xAB; 32]); // no length prefix
    }

    #[test]
    fn entry_function_payload_uses_variant_index_2() {
        let payload =
            TransactionPayload::EntryFunction(sample_entry(vec![args::address([0x01; 32])]));
        let bytes = bcs::to_bytes(&payload).unwrap();
        // First byte is the ULEB128 enum variant index for EntryFunction.
        assert_eq!(bytes[0], 2);
    }

    #[test]
    fn signing_message_is_salt_prefixed() {
        let raw = RawTransaction {
            sender: AccountAddress([0x11; 32]),
            sequence_number: 0,
            payload: TransactionPayload::EntryFunction(sample_entry(Vec::new())),
            max_gas_amount: 100_000,
            gas_unit_price: 100,
            expiration_timestamp_secs: 1_700_000_000,
            chain_id: 2,
        };
        let message = raw.signing_message().unwrap();
        let salt = raw_transaction_signing_salt();
        assert_eq!(&message[..32], &salt);
        assert_eq!(&message[32..], &bcs::to_bytes(&raw).unwrap()[..]);
    }

    #[test]
    fn signed_transaction_roundtrips_through_bcs() {
        let signing_key = SigningKey::from_bytes(&[7u8; 32]);
        let raw = RawTransaction {
            sender: AccountAddress([0x22; 32]),
            sequence_number: 3,
            payload: TransactionPayload::EntryFunction(sample_entry(vec![args::u64(9)])),
            max_gas_amount: 100_000,
            gas_unit_price: 100,
            expiration_timestamp_secs: 1_700_000_000,
            chain_id: 1,
        };
        let signed = raw.sign(&signing_key).unwrap();
        // Authenticator is Ed25519 (variant 0): pubkey(32) + sig(64), each
        // length-prefixed. Serialization must not panic and must be stable.
        let bytes = bcs::to_bytes(&signed).unwrap();
        assert!(!bytes.is_empty());
        let TransactionAuthenticator::Ed25519 {
            public_key,
            signature,
        } = &signed.authenticator;
        assert_eq!(public_key.len(), 32);
        assert_eq!(signature.len(), 64);
    }

    /// Validates our hand-rolled `RawTransaction` BCS + signing-message salt
    /// against a live Aptos fullnode's `encode_submission` (which BCS-encodes
    /// the transaction server-side using aptos-core). Uses the always-present
    /// `0x1::aptos_account::transfer` entry function — the encoding path is the
    /// same one the bridge entry functions use. Ignored by default (network).
    #[tokio::test]
    #[ignore = "requires network access to the Aptos testnet fullnode"]
    async fn signing_message_matches_node_encode_submission() {
        const NODE: &str = "https://fullnode.testnet.aptoslabs.com/v1";

        let mut sender = [0u8; 32];
        sender[31] = 0x1;
        let mut dest = [0u8; 32];
        dest[31] = 0x2;

        let raw = RawTransaction {
            sender: AccountAddress(sender),
            sequence_number: 0,
            payload: TransactionPayload::EntryFunction(EntryFunction {
                module: ModuleId {
                    address: AccountAddress(sender), // 0x1
                    name: "aptos_account".to_string(),
                },
                function: "transfer".to_string(),
                ty_args: Vec::new(),
                args: vec![args::address(dest), args::u64(1000)],
            }),
            max_gas_amount: 100_000,
            gas_unit_price: 100,
            expiration_timestamp_secs: 1_700_000_000,
            chain_id: 2, // testnet
        };
        let ours = format!("0x{}", hex::encode(raw.signing_message().unwrap()));

        let body = serde_json::json!({
            "sender": "0x1",
            "sequence_number": "0",
            "max_gas_amount": "100000",
            "gas_unit_price": "100",
            "expiration_timestamp_secs": "1700000000",
            "payload": {
                "type": "entry_function_payload",
                "function": "0x1::aptos_account::transfer",
                "type_arguments": [],
                "arguments": ["0x2", "1000"],
            },
        });
        let theirs: String = reqwest::Client::new()
            .post(format!("{NODE}/transactions/encode_submission"))
            .json(&body)
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();

        assert_eq!(ours, theirs, "BCS signing message diverged from aptos-core");
    }
}
