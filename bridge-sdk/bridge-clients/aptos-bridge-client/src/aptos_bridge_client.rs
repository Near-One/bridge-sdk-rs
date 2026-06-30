use std::collections::BTreeMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ed25519_dalek::SigningKey;
use near_mpc_contract_interface::types::AptosFinality;
use omni_types::near_events::OmniBridgeEvent;
use omni_types::OmniAddress;

use crate::error::{AptosBridgeClientError, Result};
use crate::rest::{CommittedTransaction, TransactionEvent};
use crate::transaction::{args, EntryFunction, ModuleId, RawTransaction, TransactionPayload};

pub use builder::AptosBridgeClientBuilder;

mod builder;
pub mod error;
mod rest;
mod transaction;

/// Move module that hosts the bridge entry functions.
const MODULE_NAME: &str = "omni_bridge";
/// Generous upper bound; omni-bridge entry functions cost well under this.
const MAX_GAS_AMOUNT: u64 = 100_000;
/// How long a submitted transaction stays valid for inclusion.
const TX_EXPIRATION_SECS: u64 = 60;
/// Receipt polling after submission.
const MAX_POLL_RETRIES: u32 = 30;
const POLL_INTERVAL: Duration = Duration::from_secs(2);

/// An Ed25519 signing identity for submitting Aptos transactions.
pub struct AptosAccount {
    pub(crate) signing_key: SigningKey,
    pub(crate) address: [u8; 32],
}

/// Aptos bridge client for the `omni_bridge` Move package.
pub struct AptosBridgeClient {
    pub(crate) http_client: reqwest::Client,
    pub(crate) base_url: String,
    pub(crate) account: Option<AptosAccount>,
    pub(crate) omni_bridge_address: Option<[u8; 32]>,
    pub(crate) mpc_finality: Option<AptosFinality>,
}

/// A decoded `InitTransfer` event, used to derive NEAR storage-deposit actions.
#[derive(Debug)]
pub struct AptosInitTransferEvent {
    pub sender: [u8; 32],
    pub token_address: [u8; 32],
    pub origin_nonce: u64,
    pub amount: u128,
    pub fee: u128,
    pub native_fee: u128,
    pub recipient: String,
    pub message: String,
}

/// A raw bridge event with the metadata the MPC foreign-tx validation payload
/// needs. `data` and `account_address` are already in the canonical form the
/// MPC node reconstructs (see `normalize_event_data` / left-padded address).
#[derive(Debug)]
pub struct AptosEventLog {
    pub account_address: [u8; 32],
    pub sequence_number: u64,
    pub type_tag: String,
    pub data: String,
    pub event_index: u64,
}

impl AptosBridgeClient {
    fn account(&self) -> Result<&AptosAccount> {
        self.account.as_ref().ok_or_else(|| {
            AptosBridgeClientError::ConfigError(
                "Aptos private key / account address is not set".to_string(),
            )
        })
    }

    fn omni_bridge_address(&self) -> Result<[u8; 32]> {
        self.omni_bridge_address.ok_or_else(|| {
            AptosBridgeClientError::ConfigError("OmniBridge address is not set".to_string())
        })
    }

    fn bridge_module(&self) -> Result<ModuleId> {
        Ok(ModuleId {
            address: transaction::AccountAddress(self.omni_bridge_address()?),
            name: MODULE_NAME.to_string(),
        })
    }

    /// Build, sign, and submit an `omni_bridge` entry-function call, then wait
    /// for it to commit. Returns the transaction hash (`0x`-prefixed).
    async fn submit_entry_function(&self, function: &str, args: Vec<Vec<u8>>) -> Result<String> {
        let account = self.account()?;
        let module = self.bridge_module()?;

        let sender_hex = format!("0x{}", hex::encode(account.address));
        let sequence_number =
            rest::get_account_sequence_number(&self.http_client, &self.base_url, &sender_hex)
                .await?;
        let chain_id = rest::get_ledger_info(&self.http_client, &self.base_url)
            .await?
            .chain_id;
        let gas_unit_price = rest::estimate_gas_price(&self.http_client, &self.base_url).await?;

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| AptosBridgeClientError::TransactionError(format!("system clock: {e}")))?
            .as_secs();

        let raw_txn = RawTransaction {
            sender: transaction::AccountAddress(account.address),
            sequence_number,
            payload: TransactionPayload::EntryFunction(EntryFunction {
                module,
                function: function.to_string(),
                ty_args: Vec::new(),
                args,
            }),
            max_gas_amount: MAX_GAS_AMOUNT,
            gas_unit_price,
            expiration_timestamp_secs: now + TX_EXPIRATION_SECS,
            chain_id,
        };

        let signed = raw_txn.sign(&account.signing_key).map_err(|e| {
            AptosBridgeClientError::TransactionError(format!("failed to sign transaction: {e}"))
        })?;
        let signed_bytes = bcs::to_bytes(&signed).map_err(|e| {
            AptosBridgeClientError::TransactionError(format!(
                "failed to serialize signed transaction: {e}"
            ))
        })?;

        let tx_hash =
            rest::submit_bcs_transaction(&self.http_client, &self.base_url, signed_bytes).await?;
        tracing::info!(tx_hash = %tx_hash, "Submitted Aptos transaction");
        self.wait_for_committed(&tx_hash).await?;
        Ok(tx_hash)
    }

    async fn wait_for_committed(&self, tx_hash: &str) -> Result<()> {
        for _ in 0..MAX_POLL_RETRIES {
            if let Some(tx) =
                rest::get_transaction_by_hash(&self.http_client, &self.base_url, tx_hash).await?
            {
                match tx.success {
                    Some(true) => return Ok(()),
                    Some(false) => {
                        return Err(AptosBridgeClientError::TransactionError(format!(
                            "transaction {tx_hash} failed: {}",
                            tx.vm_status.unwrap_or_default()
                        )));
                    }
                    None => {}
                }
            }
            tokio::time::sleep(POLL_INTERVAL).await;
        }
        Err(AptosBridgeClientError::TransactionError(format!(
            "transaction {tx_hash} was not committed after {} seconds",
            u64::from(MAX_POLL_RETRIES) * POLL_INTERVAL.as_secs()
        )))
    }

    /// Log token metadata on the Aptos `omni_bridge` contract (permissionless).
    #[tracing::instrument(skip_all, name = "APTOS LOG METADATA")]
    pub async fn log_metadata(&self, token: [u8; 32]) -> Result<String> {
        self.submit_entry_function("log_metadata", vec![args::address(token)])
            .await
    }

    /// Deploy a bridged token on Aptos using a `LogMetadataEvent` from NEAR.
    #[tracing::instrument(skip_all, name = "APTOS DEPLOY TOKEN")]
    pub async fn deploy_token(&self, event: OmniBridgeEvent) -> Result<String> {
        let OmniBridgeEvent::LogMetadataEvent {
            signature,
            metadata_payload,
        } = event
        else {
            return Err(AptosBridgeClientError::InvalidArgument(format!(
                "Expected LogMetadataEvent but got {event:?}"
            )));
        };

        let (rs, v) = split_signature(&signature.to_bytes())?;

        self.submit_entry_function(
            "deploy_token",
            vec![
                args::bytes(&rs),
                args::u8(v),
                args::string(&metadata_payload.token),
                args::string(&metadata_payload.name),
                args::string(&metadata_payload.symbol),
                args::u8(metadata_payload.decimals),
            ],
        )
        .await
    }

    /// Initiate a transfer from Aptos to another chain (user-signed outbound).
    #[tracing::instrument(skip_all, name = "APTOS INIT TRANSFER")]
    pub async fn init_transfer(
        &self,
        token: [u8; 32],
        amount: u128,
        fee: u128,
        native_fee: u128,
        recipient: String,
        message: Vec<u8>,
    ) -> Result<String> {
        self.submit_entry_function(
            "init_transfer",
            vec![
                args::address(token),
                args::u128(amount),
                args::u128(fee),
                args::u128(native_fee),
                args::string(&recipient),
                args::bytes(&message),
            ],
        )
        .await
    }

    /// Finalize a transfer to Aptos using a `SignTransferEvent` from NEAR.
    #[tracing::instrument(skip_all, name = "APTOS FIN TRANSFER")]
    pub async fn fin_transfer(&self, event: OmniBridgeEvent) -> Result<String> {
        let OmniBridgeEvent::SignTransferEvent {
            message_payload,
            signature,
        } = event
        else {
            return Err(AptosBridgeClientError::InvalidArgument(format!(
                "Expected SignTransferEvent but got {event:?}"
            )));
        };

        let (rs, v) = split_signature(&signature.to_bytes())?;
        let token = omni_address_to_aptos(&message_payload.token_address)?;
        let recipient = omni_address_to_aptos(&message_payload.recipient)?;
        let amount: u128 = message_payload.amount.into();
        let fee_recipient = message_payload.fee_recipient.map(|a| a.to_string());
        let message = if message_payload.message.is_empty() {
            None
        } else {
            Some(message_payload.message)
        };

        self.submit_entry_function(
            "fin_transfer",
            vec![
                args::bytes(&rs),
                args::u8(v),
                args::u64(message_payload.destination_nonce),
                args::u8(u8::from(message_payload.transfer_id.origin_chain)),
                args::u64(message_payload.transfer_id.origin_nonce),
                args::address(token),
                args::u128(amount),
                args::address(recipient),
                args::option_string(fee_recipient.as_deref()),
                args::option_bytes(message.as_deref()),
            ],
        )
        .await
    }

    /// Whether a transfer with the given destination nonce has been finalised.
    pub async fn is_transfer_finalised(&self, nonce: u64) -> Result<bool> {
        let bridge = self.omni_bridge_address()?;
        let function = format!(
            "0x{}::{MODULE_NAME}::is_transfer_finalised",
            hex::encode(bridge)
        );
        let result = rest::view(
            &self.http_client,
            &self.base_url,
            &function,
            Vec::new(),
            vec![serde_json::json!(nonce.to_string())],
        )
        .await?;
        result
            .first()
            .and_then(serde_json::Value::as_bool)
            .ok_or_else(|| {
                AptosBridgeClientError::BlockchainDataError(
                    "is_transfer_finalised view returned no boolean".to_string(),
                )
            })
    }

    /// Returns the configured MPC finality level for this chain.
    pub fn mpc_finality(&self) -> Result<AptosFinality> {
        self.mpc_finality.clone().ok_or_else(|| {
            AptosBridgeClientError::ConfigError("MPC finality is not configured".to_string())
        })
    }

    /// Verifies that `tx_hash` has reached the configured MPC finality level
    /// and returns it for embedding in the MPC sign payload. For Aptos,
    /// `Committed` means the transaction carries a successful execution result.
    pub async fn check_mpc_finality(&self, tx_hash: &str) -> Result<AptosFinality> {
        let finality = self.mpc_finality()?;
        match rest::get_transaction_by_hash(&self.http_client, &self.base_url, tx_hash).await? {
            Some(tx) => match tx.success {
                Some(true) => Ok(finality),
                Some(false) => Err(AptosBridgeClientError::TransactionError(format!(
                    "transaction {tx_hash} failed: {}",
                    tx.vm_status.unwrap_or_default()
                ))),
                None => Err(AptosBridgeClientError::MpcFinalityNotReached),
            },
            None => Err(AptosBridgeClientError::MpcFinalityNotReached),
        }
    }

    /// Decode the `InitTransfer` event from a transaction.
    pub async fn get_transfer_event(&self, tx_hash: &str) -> Result<AptosInitTransferEvent> {
        let tx = self.fetch_committed(tx_hash).await?;
        let (_, event) = find_bridge_event(&tx, self.omni_bridge_address()?, "InitTransfer")?;
        parse_init_transfer_event(&event.data)
    }

    /// Raw `InitTransfer` log with metadata for MPC proof construction.
    pub async fn get_init_transfer_log(&self, tx_hash: &str) -> Result<AptosEventLog> {
        self.get_event_log(tx_hash, "InitTransfer").await
    }

    /// Raw `DeployToken` log with metadata for MPC proof construction.
    pub async fn get_deploy_token_log(&self, tx_hash: &str) -> Result<AptosEventLog> {
        self.get_event_log(tx_hash, "DeployToken").await
    }

    /// Raw `FinTransfer` log with metadata for MPC proof construction.
    pub async fn get_fin_transfer_log(&self, tx_hash: &str) -> Result<AptosEventLog> {
        self.get_event_log(tx_hash, "FinTransfer").await
    }

    /// Raw `LogMetadata` log with metadata for MPC proof construction.
    pub async fn get_log_metadata_log(&self, tx_hash: &str) -> Result<AptosEventLog> {
        self.get_event_log(tx_hash, "LogMetadata").await
    }

    async fn fetch_committed(&self, tx_hash: &str) -> Result<CommittedTransaction> {
        rest::get_transaction_by_hash(&self.http_client, &self.base_url, tx_hash)
            .await?
            .ok_or_else(|| {
                AptosBridgeClientError::BlockchainDataError(format!(
                    "transaction {tx_hash} not found"
                ))
            })
    }

    async fn get_event_log(&self, tx_hash: &str, event_name: &str) -> Result<AptosEventLog> {
        let bridge = self.omni_bridge_address()?;
        let tx = self.fetch_committed(tx_hash).await?;
        let (event_index, event) = find_bridge_event(&tx, bridge, event_name)?;

        let account_address = builder::parse_address(&event.guid.account_address).map_err(|e| {
            AptosBridgeClientError::BlockchainDataError(format!(
                "invalid event account_address: {e}"
            ))
        })?;
        let sequence_number = event.sequence_number.parse().map_err(|e| {
            AptosBridgeClientError::BlockchainDataError(format!(
                "invalid event sequence_number {:?}: {e}",
                event.sequence_number
            ))
        })?;

        Ok(AptosEventLog {
            account_address,
            sequence_number,
            type_tag: event.event_type.clone(),
            data: normalize_event_data(&event.data),
            event_index: u64::try_from(event_index).map_err(|_| {
                AptosBridgeClientError::BlockchainDataError("event index exceeds u64".to_string())
            })?,
        })
    }
}

/// Parse an Aptos address from hex (0x-prefixed, short forms left-padded to 32
/// bytes). Exposed so callers can turn a config/CLI address string into the
/// 32-byte form the entry-function helpers expect.
pub fn parse_account_address(s: &str) -> std::result::Result<[u8; 32], String> {
    builder::parse_address(s)
}

/// Split a 65-byte Ethereum-style signature into `(r||s, v)`.
fn split_signature(sig: &[u8]) -> Result<(Vec<u8>, u8)> {
    let sig: [u8; 65] = sig.try_into().map_err(|_| {
        AptosBridgeClientError::InvalidArgument("Signature must be 65 bytes".to_string())
    })?;
    Ok((sig[..64].to_vec(), sig[64]))
}

fn omni_address_to_aptos(address: &OmniAddress) -> Result<[u8; 32]> {
    match address {
        OmniAddress::Aptos(h256) => Ok(h256.0),
        other => Err(AptosBridgeClientError::InvalidArgument(format!(
            "Expected Aptos address but got {other:?}"
        ))),
    }
}

/// Split a Move event type tag `0xaddr::module::Struct` into its parts.
fn parse_event_type(event_type: &str) -> Option<(&str, &str, &str)> {
    let mut parts = event_type.splitn(3, "::");
    let address = parts.next()?;
    let module = parts.next()?;
    let name = parts.next()?;
    Some((address, module, name))
}

/// Find the `omni_bridge::{event_name}` event emitted by `bridge`, with its
/// index in the transaction's `events` array.
fn find_bridge_event<'a>(
    tx: &'a CommittedTransaction,
    bridge: [u8; 32],
    event_name: &str,
) -> Result<(usize, &'a TransactionEvent)> {
    tx.events
        .iter()
        .enumerate()
        .find(|(_, event)| {
            parse_event_type(&event.event_type).is_some_and(|(address, module, name)| {
                module == MODULE_NAME
                    && name == event_name
                    && builder::parse_address(address).is_ok_and(|addr| addr == bridge)
            })
        })
        .ok_or_else(|| {
            AptosBridgeClientError::BlockchainDataError(format!(
                "{event_name} event not found in transaction {}",
                tx.hash
            ))
        })
}

fn parse_init_transfer_event(data: &serde_json::Value) -> Result<AptosInitTransferEvent> {
    let str_field = |key: &str| -> Result<&str> {
        data.get(key)
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| {
                AptosBridgeClientError::BlockchainDataError(format!(
                    "InitTransfer event missing string field {key}"
                ))
            })
    };
    let address = |key: &str| -> Result<[u8; 32]> {
        builder::parse_address(str_field(key)?).map_err(|e| {
            AptosBridgeClientError::BlockchainDataError(format!("InitTransfer {key}: {e}"))
        })
    };
    let u64_field = |key: &str| -> Result<u64> {
        str_field(key)?.parse().map_err(|e| {
            AptosBridgeClientError::BlockchainDataError(format!("InitTransfer {key}: {e}"))
        })
    };
    let u128_field = |key: &str| -> Result<u128> {
        str_field(key)?.parse().map_err(|e| {
            AptosBridgeClientError::BlockchainDataError(format!("InitTransfer {key}: {e}"))
        })
    };

    Ok(AptosInitTransferEvent {
        sender: address("sender")?,
        token_address: address("token_address")?,
        origin_nonce: u64_field("origin_nonce")?,
        amount: u128_field("amount")?,
        fee: u128_field("fee")?,
        native_fee: u128_field("native_fee")?,
        recipient: str_field("recipient")?.to_string(),
        message: decode_message(str_field("message")?),
    })
}

/// Decode an event `vector<u8>` field (`0x…` hex) to text. Bridge messages
/// carry UTF-8; keep the raw hex string if the bytes aren't valid UTF-8.
fn decode_message(hex_str: &str) -> String {
    let stripped = hex_str.strip_prefix("0x").unwrap_or(hex_str);
    if stripped.is_empty() {
        return String::new();
    }
    hex::decode(stripped)
        .ok()
        .and_then(|bytes| String::from_utf8(bytes).ok())
        .unwrap_or_else(|| hex_str.to_string())
}

/// Canonical string form of an event's `data`: object keys sorted recursively
/// so the MPC node and the SDK hash identical bytes regardless of provider key
/// ordering. Byte-for-byte mirror of the node's `normalize_event_data`.
pub fn normalize_event_data(value: &serde_json::Value) -> String {
    serde_json::to_string(&sort_keys(value.clone()))
        .expect("serde_json serialization of Value is infallible")
}

fn sort_keys(v: serde_json::Value) -> serde_json::Value {
    match v {
        serde_json::Value::Object(map) => {
            let sorted: serde_json::Map<String, serde_json::Value> = map
                .into_iter()
                .map(|(k, v)| (k, sort_keys(v)))
                .collect::<BTreeMap<_, _>>()
                .into_iter()
                .collect();
            serde_json::Value::Object(sorted)
        }
        serde_json::Value::Array(arr) => {
            serde_json::Value::Array(arr.into_iter().map(sort_keys).collect())
        }
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_event_data_sorts_keys_recursively() {
        let value = serde_json::json!({ "z": 1, "a": 2, "nested": { "y": 1, "x": 2 } });
        assert_eq!(
            normalize_event_data(&value),
            r#"{"a":2,"nested":{"x":2,"y":1},"z":1}"#
        );
    }

    #[test]
    fn split_signature_splits_rs_and_v() {
        let mut sig = [0u8; 65];
        sig[0] = 0xAA;
        sig[63] = 0xBB;
        sig[64] = 27;
        let (rs, v) = split_signature(&sig).unwrap();
        assert_eq!(rs.len(), 64);
        assert_eq!(rs[0], 0xAA);
        assert_eq!(rs[63], 0xBB);
        assert_eq!(v, 27);
        assert!(split_signature(&[0u8; 64]).is_err());
    }

    #[test]
    fn parse_event_type_splits_parts() {
        assert_eq!(
            parse_event_type("0xcafe::omni_bridge::InitTransfer"),
            Some(("0xcafe", "omni_bridge", "InitTransfer"))
        );
        assert_eq!(parse_event_type("not-a-type"), None);
    }

    #[test]
    fn find_bridge_event_matches_module_and_name() {
        let tx: CommittedTransaction = serde_json::from_value(serde_json::json!({
            "hash": "0xabc",
            "success": true,
            "events": [
                { "guid": {"account_address": "0x0"}, "sequence_number": "0",
                  "type": "0x1::other::InitTransfer", "data": {} },
                { "guid": {"account_address": "0x0"}, "sequence_number": "5",
                  "type": "0xcafe::omni_bridge::InitTransfer", "data": {"amount": "1"} }
            ]
        }))
        .unwrap();
        // 0xcafe left-padded to 32 bytes.
        let mut bridge = [0u8; 32];
        bridge[30] = 0xca;
        bridge[31] = 0xfe;
        let (idx, event) = find_bridge_event(&tx, bridge, "InitTransfer").unwrap();
        assert_eq!(idx, 1);
        assert_eq!(event.sequence_number, "5");
    }

    #[test]
    fn parse_init_transfer_event_decodes_fields() {
        let data = serde_json::json!({
            "sender": "0xabc",
            "token_address": "0xa",
            "origin_nonce": "7",
            "amount": "1000000",
            "fee": "100",
            "native_fee": "50",
            "recipient": "near:alice.near",
            "message": "0x"
        });
        let event = parse_init_transfer_event(&data).unwrap();
        assert_eq!(event.origin_nonce, 7);
        assert_eq!(event.amount, 1_000_000);
        assert_eq!(event.fee, 100);
        assert_eq!(event.native_fee, 50);
        assert_eq!(event.recipient, "near:alice.near");
        assert_eq!(event.token_address[31], 0x0a);
    }
}
