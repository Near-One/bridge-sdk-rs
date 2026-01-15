use crate::{CryptoHash, OmniConnector, TransactionOptions};

use bitcoin::{secp256k1, OutPoint, TxOut};
use bridge_connector_common::result::{BridgeSdkError, Result};

use bitcoin::hashes::Hash;
use bitcoin::key::rand::rngs::OsRng;
use near_bridge_client::btc::VUTXO;
use omni_types::ChainKind;
use pczt::roles::{
    creator::Creator, io_finalizer::IoFinalizer, prover::Prover, tx_extractor::TransactionExtractor,
};
use sha2::Digest;
use std::str::FromStr;
use std::sync::OnceLock;
use utxo_utils::address::UTXOAddress;
use utxo_utils::InputPoint;
use zcash_primitives::transaction::fees::zip317;
use zcash_primitives::transaction::sighash::SignableInput;
use zcash_primitives::transaction::txid::TxIdDigester;
use zcash_primitives::transaction::{sighash_v5, Authorized, TransactionData};
use zcash_protocol::consensus::BlockHeight;
use zcash_protocol::memo::MemoBytes;
use zcash_transparent::address::TransparentAddress;
use zcash_transparent::bundle::Bundle;

static ORCHARD_PROVING_KEY: OnceLock<orchard::circuit::ProvingKey> = OnceLock::new();

fn orchard_proving_key() -> &'static orchard::circuit::ProvingKey {
    ORCHARD_PROVING_KEY.get_or_init(orchard::circuit::ProvingKey::build)
}

static ORCHARD_VERIFYING_KEY: OnceLock<orchard::circuit::VerifyingKey> = OnceLock::new();

fn orchard_verifying_key() -> &'static orchard::circuit::VerifyingKey {
    ORCHARD_VERIFYING_KEY.get_or_init(orchard::circuit::VerifyingKey::build)
}

impl OmniConnector {
    async fn get_builder_with_transparent(
        &self,
        current_height: u64,
        input_points: Vec<InputPoint>,
        tx_out_change: Option<&TxOut>,
    ) -> Result<
        zcash_primitives::transaction::builder::Builder<
            '_,
            zcash_protocol::consensus::TestNetwork,
            (),
        >,
    > {
        let near_bridge_client = self.near_bridge_client().map_err(|err| {
            BridgeSdkError::ZCashError(format!("Near bridge client is not initialized: {err}"))
        })?;

        let params = zcash_protocol::consensus::TestNetwork;

        let mut builder = zcash_primitives::transaction::builder::Builder::new(
            params,
            BlockHeight::from_u32(current_height.try_into().unwrap_or(u32::MAX)),
            zcash_primitives::transaction::builder::BuildConfig::Standard {
                sapling_anchor: None,
                orchard_anchor: Some(orchard::Anchor::empty_tree()),
            },
        );

        for input in &input_points {
            let pk_raw = near_bridge_client
                .get_pk_for_utxo(ChainKind::Zcash, input.utxo.clone())
                .await?;

            let transparent_pubkey = secp256k1::PublicKey::from_str(&pk_raw).map_err(|err| {
                BridgeSdkError::ZCashError(format!("Invalid secp256k1 public key for UTXO: {err}"))
            })?;

            let utxo = zcash_transparent::bundle::OutPoint::new(
                input.out_point.txid.to_byte_array(),
                input.out_point.vout,
            );

            let pk_bytes = transparent_pubkey.serialize();
            let sha = sha2::Sha256::digest(pk_bytes);
            let rip = ripemd::Ripemd160::digest(sha);

            let mut h160 = [0u8; 20];
            h160.copy_from_slice(&rip);

            let coin = zcash_transparent::bundle::TxOut::new(
                zcash_protocol::value::Zatoshis::const_from_u64(input.utxo.balance),
                TransparentAddress::PublicKeyHash(h160).script().into(),
            );

            builder
                .add_transparent_input(transparent_pubkey, utxo, coin)
                .map_err(|err| {
                    BridgeSdkError::ZCashError(format!(
                        "Failed to add transparent input for UTXO: {err}"
                    ))
                })?;
        }

        if let Some(tx_out_change) = tx_out_change {
            let script_bytes = tx_out_change.clone().script_pubkey.into_bytes();

            let h160_change: [u8; 20] = script_bytes[3..23].try_into().map_err(|_| {
                BridgeSdkError::ZCashError(
                    "Failed to convert change output hash160 to [u8; 20]".to_string(),
                )
            })?;

            builder
                .add_transparent_output(
                    &TransparentAddress::PublicKeyHash(h160_change),
                    zcash_protocol::value::Zatoshis::const_from_u64(tx_out_change.value.to_sat()),
                )
                .map_err(|err| {
                    BridgeSdkError::ZCashError(format!(
                        "Failed to add transparent change output: {err}"
                    ))
                })?;
        }

        Ok(builder)
    }

    async fn get_transparent_bundle(
        &self,
        current_height: u64,
        input_points: Vec<InputPoint>,
        tx_out_change: Option<&TxOut>,
    ) -> Result<Option<Bundle<zcash_transparent::builder::Unauthorized>>> {
        let builder = self
            .get_builder_with_transparent(current_height, input_points, tx_out_change)
            .await?;
        Ok(builder.get_transp_bundel())
    }

    async fn validate_orchard(
        &self,
        auth_data: &TransactionData<Authorized>,
        current_height: u64,
        input_points: Vec<InputPoint>,
        tx_out_change: Option<&TxOut>,
    ) -> Result<()> {
        let tx_orchard = auth_data.orchard_bundle().ok_or_else(|| {
            BridgeSdkError::ZCashError("Missing Orchard bundle in transaction".to_string())
        })?;

        let txid_parts = auth_data.digest(TxIdDigester);

        let shielded_sig_commitment = sighash_v5::my_signature_hash(
            auth_data,
            self.get_transparent_bundle(current_height, input_points, tx_out_change)
                .await?,
            &SignableInput::Shielded,
            &txid_parts,
        );

        let sighash: [u8; 32] = shielded_sig_commitment
            .as_ref()
            .get(..32)
            .ok_or_else(|| {
                BridgeSdkError::ZCashError(
                    "Shielded signature commitment is shorter than 32 bytes".to_string(),
                )
            })?
            .try_into()
            .map_err(|_| {
                BridgeSdkError::ZCashError("Failed to convert sighash to [u8; 32]".to_string())
            })?;

        tx_orchard
            .verify_proof(orchard_verifying_key())
            .map_err(|err| {
                BridgeSdkError::ZCashError(format!("Orchard proof verification failed: {err}"))
            })?;

        let mut validator = orchard::bundle::BatchValidator::new();
        validator.add_bundle(tx_orchard, sighash);

        let is_valid = validator.validate(orchard_verifying_key(), OsRng);
        if !is_valid {
            return Err(BridgeSdkError::ZCashError(
                "Batch Orchard validation failed".to_string(),
            ));
        }

        Ok(())
    }

    /// Creates an Orchard bundle for a shielded Zcash withdrawal.
    ///
    /// Returns a tuple of (`bundle_bytes`, `expiry_height`).
    /// The `bundle_bytes` can be passed to the contract as `chain_specific_data`.
    pub async fn get_orchard_raw(
        &self,
        recipient: String,
        amount: u64,
        input_points: Vec<InputPoint>,
        tx_out_change: Option<&TxOut>,
    ) -> Result<(Vec<u8>, u32)> {
        let recipient = utxo_utils::extract_orchard_address(&recipient).map_err(|err| {
            BridgeSdkError::ZCashError(format!("Error on extract Orchard Address: {err}"))
        })?;

        let utxo_bridge_client = self.utxo_bridge_client(ChainKind::Zcash)?;

        let current_height = utxo_bridge_client.get_current_height().await?;

        let mut builder = self
            .get_builder_with_transparent(current_height, input_points.clone(), tx_out_change)
            .await?;

        let rng = OsRng;

        let recipient = recipient.into_option().ok_or_else(|| {
            BridgeSdkError::ZCashError("Recipient Orchard address is None".to_string())
        })?;

        builder
            .add_orchard_output::<zip317::FeeRule>(
                Some(orchard::keys::OutgoingViewingKey::from([0u8; 32])),
                recipient,
                amount,
                MemoBytes::empty(),
            )
            .map_err(|err| {
                BridgeSdkError::ZCashError(format!("Error on add orchard output: {err:?}"))
            })?;

        let zcash_primitives::transaction::builder::PcztResult { pczt_parts, .. } = builder
            .build_for_pczt(rng, &zip317::FeeRule::standard())
            .map_err(|err| BridgeSdkError::ZCashError(format!("Error on build PCZT: {err}")))?;

        let pczt = Creator::build_from_parts(pczt_parts).ok_or_else(|| {
            BridgeSdkError::ZCashError("Error on Creator::build_from_parts".to_string())
        })?;

        let pczt = IoFinalizer::new(pczt).finalize_io().map_err(|err| {
            BridgeSdkError::ZCashError(format!("Error on IoFinalizer::finalize_io: {err:?}"))
        })?;

        let pczt = Prover::new(pczt)
            .create_orchard_proof(orchard_proving_key())
            .map_err(|err| {
                BridgeSdkError::ZCashError(format!("Error on create orchard proof: {err:?}"))
            })?
            .finish();

        let tx: zcash_primitives::transaction::Transaction =
            TransactionExtractor::new(pczt).extract().map_err(|err| {
                BridgeSdkError::ZCashError(format!("Error on extract transaction: {err:?}"))
            })?;

        if tx.version() != zcash_primitives::transaction::TxVersion::V5 {
            return Err(BridgeSdkError::ZCashError(format!(
                "Invalid transaction version: expected V5, got {:?}",
                tx.version()
            )));
        }

        if tx.lock_time() != 0 {
            return Err(BridgeSdkError::ZCashError(format!(
                "Invalid transaction lock_time: expected 0, got {}",
                tx.lock_time()
            )));
        }

        let auth_data = tx.into_data();
        let tx_orchard = auth_data.orchard_bundle();
        let expiry_height = auth_data.expiry_height().into();

        self.validate_orchard(&auth_data, current_height, input_points, tx_out_change)
            .await?;

        let mut res = Vec::new();
        zcash_primitives::transaction::components::orchard::write_v5_bundle(tx_orchard, &mut res)
            .map_err(|err| {
            BridgeSdkError::ZCashError(format!("Error on write orchard bundle: {err}"))
        })?;

        Ok((res, expiry_height))
    }

    /// Internal helper to regenerate an Orchard bundle for an existing pending transaction.
    /// Returns (`bundle_bytes_hex`, `expiry_height`).
    async fn regenerate_orchard_bundle(&self, btc_tx_hash: String) -> Result<(String, u32)> {
        let near_bridge_client = self.near_bridge_client()?;

        // Get the pending transaction info
        let btc_pending_info = near_bridge_client
            .get_btc_pending_info(ChainKind::Zcash, btc_tx_hash)
            .await?;

        // Extract recipient address from pending info
        // The recipient is stored in the PSBT recipient_address field
        let recipient = btc_pending_info
            .tx_bytes_with_sign
            .as_ref()
            .ok_or_else(|| {
                BridgeSdkError::InvalidArgument(
                    "Pending transaction has no signed tx bytes".to_string(),
                )
            })?;

        // Parse the pending PSBT to get the recipient address
        // For Zcash, the recipient is stored in the serialized PSBT
        let _psbt_hex = hex::encode(recipient);

        // Get recipient from contract view call
        let endpoint = near_bridge_client.endpoint()?;
        let zcash_connector = near_bridge_client.utxo_chain_connector(ChainKind::Zcash)?;

        let response = near_rpc_client::view(
            endpoint,
            near_rpc_client::ViewRequest {
                contract_account_id: zcash_connector,
                method_name: "get_btc_pending_recipient".to_string(),
                args: serde_json::json!({
                    "btc_pending_id": btc_pending_info.btc_pending_id
                }),
            },
        )
        .await
        .map_err(|e| BridgeSdkError::UnknownError(format!("Failed to get recipient: {e}")))?;

        let recipient: String = serde_json::from_slice(&response)?;

        // Calculate the orchard amount (what the user receives after fees)
        let orchard_amount = btc_pending_info
            .actual_received_amount
            .try_into()
            .map_err(|e| BridgeSdkError::UnknownError(format!("Amount conversion error: {e}")))?;

        // Convert vutxos to input points
        let input_points: Vec<InputPoint> = btc_pending_info
            .vutxos
            .iter()
            .map(|vutxo| {
                let utxo = match vutxo {
                    VUTXO::Current(u) => u.clone(),
                };
                let (txid, vout) = parse_utxo_path(&utxo.path)?;

                Ok(InputPoint {
                    out_point: OutPoint { txid, vout },
                    utxo: utxo_utils::UTXO {
                        path: utxo.path.clone(),
                        tx_bytes: utxo.tx_bytes.clone(),
                        vout: utxo.vout,
                        balance: utxo.balance,
                    },
                })
            })
            .collect::<Result<Vec<_>>>()?;

        // Calculate change output if needed
        let utxo_balance: u64 = btc_pending_info
            .vutxos
            .iter()
            .map(|vutxo| match vutxo {
                VUTXO::Current(u) => u.balance,
            })
            .sum();

        let change_amount = calculate_change_amount(
            utxo_balance,
            orchard_amount,
            btc_pending_info.gas_fee.try_into().unwrap_or(u64::MAX),
        );

        let tx_out_change = if change_amount > 0 {
            let change_address = near_bridge_client
                .get_change_address(ChainKind::Zcash)
                .await?;
            let change_address = UTXOAddress::parse(
                &change_address,
                ChainKind::Zcash,
                self.network()?,
            )
            .map_err(|e| {
                BridgeSdkError::ContractConfigurationError(format!("Invalid change address: {e}"))
            })?;
            let change_script_pubkey = change_address.script_pubkey().map_err(|e| {
                BridgeSdkError::ContractConfigurationError(format!(
                    "Failed to get script pubkey: {e}"
                ))
            })?;

            Some(TxOut {
                value: bitcoin::Amount::from_sat(change_amount),
                script_pubkey: change_script_pubkey,
            })
        } else {
            None
        };

        // Generate new bundle with the same parameters
        let (bundle_bytes, expiry_height) = self
            .get_orchard_raw(
                recipient,
                orchard_amount,
                input_points,
                tx_out_change.as_ref(),
            )
            .await?;

        Ok((hex::encode(bundle_bytes), expiry_height))
    }

    /// Regenerates the Orchard bundle for a pending Zcash transaction and submits
    /// an RBF transaction with the new bundle.
    ///
    /// This function does NOT change any transaction parameters (fee, amount, recipient).
    /// It only regenerates the zero-knowledge proof and submits a replacement transaction.
    ///
    /// Use this when:
    /// - The original bundle's expiry height has passed
    /// - The original proof was rejected for some reason
    /// - You need to refresh the bundle without changing withdrawal parameters
    pub async fn rbf_update_orchard_bundle(
        &self,
        btc_tx_hash: String,
        transaction_options: TransactionOptions,
    ) -> Result<CryptoHash> {
        // Regenerate bundle with same parameters
        let (bundle_hex, expiry_height) =
            self.regenerate_orchard_bundle(btc_tx_hash.clone()).await?;

        // Submit RBF with only the new bundle - no fee/output changes
        let near_bridge_client = self.near_bridge_client()?;
        near_bridge_client
            .btc_rbf_increase_gas_fee(
                ChainKind::Zcash,
                btc_tx_hash,
                vec![], // empty outputs = keep original
                Some(bundle_hex),
                Some(expiry_height),
                transaction_options,
            )
            .await
    }
}

/// Parses a UTXO path string (format: "txid@vout") into txid and vout components.
fn parse_utxo_path(path: &str) -> Result<(bitcoin::Txid, u32)> {
    let parts: Vec<&str> = path.split('@').collect();
    let txid_str = parts.first().ok_or_else(|| {
        BridgeSdkError::InvalidArgument(format!("Invalid UTXO path format: {path}"))
    })?;
    let vout: u32 = parts.get(1).and_then(|s| s.parse().ok()).ok_or_else(|| {
        BridgeSdkError::InvalidArgument(format!("Invalid vout in UTXO path: {path}"))
    })?;
    let txid = bitcoin::Txid::from_str(txid_str)
        .map_err(|e| BridgeSdkError::InvalidArgument(format!("Invalid txid in UTXO path: {e}")))?;
    Ok((txid, vout))
}

/// Calculates the change amount for a transaction.
/// Returns 0 if there's no change (or negative, which shouldn't happen).
fn calculate_change_amount(utxo_balance: u64, orchard_amount: u64, gas_fee: u64) -> u64 {
    utxo_balance
        .saturating_sub(orchard_amount)
        .saturating_sub(gas_fee)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Tests that the Orchard proving and verifying keys can be initialized.
    /// This is important because key generation is expensive and lazy-loaded.
    #[test]
    fn test_orchard_keys_init() {
        // Initialize proving key (this is expensive, ~few seconds)
        let _pk = orchard_proving_key();

        // Initialize verifying key
        let _vk = orchard_verifying_key();

        // Keys should be cached after first access
        assert!(ORCHARD_PROVING_KEY.get().is_some());
        assert!(ORCHARD_VERIFYING_KEY.get().is_some());
    }

    #[test]
    fn test_parse_utxo_path_valid() {
        let path = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef@0";
        let result = parse_utxo_path(path);
        assert!(result.is_ok());
        let (txid, vout) = result.unwrap();
        assert_eq!(vout, 0);
        // txid.to_string() returns the same hex as input (bitcoin crate handles display)
        assert_eq!(
            txid.to_string(),
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        );
    }

    #[test]
    fn test_parse_utxo_path_with_vout() {
        let path = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef@42";
        let result = parse_utxo_path(path);
        assert!(result.is_ok());
        let (_, vout) = result.unwrap();
        assert_eq!(vout, 42);
    }

    #[test]
    fn test_parse_utxo_path_invalid_no_separator() {
        let path = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let result = parse_utxo_path(path);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_utxo_path_invalid_txid() {
        let path = "not_a_valid_txid@0";
        let result = parse_utxo_path(path);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_utxo_path_invalid_vout() {
        let path = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef@notanumber";
        let result = parse_utxo_path(path);
        assert!(result.is_err());
    }

    #[test]
    fn test_calculate_change_amount_with_change() {
        let utxo_balance = 100_000;
        let orchard_amount = 50_000;
        let gas_fee = 10_000;
        let change = calculate_change_amount(utxo_balance, orchard_amount, gas_fee);
        assert_eq!(change, 40_000);
    }

    #[test]
    fn test_calculate_change_amount_no_change() {
        let utxo_balance = 60_000;
        let orchard_amount = 50_000;
        let gas_fee = 10_000;
        let change = calculate_change_amount(utxo_balance, orchard_amount, gas_fee);
        assert_eq!(change, 0);
    }

    #[test]
    fn test_calculate_change_amount_saturates() {
        // When fees exceed balance, should return 0 (not underflow)
        let utxo_balance = 50_000;
        let orchard_amount = 50_000;
        let gas_fee = 10_000;
        let change = calculate_change_amount(utxo_balance, orchard_amount, gas_fee);
        assert_eq!(change, 0);
    }

    #[test]
    fn test_calculate_change_amount_large_values() {
        // Test with large values close to u64 max
        let utxo_balance = 1_000_000_000_000u64; // 1 trillion zatoshis
        let orchard_amount = 500_000_000_000u64;
        let gas_fee = 100_000_000u64;
        let change = calculate_change_amount(utxo_balance, orchard_amount, gas_fee);
        assert_eq!(change, 499_900_000_000u64);
    }
}
