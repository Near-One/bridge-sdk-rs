use crate::*;

use bitcoin::{secp256k1, TxOut};

use bitcoin::hashes::Hash;
use bitcoin::key::rand::rngs::OsRng;
use omni_types::ChainKind;
use pczt::roles::{
    creator::Creator, io_finalizer::IoFinalizer, prover::Prover, tx_extractor::TransactionExtractor,
};
use sha2::Digest;
use std::str::FromStr;
use std::sync::OnceLock;
use utxo_utils::InputPoint;
use zcash_primitives::transaction::fees::zip317;
use zcash_primitives::transaction::sighash::SignableInput;
use zcash_primitives::transaction::txid::TxIdDigester;
use zcash_primitives::transaction::{sighash_v5, Authorized, TransactionData};
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
            (current_height as u32).into(),
            zcash_primitives::transaction::builder::BuildConfig::Standard {
                sapling_anchor: None,
                orchard_anchor: Some(orchard::Anchor::empty_tree()),
            },
        );

        for input in &input_points {
            let pk_raw = near_bridge_client
                .get_pk_for_utxo(ChainKind::Zcash, input.utxo.clone())
                .await;

            let transparent_pubkey = secp256k1::PublicKey::from_str(&pk_raw).map_err(|err| {
                BridgeSdkError::ZCashError(format!("Invalid secp256k1 public key for UTXO: {err}"))
            })?;

            let utxo = zcash_transparent::bundle::OutPoint::new(
                input.out_point.txid.to_byte_array(),
                input.out_point.vout,
            );

            let pk_bytes = transparent_pubkey.serialize();
            let sha = sha2::Sha256::digest(&pk_bytes);
            let rip = ripemd::Ripemd160::digest(&sha);

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
        let tx_orchard = auth_data.orchard_bundle().clone().ok_or_else(|| {
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

    pub(crate) async fn get_orchard_raw(
        &self,
        recipient: String,
        amount: u64,
        input_points: Vec<InputPoint>,
        tx_out_change: Option<&TxOut>,
    ) -> Result<(Vec<u8>, u32)> {
        let recipient = utxo_utils::extract_orchard_address(recipient).map_err(|err| {
            BridgeSdkError::ZCashError(format!("Error on extract Orchard Address: {err}"))
        })?;

        let utxo_bridge_client = self.utxo_bridge_client(ChainKind::Zcash)?;

        let current_height = utxo_bridge_client.get_current_height().await?;

        let mut builder = self
            .get_builder_with_transparent(
                current_height,
                input_points.clone(),
                tx_out_change.clone(),
            )
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
            BridgeSdkError::ZCashError(format!("Error on Creator::build_from_parts"))
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
        let tx_orchard = auth_data.orchard_bundle().clone();
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
}
