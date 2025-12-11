use crate::*;

use bitcoin::{secp256k1, TxOut};
use ethers::prelude::*;

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
        orchard_anchor: Option<orchard::Anchor>,
        input_points: Vec<InputPoint>,
        tx_out_change: Option<&TxOut>,
    ) -> zcash_primitives::transaction::builder::Builder<
        '_,
        zcash_protocol::consensus::TestNetwork,
        (),
    > {
        let near_bridge_client = self.near_bridge_client().unwrap();
        let params = zcash_protocol::consensus::TestNetwork;
        let mut builder = zcash_primitives::transaction::builder::Builder::new(
            params,
            (current_height as u32).into(),
            zcash_primitives::transaction::builder::BuildConfig::Standard {
                sapling_anchor: None,
                orchard_anchor: orchard_anchor,
            },
        );

        for i in 0..input_points.len() {
            let pk_raw = &near_bridge_client
                .get_pk_raw(ChainKind::Zcash, input_points[i].utxo.clone())
                .await;

            let transparent_pubkey = secp256k1::PublicKey::from_str(pk_raw).unwrap();

            let utxo = zcash_transparent::bundle::OutPoint::new(
                input_points[i].out_point.txid.to_byte_array(),
                input_points[i].out_point.vout,
            );

            let pk_bytes = transparent_pubkey.serialize();
            let sha = sha2::Sha256::digest(&pk_bytes);
            let rip = ripemd::Ripemd160::digest(&sha);

            let mut h160 = [0u8; 20];
            h160.copy_from_slice(&rip);

            let coin = zcash_transparent::bundle::TxOut::new(
                zcash_protocol::value::Zatoshis::const_from_u64(input_points[i].utxo.balance),
                TransparentAddress::PublicKeyHash(h160).script().into(),
            );
            builder
                .add_transparent_input(transparent_pubkey, utxo.clone(), coin.clone())
                .unwrap();
        }

        if let Some(tx_out_change) = tx_out_change {
            let h160_change = tx_out_change.clone().script_pubkey.into_bytes()[3..23]
                .try_into()
                .unwrap();

            builder
                .add_transparent_output(
                    &TransparentAddress::PublicKeyHash(h160_change),
                    zcash_protocol::value::Zatoshis::const_from_u64(tx_out_change.value.to_sat()),
                )
                .unwrap();
        }

        builder
    }

    async fn get_transparent_bundle(
        &self,
        current_height: u64,
        input_points: Vec<InputPoint>,
        tx_out_change: Option<&TxOut>,
    ) -> Option<Bundle<zcash_transparent::builder::Unauthorized>> {
        let builder = self
            .get_builder_with_transparent(current_height, None, input_points, tx_out_change)
            .await;
        builder.get_transp_bundel()
    }

    async fn validate_orchard(
        &self,
        auth_data: &TransactionData<Authorized>,
        current_height: u64,
        input_points: Vec<InputPoint>,
        tx_out_change: Option<&TxOut>,
    ) {
        let tx_orchard = auth_data.orchard_bundle().clone();
        let txid_parts = auth_data.digest(TxIdDigester);
        let shielded_sig_commitment = sighash_v5::my_signature_hash(
            &auth_data,
            self.get_transparent_bundle(current_height, input_points, tx_out_change)
                .await,
            &SignableInput::Shielded,
            &txid_parts,
        );

        let sighash: [u8; 32] = shielded_sig_commitment.as_ref()[..32].try_into().unwrap();
        tx_orchard
            .unwrap()
            .verify_proof(orchard_verifying_key())
            .unwrap();
        let mut validator = orchard::bundle::BatchValidator::new();
        validator.add_bundle(tx_orchard.unwrap(), sighash);
        assert_eq!(validator.validate(orchard_verifying_key(), OsRng), true);
    }

    pub(crate) async fn get_orchard_raw(
        &self,
        recipient: String,
        amount: u64,
        input_points: Vec<InputPoint>,
        tx_out_change: Option<&TxOut>,
    ) -> (Vec<u8>, u32) {
        let recipient = utxo_utils::extract_orchar_address(recipient);
        let utxo_bridge_client = self.utxo_bridge_client(ChainKind::Zcash).unwrap();

        let current_height = utxo_bridge_client.get_current_height().await.unwrap();
        let anchor = utxo_bridge_client.get_orchard_anchor().await;
        let mut builder = self
            .get_builder_with_transparent(
                current_height,
                Some(anchor),
                input_points.clone(),
                tx_out_change.clone(),
            )
            .await;

        let rng = k256::elliptic_curve::rand_core::OsRng;

        builder
            .add_orchard_output::<zip317::FeeRule>(
                Some(orchard::keys::OutgoingViewingKey::from([0u8; 32])),
                recipient.unwrap(),
                amount,
                MemoBytes::empty(),
            )
            .unwrap();

        let zcash_primitives::transaction::builder::PcztResult { pczt_parts, .. } = builder
            .build_for_pczt(
                rng,
                &zcash_primitives::transaction::fees::zip317::FeeRule::standard(),
            )
            .unwrap();

        let pczt = Creator::build_from_parts(pczt_parts).unwrap();
        let pczt = IoFinalizer::new(pczt).finalize_io().unwrap();
        let pczt = Prover::new(pczt)
            .create_orchard_proof(orchard_proving_key())
            .unwrap()
            .finish();

        let tx: zcash_primitives::transaction::Transaction =
            TransactionExtractor::new(pczt).extract().unwrap();

        assert_eq!(tx.version(), zcash_primitives::transaction::TxVersion::V5);
        assert_eq!(tx.lock_time(), 0);

        let auth_data = tx.into_data();
        let tx_orchard = auth_data.orchard_bundle().clone();
        let expiry_height = auth_data.expiry_height().into();

        self.validate_orchard(&auth_data, current_height, input_points, tx_out_change)
            .await;

        let mut res = Vec::new();
        zcash_primitives::transaction::components::orchard::write_v5_bundle(tx_orchard, &mut res)
            .unwrap();

        (res, expiry_height)
    }
}
