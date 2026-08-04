use crate::{CryptoHash, OmniConnector, TransactionOptions};

use bitcoin::{secp256k1, OutPoint, TxOut};
use bridge_connector_common::result::{BridgeSdkError, Result};

use bitcoin::hashes::Hash;
use bitcoin::key::rand::rngs::OsRng;
use near_bridge_client::btc::{ChainSpecificData, VUTXO};
use omni_types::ChainKind;
use orchard::circuit::OrchardCircuitVersion;
use pczt::roles::{
    creator::Creator, io_finalizer::IoFinalizer, prover::Prover, tx_extractor::TransactionExtractor,
};
use sha2::Digest;
use std::str::FromStr;
use std::sync::OnceLock;
use utxo_utils::address::{Network, UTXOAddress};
use utxo_utils::InputPoint;
use zcash_primitives::transaction::components::orchard::bundle_version_for_branch;
use zcash_primitives::transaction::fees::zip317;
use zcash_primitives::transaction::sighash::SignableInput;
use zcash_primitives::transaction::txid::TxIdDigester;
use zcash_primitives::transaction::{
    sighash_v5, sighash_v6, Authorized, TransactionData, TxVersion,
};
use zcash_protocol::consensus::{BlockHeight, BranchId};
use zcash_protocol::memo::{Memo, MemoBytes};
use zcash_transparent::address::TransparentAddress;
use zcash_transparent::bundle::Bundle;

static ORCHARD_PROVING_KEY_POST_NU6_2: OnceLock<orchard::circuit::ProvingKey> = OnceLock::new();
static ORCHARD_PROVING_KEY_POST_NU6_3: OnceLock<orchard::circuit::ProvingKey> = OnceLock::new();

static ORCHARD_VERIFYING_KEY_POST_NU6_2: OnceLock<orchard::circuit::VerifyingKey> = OnceLock::new();
static ORCHARD_VERIFYING_KEY_POST_NU6_3: OnceLock<orchard::circuit::VerifyingKey> = OnceLock::new();

/// Returns the cached Orchard proving key for the given circuit version.
/// Key generation takes several seconds, so each version is built at most
/// once per process.
fn orchard_proving_key(
    circuit_version: OrchardCircuitVersion,
) -> Result<&'static orchard::circuit::ProvingKey> {
    match circuit_version {
        OrchardCircuitVersion::InsecurePreNu6_2 => Err(BridgeSdkError::ZCashOrchardBundleError(
            "refusing to build proofs with the insecure pre-NU6.2 Orchard circuit".to_string(),
        )),
        OrchardCircuitVersion::FixedPostNu6_2 => Ok(ORCHARD_PROVING_KEY_POST_NU6_2
            .get_or_init(|| orchard::circuit::ProvingKey::build(circuit_version))),
        OrchardCircuitVersion::PostNu6_3 => Ok(ORCHARD_PROVING_KEY_POST_NU6_3
            .get_or_init(|| orchard::circuit::ProvingKey::build(circuit_version))),
    }
}

/// Returns the cached Orchard verifying key for the given circuit version.
fn orchard_verifying_key(
    circuit_version: OrchardCircuitVersion,
) -> Result<&'static orchard::circuit::VerifyingKey> {
    match circuit_version {
        OrchardCircuitVersion::InsecurePreNu6_2 => Err(BridgeSdkError::ZCashOrchardBundleError(
            "refusing to validate proofs against the insecure pre-NU6.2 Orchard circuit"
                .to_string(),
        )),
        OrchardCircuitVersion::FixedPostNu6_2 => Ok(ORCHARD_VERIFYING_KEY_POST_NU6_2
            .get_or_init(|| orchard::circuit::VerifyingKey::build(circuit_version))),
        OrchardCircuitVersion::PostNu6_3 => Ok(ORCHARD_VERIFYING_KEY_POST_NU6_3
            .get_or_init(|| orchard::circuit::VerifyingKey::build(circuit_version))),
    }
}

/// The shielded pool a withdrawal output must enter, together with the
/// transaction version that carries it, as mandated by the consensus branch
/// at the target height.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ShieldedPool {
    /// The legacy Orchard pool, carried by V5 transactions (branches up to
    /// Nu6.2).
    Orchard,
    /// The Ironwood pool, carried by V6 transactions (Nu6.3 onward). The
    /// NU6.3 turnstile closes the legacy Orchard pool for cross-address
    /// outputs, so shielded withdrawals must enter the Ironwood pool.
    Ironwood,
}

impl ShieldedPool {
    fn for_branch(branch_id: BranchId) -> Self {
        match TxVersion::suggested_for_branch(branch_id) {
            TxVersion::V6 => ShieldedPool::Ironwood,
            _ => ShieldedPool::Orchard,
        }
    }

    fn tx_version(self) -> TxVersion {
        match self {
            ShieldedPool::Orchard => TxVersion::V5,
            ShieldedPool::Ironwood => TxVersion::V6,
        }
    }

    fn value_pool(self) -> orchard::ValuePool {
        match self {
            ShieldedPool::Orchard => orchard::ValuePool::Orchard,
            ShieldedPool::Ironwood => orchard::ValuePool::Ironwood,
        }
    }
}

/// Returns the shielded pool and the Orchard circuit version mandated by the
/// consensus branch active at the given height (the legacy Orchard pool with
/// the `FixedPostNu6_2` circuit before NU6.3; the Ironwood pool with the
/// `PostNu6_3` circuit after the NU6.3 activation — height 3,428,143 on
/// mainnet, 4,134,000 on testnet).
fn shielded_pool_and_circuit(
    params: &zcash_protocol::consensus::Network,
    height: BlockHeight,
) -> Result<(ShieldedPool, OrchardCircuitVersion)> {
    let branch_id = BranchId::for_height(params, height);
    let pool = ShieldedPool::for_branch(branch_id);
    let circuit_version = bundle_version_for_branch(branch_id, pool.value_pool())
        .map(|bundle_version| bundle_version.circuit_version())
        .ok_or_else(|| {
            BridgeSdkError::ZCashOrchardBundleError(format!(
                "Shielded pool {pool:?} is not active in consensus branch {branch_id:?}"
            ))
        })?;
    Ok((pool, circuit_version))
}

fn to_block_height(height: u64) -> BlockHeight {
    BlockHeight::from_u32(height.try_into().unwrap_or(u32::MAX))
}

enum OrchardFee {
    /// Standard zip317 fee, absorbed by the caller's transparent change output.
    Zip317,
    /// Exact fee in zatoshis, with no transparent change (refunds).
    Fixed(u64),
}

fn extract_orchard_recipient(recipient: &str) -> Result<orchard::Address> {
    utxo_utils::extract_orchard_address(recipient)
        .map_err(|err| {
            BridgeSdkError::ZCashOrchardBundleError(format!(
                "Error on extract Orchard Address: {err}"
            ))
        })?
        .into_option()
        .ok_or_else(|| {
            BridgeSdkError::ZCashOrchardBundleError(
                "Recipient has no Orchard receiver (use a transparent refund instead)".to_string(),
            )
        })
}

fn parse_memo_bytes(memo: Option<String>) -> Result<MemoBytes> {
    match memo {
        Some(m) => Memo::from_str(&m).map(MemoBytes::from).map_err(|err| {
            BridgeSdkError::ZCashOrchardBundleError(format!(
                "Invalid memo (max 512 bytes): {err:?}"
            ))
        }),
        None => Ok(MemoBytes::empty()),
    }
}

impl OmniConnector {
    /// Returns the Zcash consensus parameters matching the configured bridge
    /// network. The activation heights (and thus the consensus branch ID used
    /// in sighashes) differ between mainnet and testnet.
    fn zcash_params(&self) -> Result<zcash_protocol::consensus::Network> {
        Ok(match self.network()? {
            Network::Mainnet => zcash_protocol::consensus::Network::MainNetwork,
            Network::Testnet => zcash_protocol::consensus::Network::TestNetwork,
        })
    }

    async fn get_builder_with_transparent(
        &self,
        current_height: u64,
        input_points: Vec<InputPoint>,
        tx_out_change: Option<&TxOut>,
        expiry_height: BlockHeight,
    ) -> Result<
        zcash_primitives::transaction::builder::Builder<zcash_protocol::consensus::Network, ()>,
    > {
        let near_bridge_client = self.near_bridge_client().map_err(|err| {
            BridgeSdkError::ConfigError(format!("Near bridge client is not initialized: {err}"))
        })?;

        let params = self.zcash_params()?;
        let target_height = to_block_height(current_height);
        let (pool, _) = shielded_pool_and_circuit(&params, target_height)?;

        let mut builder = zcash_primitives::transaction::builder::Builder::new(
            params,
            target_height,
            expiry_height,
            zcash_primitives::transaction::builder::BuildConfig::Standard {
                sapling_anchor: None,
                orchard_anchor: Some(orchard::Anchor::empty_tree()),
                ironwood_anchor: Some(orchard::Anchor::empty_tree()),
                // Unpadded: the withdrawal shape is public anyway (transparent
                // inputs, public value balance), and a single-action bundle is
                // what `utxo_utils::get_gas_fee` prices in (+1 ZIP-317 action).
                orchard_padding: zcash_primitives::transaction::builder::BundlePadding::UNPADDED,
                ironwood_padding: zcash_primitives::transaction::builder::BundlePadding::UNPADDED,
            },
        );

        // Pin the transaction version explicitly: V5 up to Nu6.2, V6 from
        // NU6.3 onward (the Ironwood bundle only exists in the V6 format).
        builder
            .propose_version::<std::convert::Infallible>(pool.tx_version())
            .map_err(|err| {
                BridgeSdkError::ZCashOrchardBundleError(format!(
                    "Failed to propose {:?} transaction version: {err:?}",
                    pool.tx_version()
                ))
            })?;

        for input in &input_points {
            let pk_raw = near_bridge_client
                .get_pk_for_utxo(ChainKind::Zcash, input.utxo.clone())
                .await?;

            let transparent_pubkey = secp256k1::PublicKey::from_str(&pk_raw).map_err(|err| {
                BridgeSdkError::ZCashOrchardBundleError(format!(
                    "Invalid secp256k1 public key for UTXO: {err}"
                ))
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
                .add_transparent_p2pkh_input(transparent_pubkey, utxo, coin)
                .map_err(|err| {
                    BridgeSdkError::ZCashOrchardBundleError(format!(
                        "Failed to add transparent input for UTXO: {err}"
                    ))
                })?;
        }

        if let Some(tx_out_change) = tx_out_change {
            let script_bytes = tx_out_change.clone().script_pubkey.into_bytes();

            let h160_change: [u8; 20] = script_bytes[3..23].try_into().map_err(|_| {
                BridgeSdkError::InvalidArgument(
                    "Failed to convert change output hash160 to [u8; 20]".to_string(),
                )
            })?;

            builder
                .add_transparent_output(
                    &TransparentAddress::PublicKeyHash(h160_change),
                    zcash_protocol::value::Zatoshis::const_from_u64(tx_out_change.value.to_sat()),
                )
                .map_err(|err| {
                    BridgeSdkError::ZCashOrchardBundleError(format!(
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
        expiry_height: BlockHeight,
    ) -> Result<Option<Bundle<zcash_transparent::builder::Unauthorized>>> {
        let builder = self
            .get_builder_with_transparent(
                current_height,
                input_points,
                tx_out_change,
                expiry_height,
            )
            .await?;
        Ok(builder.get_transp_bundel())
    }

    async fn validate_orchard(
        &self,
        auth_data: &TransactionData<Authorized>,
        current_height: u64,
        input_points: Vec<InputPoint>,
        tx_out_change: Option<&TxOut>,
        expiry_height: BlockHeight,
    ) -> Result<()> {
        let (pool, circuit_version) =
            shielded_pool_and_circuit(&self.zcash_params()?, to_block_height(current_height))?;

        let tx_orchard = match pool {
            ShieldedPool::Orchard => auth_data.orchard_bundle(),
            ShieldedPool::Ironwood => auth_data.ironwood_bundle(),
        }
        .ok_or_else(|| {
            BridgeSdkError::ZCashOrchardBundleError(format!(
                "Missing {pool:?} bundle in transaction"
            ))
        })?;

        let txid_parts = auth_data.digest(TxIdDigester);

        let transparent_bundle = self
            .get_transparent_bundle(current_height, input_points, tx_out_change, expiry_height)
            .await?;

        let shielded_sig_commitment = match pool {
            ShieldedPool::Orchard => sighash_v5::my_signature_hash(
                auth_data,
                transparent_bundle,
                &SignableInput::Shielded,
                &txid_parts,
            ),
            ShieldedPool::Ironwood => sighash_v6::my_signature_hash_v6(
                auth_data,
                transparent_bundle,
                &SignableInput::Shielded,
                &txid_parts,
            ),
        };

        let sighash: [u8; 32] = shielded_sig_commitment
            .as_ref()
            .get(..32)
            .ok_or_else(|| {
                BridgeSdkError::ZCashOrchardBundleError(
                    "Shielded signature commitment is shorter than 32 bytes".to_string(),
                )
            })?
            .try_into()
            .map_err(|_| {
                BridgeSdkError::ZCashOrchardBundleError(
                    "Failed to convert sighash to [u8; 32]".to_string(),
                )
            })?;

        let verifying_key = orchard_verifying_key(circuit_version)?;

        tx_orchard.verify_proof(verifying_key).map_err(|err| {
            BridgeSdkError::ZCashOrchardBundleError(format!(
                "Orchard proof verification failed: {err}"
            ))
        })?;

        let mut validator = orchard::bundle::BatchValidator::new(verifying_key);
        validator.add_bundle(tx_orchard, sighash).map_err(|err| {
            BridgeSdkError::ZCashOrchardBundleError(format!(
                "Failed to add Orchard bundle to batch validator: {err:?}"
            ))
        })?;

        let is_valid = validator.validate(OsRng);
        if !is_valid {
            return Err(BridgeSdkError::ZCashOrchardBundleError(
                "Batch Orchard validation failed".to_string(),
            ));
        }

        Ok(())
    }

    /// Creates an Orchard bundle for a shielded Zcash withdrawal (no memo).
    ///
    /// Returns a tuple of (`bundle_bytes`, `expiry_height`).
    /// The `bundle_bytes` can be passed to the contract as `chain_specific_data`.
    ///
    /// To attach a memo, use [`get_orchard_raw_with_memo`].
    pub async fn get_orchard_raw(
        &self,
        recipient: String,
        amount: u64,
        input_points: Vec<InputPoint>,
        tx_out_change: Option<&TxOut>,
    ) -> Result<(Vec<u8>, u32)> {
        self.get_orchard_raw_with_memo(recipient, amount, input_points, tx_out_change, None)
            .await
    }

    /// Creates an Orchard bundle for a shielded Zcash withdrawal with an optional memo.
    ///
    /// Returns a tuple of (`bundle_bytes`, `expiry_height`).
    /// The `bundle_bytes` can be passed to the contract as `chain_specific_data`.
    ///
    /// If `memo` is provided, it is included in the shielded output as a
    /// Zcash memo (up to 512 bytes). The recipient can decrypt it with their
    /// incoming viewing key; the sender cannot recover it (OVK is zeroed).
    pub async fn get_orchard_raw_with_memo(
        &self,
        recipient: String,
        amount: u64,
        input_points: Vec<InputPoint>,
        tx_out_change: Option<&TxOut>,
        memo: Option<String>,
    ) -> Result<(Vec<u8>, u32)> {
        let recipient = extract_orchard_recipient(&recipient)?;

        let current_height = self
            .utxo_bridge_client(ChainKind::Zcash)?
            .get_current_height()
            .await?;

        let expiry_delta = self
            .near_bridge_client()?
            .get_expiry_height_gap(ChainKind::Zcash)
            .await?;
        let expiry_height =
            BlockHeight::from_u32(current_height.try_into().unwrap_or(u32::MAX)) + expiry_delta;

        let memo_bytes = parse_memo_bytes(memo)?;

        let res = self
            .build_orchard_bundle(
                recipient,
                amount,
                input_points,
                tx_out_change,
                memo_bytes,
                current_height,
                expiry_height,
                OrchardFee::Zip317,
            )
            .await?;

        Ok((res, expiry_height.into()))
    }

    /// `expiry_height` and `fee` must match the transaction the contract will
    /// reconstruct and broadcast — the Orchard binding signature covers both.
    #[allow(clippy::too_many_arguments)]
    async fn build_orchard_bundle(
        &self,
        recipient: orchard::Address,
        amount: u64,
        input_points: Vec<InputPoint>,
        tx_out_change: Option<&TxOut>,
        memo_bytes: MemoBytes,
        current_height: u64,
        expiry_height: BlockHeight,
        fee: OrchardFee,
    ) -> Result<Vec<u8>> {
        let mut builder = self
            .get_builder_with_transparent(
                current_height,
                input_points.clone(),
                tx_out_change,
                expiry_height,
            )
            .await?;

        let rng = OsRng;

        let (pool, circuit_version) =
            shielded_pool_and_circuit(&self.zcash_params()?, to_block_height(current_height))?;

        // From NU6.3 the legacy Orchard pool is closed for cross-address
        // outputs (turnstile), so the withdrawal output goes to the Ironwood
        // pool instead; the recipient address stays the same.
        match pool {
            ShieldedPool::Orchard => builder.add_orchard_output::<zip317::FeeRule>(
                Some(orchard::keys::OutgoingViewingKey::from([0u8; 32])),
                recipient,
                zcash_protocol::value::Zatoshis::const_from_u64(amount),
                memo_bytes,
            ),
            ShieldedPool::Ironwood => builder.add_ironwood_output::<zip317::FeeRule>(
                Some(orchard::keys::OutgoingViewingKey::from([0u8; 32])),
                recipient,
                zcash_protocol::value::Zatoshis::const_from_u64(amount),
                memo_bytes,
            ),
        }
        .map_err(|err| {
            BridgeSdkError::ZCashOrchardBundleError(format!(
                "Error on add {pool:?} output: {err:?}"
            ))
        })?;

        let pczt_parts = match fee {
            OrchardFee::Zip317 => {
                builder
                    .build_for_pczt(rng, &zip317::FeeRule::standard())
                    .map_err(|err| {
                        BridgeSdkError::ZCashOrchardBundleError(format!(
                            "Error on build PCZT: {err}"
                        ))
                    })?
                    .pczt_parts
            }
            OrchardFee::Fixed(fee) => {
                let fee_rule = zcash_primitives::transaction::fees::fixed::FeeRule::non_standard(
                    zcash_protocol::value::Zatoshis::const_from_u64(fee),
                );
                builder
                    .build_for_pczt(rng, &fee_rule)
                    .map_err(|err| {
                        BridgeSdkError::ZCashOrchardBundleError(format!(
                            "Error on build PCZT: {err}"
                        ))
                    })?
                    .pczt_parts
            }
        };

        let pczt = Creator::build_from_parts(pczt_parts).ok_or_else(|| {
            BridgeSdkError::ZCashOrchardBundleError(
                "Error on Creator::build_from_parts".to_string(),
            )
        })?;

        let pczt = IoFinalizer::new(pczt).finalize_io().map_err(|err| {
            BridgeSdkError::ZCashOrchardBundleError(format!(
                "Error on IoFinalizer::finalize_io: {err:?}"
            ))
        })?;

        let prover = Prover::new(pczt);
        let pczt = match pool {
            ShieldedPool::Orchard => prover
                .create_orchard_proof(orchard_proving_key(circuit_version)?)
                .map_err(|err| {
                    BridgeSdkError::ZCashOrchardBundleError(format!(
                        "Error on create orchard proof: {err:?}"
                    ))
                })?,
            ShieldedPool::Ironwood => prover
                .create_ironwood_proof(orchard_proving_key(circuit_version)?)
                .map_err(|err| {
                    BridgeSdkError::ZCashOrchardBundleError(format!(
                        "Error on create ironwood proof: {err:?}"
                    ))
                })?,
        }
        .finish();

        let tx: zcash_primitives::transaction::Transaction =
            TransactionExtractor::new(pczt).extract().map_err(|err| {
                BridgeSdkError::ZCashOrchardBundleError(format!(
                    "Error on extract transaction: {err:?}"
                ))
            })?;

        if tx.version() != pool.tx_version() {
            return Err(BridgeSdkError::ZCashOrchardBundleError(format!(
                "Invalid transaction version: expected {:?}, got {:?}",
                pool.tx_version(),
                tx.version()
            )));
        }

        if tx.lock_time() != 0 {
            return Err(BridgeSdkError::ZCashOrchardBundleError(format!(
                "Invalid transaction lock_time: expected 0, got {}",
                tx.lock_time()
            )));
        }

        let auth_data = tx.into_data();

        self.validate_orchard(
            &auth_data,
            current_height,
            input_points,
            tx_out_change,
            expiry_height,
        )
        .await?;

        let mut res = Vec::new();
        match pool {
            ShieldedPool::Orchard => {
                zcash_primitives::transaction::components::orchard::write_v5_bundle(
                    auth_data.orchard_bundle(),
                    &mut res,
                )
            }
            ShieldedPool::Ironwood => {
                zcash_primitives::transaction::components::orchard::write_v6_bundle(
                    auth_data.ironwood_bundle(),
                    &mut res,
                )
            }
        }
        .map_err(|err| {
            BridgeSdkError::ZCashOrchardBundleError(format!(
                "Error on write {pool:?} bundle: {err}"
            ))
        })?;

        Ok(res)
    }

    /// Build the `ChainSpecificData` (Orchard bundle) for a shielded Zcash refund
    /// identified by its UTXO storage key (`{tx_id}@{vout}`). The bundle pays
    /// `amount − gas_fee` to the request's `refund_address`, with no transparent
    /// change and `expiry_height = 0` — matching the transaction the contract
    /// reconstructs in `execute_refund`.
    pub async fn build_refund_chain_specific_data(
        &self,
        utxo_storage_key: &str,
    ) -> Result<ChainSpecificData> {
        let near_bridge_client = self.near_bridge_client()?;

        let refund_request = near_bridge_client
            .get_refund_request(ChainKind::Zcash, utxo_storage_key)
            .await?;

        let gas_fee = u64::try_from(refund_request.gas_fee).map_err(|_| {
            BridgeSdkError::InvalidArgument("Refund gas_fee overflows u64".to_string())
        })?;
        let amount = u64::try_from(refund_request.amount).map_err(|_| {
            BridgeSdkError::InvalidArgument("Refund amount overflows u64".to_string())
        })?;
        let refund_amount = amount.checked_sub(gas_fee).ok_or_else(|| {
            BridgeSdkError::InvalidArgument("Deposit amount too small to cover gas fee".to_string())
        })?;
        if refund_amount == 0 {
            return Err(BridgeSdkError::InvalidArgument(
                "Refund amount is zero after gas fee".to_string(),
            ));
        }

        // Matches the contract's key-derivation path: sha256(deposit_msg_json).
        let path = hex::encode(sha2::Sha256::digest(
            refund_request.deposit_msg_json.as_bytes(),
        ));

        let (txid, _) = parse_utxo_path(utxo_storage_key)?;
        let vout = u32::try_from(refund_request.vout).map_err(|_| {
            BridgeSdkError::InvalidArgument("Refund vout overflows u32".to_string())
        })?;

        let input_point = InputPoint {
            out_point: OutPoint { txid, vout },
            utxo: utxo_utils::UTXO {
                path,
                tx_bytes: refund_request.tx_bytes.0.clone(),
                vout,
                balance: amount,
            },
        };

        let recipient = extract_orchard_recipient(&refund_request.refund_address)?;

        let current_height = self
            .utxo_bridge_client(ChainKind::Zcash)?
            .get_current_height()
            .await?;

        let bundle_bytes = self
            .build_orchard_bundle(
                recipient,
                refund_amount,
                vec![input_point],
                None,
                MemoBytes::empty(),
                current_height,
                BlockHeight::from_u32(0),
                OrchardFee::Fixed(gas_fee),
            )
            .await?;

        Ok(ChainSpecificData {
            orchard_bundle_bytes: bundle_bytes.into(),
            expiry_height: 0,
        })
    }

    /// Internal helper to regenerate an Orchard bundle for an existing pending transaction.
    /// Returns (`bundle_bytes_hex`, `expiry_height`).
    async fn regenerate_orchard_bundle(
        &self,
        btc_tx_hash: String,
        memo: Option<String>,
    ) -> Result<(String, u32)> {
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
        .await?;

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

        // The original memo is not stored in pending-info, so callers that
        // need memo preservation during RBF must provide the same memo again.
        let (bundle_bytes, expiry_height) = self
            .get_orchard_raw_with_memo(
                recipient,
                orchard_amount,
                input_points,
                tx_out_change.as_ref(),
                memo,
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
    ///
    /// This regenerates the bundle without a memo. If the original withdrawal
    /// used a memo, use [`rbf_update_orchard_bundle_with_memo`] and pass the
    /// same memo again.
    pub async fn rbf_update_orchard_bundle(
        &self,
        btc_tx_hash: String,
        transaction_options: TransactionOptions,
    ) -> Result<CryptoHash> {
        self.rbf_update_orchard_bundle_with_memo(btc_tx_hash, transaction_options, None)
            .await
    }

    /// Regenerates the Orchard bundle for a pending Zcash transaction with an
    /// optional memo and submits an RBF transaction with the new bundle.
    ///
    /// If the original withdrawal used a memo, pass the same memo again so the
    /// replacement bundle preserves it. The memo cannot be recovered from the
    /// encrypted on-chain bundle.
    pub async fn rbf_update_orchard_bundle_with_memo(
        &self,
        btc_tx_hash: String,
        transaction_options: TransactionOptions,
        memo: Option<String>,
    ) -> Result<CryptoHash> {
        // Regenerate bundle with same parameters
        let (bundle_hex, expiry_height) = self
            .regenerate_orchard_bundle(btc_tx_hash.clone(), memo)
            .await?;

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
        let _pk = orchard_proving_key(OrchardCircuitVersion::PostNu6_3).unwrap();

        // Initialize verifying key
        let _vk = orchard_verifying_key(OrchardCircuitVersion::PostNu6_3).unwrap();

        // Keys should be cached after first access
        assert!(ORCHARD_PROVING_KEY_POST_NU6_3.get().is_some());
        assert!(ORCHARD_VERIFYING_KEY_POST_NU6_3.get().is_some());

        // The insecure historical circuit must never be used.
        assert!(orchard_proving_key(OrchardCircuitVersion::InsecurePreNu6_2).is_err());
        assert!(orchard_verifying_key(OrchardCircuitVersion::InsecurePreNu6_2).is_err());
    }

    /// The consensus branch (and thus the target shielded pool, transaction
    /// version and Orchard circuit version) must follow the configured
    /// network: NU6.3 activates at height 3,428,143 on mainnet and 4,134,000
    /// on testnet.
    #[test]
    fn test_shielded_pool_and_circuit_by_network() {
        use zcash_protocol::consensus::Network;

        assert_eq!(
            shielded_pool_and_circuit(&Network::MainNetwork, BlockHeight::from_u32(3_428_142))
                .unwrap(),
            (ShieldedPool::Orchard, OrchardCircuitVersion::FixedPostNu6_2)
        );
        assert_eq!(
            shielded_pool_and_circuit(&Network::MainNetwork, BlockHeight::from_u32(3_428_143))
                .unwrap(),
            (ShieldedPool::Ironwood, OrchardCircuitVersion::PostNu6_3)
        );
        assert_eq!(
            shielded_pool_and_circuit(&Network::TestNetwork, BlockHeight::from_u32(4_133_999))
                .unwrap(),
            (ShieldedPool::Orchard, OrchardCircuitVersion::FixedPostNu6_2)
        );
        assert_eq!(
            shielded_pool_and_circuit(&Network::TestNetwork, BlockHeight::from_u32(4_134_000))
                .unwrap(),
            (ShieldedPool::Ironwood, OrchardCircuitVersion::PostNu6_3)
        );
        assert_eq!(ShieldedPool::Orchard.tx_version(), TxVersion::V5);
        assert_eq!(ShieldedPool::Ironwood.tx_version(), TxVersion::V6);
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

    /// `Memo::from_str` accepts a short text payload, pads with zeros when it is
    /// encoded, and `Memo::try_from` round-trips it back to the original UTF-8
    /// string. This is the path `get_orchard_raw_with_memo` uses to embed a memo
    /// in the shielded output, so the round-trip proves the bytes survive encoding.
    #[test]
    fn test_memo_bytes_short_text_round_trip() {
        let memo_text = "swap-id-test-001";
        let memo_bytes = Memo::from_str(memo_text).unwrap().encode();

        // Raw layout: input bytes, then zero padding to 512.
        let arr = memo_bytes.as_array();
        assert_eq!(&arr[..memo_text.len()], memo_text.as_bytes());
        assert!(arr[memo_text.len()..].iter().all(|&b| b == 0));

        // ZIP-302 round-trip: the recipient parses this back as a text memo.
        let memo = zcash_protocol::memo::Memo::try_from(&memo_bytes).unwrap();
        let zcash_protocol::memo::Memo::Text(text) = memo else {
            panic!("expected Memo::Text, got {memo:?}");
        };
        let s: String = text.into();
        assert_eq!(s, memo_text);
    }

    /// Boundary: a 512-byte memo is exactly the Zcash limit and must be accepted.
    #[test]
    fn test_memo_bytes_max_length_accepted() {
        let memo = "x".repeat(512);
        let memo_bytes = Memo::from_str(&memo).unwrap().encode();
        assert_eq!(&memo_bytes.as_array()[..], memo.as_bytes());
    }

    /// Boundary: 513 bytes must fail with `Error::TooLong`. This is the validation
    /// `get_orchard_raw_with_memo` relies on to reject oversized memos at the SDK
    /// boundary.
    #[test]
    fn test_memo_bytes_oversize_rejected() {
        let memo = "x".repeat(513);
        assert!(Memo::from_str(&memo).is_err());
    }

    /// `Memo::from_str("")` uses the same empty-memo sentinel as `MemoBytes::empty`.
    /// This keeps `Some("")` and `None` aligned with the crate's canonical text
    /// memo API instead of emitting an all-zero empty text memo.
    #[test]
    fn test_empty_string_encodes_as_no_memo() {
        let none_memo = MemoBytes::empty();
        let empty_string = Memo::from_str("").unwrap().encode();

        assert_eq!(none_memo.as_array()[0], 0xF6);
        assert_eq!(empty_string.as_array()[0], 0xF6);
        assert_eq!(none_memo, empty_string);

        let parsed_none = zcash_protocol::memo::Memo::try_from(&none_memo).unwrap();
        let parsed_empty_string = zcash_protocol::memo::Memo::try_from(&empty_string).unwrap();
        assert!(matches!(parsed_none, zcash_protocol::memo::Memo::Empty));
        assert!(matches!(
            parsed_empty_string,
            zcash_protocol::memo::Memo::Empty
        ));
    }
}
