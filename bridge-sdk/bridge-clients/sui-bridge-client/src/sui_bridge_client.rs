//! Sui bridge client for the Omni Bridge.
//!
//! Mirrors `aptos-bridge-client` in shape, but talks to Sui over gRPC via the
//! `sui-rpc` crate (Sui JSON-RPC is decommissioned) and builds programmable
//! transaction blocks with `sui-transaction-builder`. Signing uses
//! `sui-crypto` (raw Ed25519 seed, Sui intent + Blake2b handled internally).

use std::time::Duration;

use near_mpc_contract_interface::types::SuiFinality;
use omni_types::near_events::OmniBridgeEvent;
use omni_types::OmniAddress;
use sha3::{Digest as _, Keccak256};
use sui_crypto::ed25519::Ed25519PrivateKey;
use sui_crypto::SuiSigner;
use sui_rpc::client::ExecuteAndWaitError;
use sui_rpc::field::{FieldMask, FieldMaskUtil};
use sui_rpc::proto::sui::rpc::v2::changed_object::IdOperation;
use sui_rpc::proto::sui::rpc::v2::owner::OwnerKind;
use sui_rpc::proto::sui::rpc::v2::simulate_transaction_request::TransactionChecks;
use sui_rpc::proto::sui::rpc::v2::{
    ExecuteTransactionRequest, ExecutedTransaction, SimulateTransactionRequest,
};
use sui_sdk_types::{
    Address, Argument, Command, GasPayment, Identifier, Input, MoveCall, ProgrammableTransaction,
    SharedInput, StructTag, Transaction, TransactionExpiration, TransactionKind, TypeTag,
};
use sui_transaction_builder::{Function, ObjectInput, TransactionBuilder};

use crate::error::{Result, SuiBridgeClientError};

pub use builder::SuiBridgeClientBuilder;

pub mod bytecode;
pub mod error;

mod builder;
mod rpc;

/// Move module that hosts the bridge functions.
const MODULE_NAME: &str = "omni_bridge";
/// How long to wait for checkpoint inclusion after execution. Sui checkpoints
/// are sub-second in practice; a timeout here does not mean the transaction
/// failed (see `sign_and_execute`).
const CHECKPOINT_TIMEOUT: Duration = Duration::from_secs(60);
/// Sui coin decimals are capped at 9 (`utils::normalize_decimals` on-chain).
const MAX_SUI_DECIMALS: u8 = 9;

/// An Ed25519 signing identity for submitting Sui transactions. The Sui
/// address is derived from the public key (Blake2b of `0x00 || pubkey`).
pub struct SuiAccount {
    pub(crate) key: Ed25519PrivateKey,
    pub(crate) address: Address,
}

/// Sui bridge client for the `omni_bridge` Move package.
pub struct SuiBridgeClient {
    pub(crate) rpc: sui_rpc::Client,
    pub(crate) account: Option<SuiAccount>,
    /// Package id the `omni_bridge` module is published under.
    pub(crate) bridge_address: Option<Address>,
    /// The shared `BridgeState` object.
    pub(crate) state_object_id: Option<Address>,
    pub(crate) mpc_finality: Option<SuiFinality>,
}

/// A decoded `InitTransfer` event (BCS layout matches the Move struct field
/// order), used to derive NEAR storage-deposit actions.
#[derive(Debug, serde::Deserialize)]
#[cfg_attr(test, derive(serde::Serialize))]
pub struct SuiInitTransferEvent {
    pub sender: [u8; 32],
    /// `keccak256(canonical coin type string)` — the wire token id.
    pub token_address: [u8; 32],
    pub coin_type: String,
    pub origin_nonce: u64,
    pub amount: u128,
    pub fee: u128,
    pub native_fee: u128,
    pub recipient: String,
    pub message: Vec<u8>,
}

/// A raw bridge event with the metadata the MPC foreign-tx validation payload
/// needs. `type_tag` is normalized to Sui's canonical long form and `bcs`
/// carries the raw BCS event contents — exactly what the MPC node's Sui
/// inspector reconstructs.
#[derive(Debug)]
pub struct SuiEventLog {
    pub package_id: [u8; 32],
    pub transaction_module: String,
    pub sender: [u8; 32],
    pub type_tag: String,
    pub bcs: Vec<u8>,
    pub event_index: u64,
}

impl SuiBridgeClient {
    fn account(&self) -> Result<&SuiAccount> {
        self.account.as_ref().ok_or_else(|| {
            SuiBridgeClientError::ConfigError("Sui private key is not set".to_string())
        })
    }

    fn bridge_address(&self) -> Result<Address> {
        self.bridge_address.ok_or_else(|| {
            SuiBridgeClientError::ConfigError("OmniBridge package id is not set".to_string())
        })
    }

    fn state_object_id(&self) -> Result<Address> {
        self.state_object_id.ok_or_else(|| {
            SuiBridgeClientError::ConfigError("OmniBridge state object id is not set".to_string())
        })
    }

    fn bridge_function(&self, function: &'static str) -> Result<Function> {
        Ok(Function::new(
            self.bridge_address()?,
            Identifier::from_static(MODULE_NAME),
            Identifier::from_static(function),
        ))
    }

    /// The shared `BridgeState` object as a PTB input; fetches the initial
    /// shared version from the node.
    async fn state_object_input(&self, mutable: bool) -> Result<ObjectInput> {
        let state_id = self.state_object_id()?;
        let (version, kind) = self.shared_object_start_version(state_id).await?;
        if kind != OwnerKind::Shared {
            return Err(SuiBridgeClientError::BlockchainDataError(format!(
                "bridge state object {state_id} is not a shared object"
            )));
        }
        Ok(ObjectInput::shared(state_id, version, mutable))
    }

    async fn shared_object_start_version(&self, object_id: Address) -> Result<(u64, OwnerKind)> {
        let object = rpc::get_object(
            &mut self.rpc.clone(),
            &object_id.to_string(),
            &["object_id", "owner"],
        )
        .await?;
        Ok((object.owner().version(), object.owner().kind()))
    }

    /// Build (resolving object versions and gas via the node), sign, submit,
    /// and wait for checkpoint inclusion. Returns the executed transaction;
    /// fails if execution was unsuccessful.
    async fn sign_and_execute(
        &self,
        transaction_builder: TransactionBuilder,
    ) -> Result<(String, ExecutedTransaction)> {
        let account = self.account()?;
        let mut client = self.rpc.clone();

        let transaction = transaction_builder
            .build(&mut client)
            .await
            .map_err(|e| SuiBridgeClientError::TransactionError(format!("{e}")))?;
        let digest = transaction.digest().to_base58();

        let signature = account
            .key
            .sign_transaction(&transaction)
            .map_err(|e| SuiBridgeClientError::TransactionError(format!("signing failed: {e}")))?;

        let request = ExecuteTransactionRequest::default()
            .with_transaction(transaction)
            .with_signatures(vec![signature.into()])
            .with_read_mask(FieldMask::from_paths([
                "digest",
                "checkpoint",
                "effects.status",
                "effects.changed_objects",
                "events",
            ]));

        tracing::info!(tx_digest = %digest, "Submitting Sui transaction");
        let response = match client
            .execute_transaction_and_wait_for_checkpoint(request, CHECKPOINT_TIMEOUT)
            .await
        {
            Ok(response) => response.into_inner(),
            Err(ExecuteAndWaitError::RpcError(status)) => return Err(rpc::rpc_error(&status)),
            // The transaction executed; only checkpoint tracking fell behind.
            // Downstream MPC flows re-verify finality via `check_mpc_finality`.
            Err(ExecuteAndWaitError::CheckpointTimeout(response)) => {
                tracing::warn!(tx_digest = %digest, "Sui transaction executed but checkpoint inclusion was not observed in time");
                response.into_inner()
            }
            Err(ExecuteAndWaitError::CheckpointStreamError { response, error }) => {
                tracing::warn!(tx_digest = %digest, %error, "Sui transaction executed but the checkpoint stream failed");
                response.into_inner()
            }
            Err(other) => return Err(SuiBridgeClientError::TransactionError(format!("{other}"))),
        };

        let executed = response.transaction.unwrap_or_default();
        let status = executed.effects().status();
        if !status.success() {
            return Err(SuiBridgeClientError::TransactionError(format!(
                "transaction {digest} failed: {}",
                status.error()
            )));
        }
        Ok((digest, executed))
    }

    /// Log token metadata on the Sui `omni_bridge` contract (permissionless).
    /// `coin_type` is the coin's Move type, e.g. `0x2::sui::SUI`.
    #[tracing::instrument(skip_all, name = "SUI LOG METADATA")]
    pub async fn log_metadata(&self, coin_type: &str) -> Result<String> {
        let account_address = self.account()?.address;
        let coin_type_tag = parse_struct_tag(coin_type)?;

        let metadata = self.coin_metadata_object(&coin_type_tag).await?;
        let function = if metadata.is_registry_currency {
            "log_metadata_registry"
        } else {
            "log_metadata"
        };

        let mut tx = TransactionBuilder::new();
        tx.set_sender(account_address);
        let state = tx.object(self.state_object_input(true).await?);
        let metadata_arg = tx.object(metadata.input);
        tx.move_call(
            self.bridge_function(function)?
                .with_type_args(vec![coin_type_tag.into()]),
            vec![state, metadata_arg],
        );

        let (digest, _) = self.sign_and_execute(tx).await?;
        Ok(digest)
    }

    /// Deploy a bridged token on Sui using a `LogMetadataEvent` from NEAR.
    ///
    /// Sui cannot create a currency at runtime, so this submits two
    /// back-to-back transactions: (1) publish a per-token package patched
    /// from the vendored `token_template` bytecode, (2) call
    /// `deploy_token<T>` with the MPC signature and the created
    /// `TreasuryCap` / `UpgradeCap` / `CoinMetadata` objects. Returns the
    /// digest of the `deploy_token` transaction.
    #[tracing::instrument(skip_all, name = "SUI DEPLOY TOKEN")]
    pub async fn deploy_token(&self, event: OmniBridgeEvent) -> Result<String> {
        let OmniBridgeEvent::LogMetadataEvent {
            signature,
            metadata_payload,
        } = event
        else {
            return Err(SuiBridgeClientError::InvalidArgument(format!(
                "Expected LogMetadataEvent but got {event:?}"
            )));
        };

        let account_address = self.account()?.address;
        let origin_decimals = metadata_payload.decimals;
        let clamped_decimals = origin_decimals.min(MAX_SUI_DECIMALS);
        let (module_name, otw_name) = bytecode::coin_module_identifiers(&metadata_payload.symbol);

        let patched_module = bytecode::patch_token_template(
            bytecode::TOKEN_TEMPLATE_BYTECODE,
            &module_name,
            &otw_name,
            &metadata_payload.symbol,
            &metadata_payload.name,
            clamped_decimals,
        )?;

        // 1. Publish the per-token package.
        let mut tx = TransactionBuilder::new();
        tx.set_sender(account_address);
        let upgrade_cap = tx.publish(
            vec![patched_module],
            bytecode::TOKEN_TEMPLATE_DEPENDENCIES
                .iter()
                .map(|address| Address::new(*address))
                .collect(),
        );
        let sender_arg = tx.pure(&account_address);
        tx.transfer_objects(vec![upgrade_cap], sender_arg);
        let (publish_digest, published) = self.sign_and_execute(tx).await?;
        tracing::info!(tx_digest = %publish_digest, "Published Sui token package");

        let created = CreatedTokenObjects::from_publish_effects(&published, &publish_digest)?;

        // 2. Bind the published coin to the bridge with the MPC signature.
        let mut tx = TransactionBuilder::new();
        tx.set_sender(account_address);
        let state = tx.object(self.state_object_input(true).await?);
        let signature_arg = tx.pure(&signature.to_bytes().to_vec());
        let token_arg = tx.pure(&metadata_payload.token.to_string());
        let name_arg = tx.pure(&metadata_payload.name);
        let symbol_arg = tx.pure(&metadata_payload.symbol);
        let decimals_arg = tx.pure(&origin_decimals);
        let treasury_cap = tx.object(created.treasury_cap);
        let upgrade_cap = tx.object(created.upgrade_cap);
        let coin_metadata = tx.object(created.coin_metadata);
        tx.move_call(
            self.bridge_function("deploy_token")?
                .with_type_args(vec![created.coin_type.into()]),
            vec![
                state,
                signature_arg,
                token_arg,
                name_arg,
                symbol_arg,
                decimals_arg,
                treasury_cap,
                upgrade_cap,
                coin_metadata,
            ],
        );

        let (digest, _) = self.sign_and_execute(tx).await?;
        Ok(digest)
    }

    /// Initiate a transfer from Sui to another chain (user-signed outbound).
    /// `token` is the coin's Move type, e.g. `0x2::sui::SUI`.
    #[tracing::instrument(skip_all, name = "SUI INIT TRANSFER")]
    pub async fn init_transfer(
        &self,
        token: String,
        amount: u128,
        fee: u128,
        native_fee: u128,
        recipient: String,
        message: Vec<u8>,
    ) -> Result<String> {
        let account_address = self.account()?.address;
        let coin_type = parse_struct_tag(&token)?;
        let amount = to_coin_value(amount, "amount")?;
        let fee = to_coin_value(fee, "fee")?;
        let native_fee = to_coin_value(native_fee, "native_fee")?;

        let mut tx = TransactionBuilder::new();
        tx.set_sender(account_address);
        let state = tx.object(self.state_object_input(true).await?);
        let coin_arg = tx.coin(coin_type.clone(), amount);
        // The contract always takes a `Coin<SUI>` native fee; split a
        // zero-value coin off gas when there is none.
        let native_fee_arg = if native_fee == 0 {
            let zero = tx.pure(&0u64);
            let gas = tx.gas();
            tx.split_coins(gas, vec![zero])
                .pop()
                .expect("split_coins returns one argument per amount")
        } else {
            tx.coin(StructTag::sui(), native_fee)
        };
        let fee_arg = tx.pure(&fee);
        let recipient_arg = tx.pure(&recipient);
        let message_arg = tx.pure(&message);
        tx.move_call(
            self.bridge_function("init_transfer")?
                .with_type_args(vec![coin_type.into()]),
            vec![
                state,
                coin_arg,
                fee_arg,
                native_fee_arg,
                recipient_arg,
                message_arg,
            ],
        );

        let (digest, _) = self.sign_and_execute(tx).await?;
        Ok(digest)
    }

    /// Finalize a transfer to Sui using a `SignTransferEvent` from NEAR.
    #[tracing::instrument(skip_all, name = "SUI FIN TRANSFER")]
    pub async fn fin_transfer(&self, event: OmniBridgeEvent) -> Result<String> {
        let OmniBridgeEvent::SignTransferEvent {
            message_payload,
            signature,
        } = event
        else {
            return Err(SuiBridgeClientError::InvalidArgument(format!(
                "Expected SignTransferEvent but got {event:?}"
            )));
        };

        let account_address = self.account()?.address;
        let token = omni_address_to_sui(&message_payload.token_address)?;
        let recipient = omni_address_to_sui(&message_payload.recipient)?;
        // Sui coins are types: resolve the wire token id back to the coin
        // type through the bridge's on-chain token registry.
        let coin_type = parse_struct_tag(&self.get_coin_type(token).await?)?;
        let amount: u128 = message_payload.amount.into();
        let fee_recipient = message_payload.fee_recipient.map(|a| a.to_string());

        let mut tx = TransactionBuilder::new();
        tx.set_sender(account_address);
        let state = tx.object(self.state_object_input(true).await?);
        let signature_arg = tx.pure(&signature.to_bytes().to_vec());
        let destination_nonce_arg = tx.pure(&message_payload.destination_nonce);
        let origin_chain_arg = tx.pure(&u8::from(message_payload.transfer_id.origin_chain));
        let origin_nonce_arg = tx.pure(&message_payload.transfer_id.origin_nonce);
        let amount_arg = tx.pure(&amount);
        let recipient_arg = tx.pure(&Address::new(recipient));
        let fee_recipient_arg = tx.pure(&fee_recipient);
        let message_arg = tx.pure(&message_payload.message);
        tx.move_call(
            self.bridge_function("fin_transfer")?
                .with_type_args(vec![coin_type.into()]),
            vec![
                state,
                signature_arg,
                destination_nonce_arg,
                origin_chain_arg,
                origin_nonce_arg,
                amount_arg,
                recipient_arg,
                fee_recipient_arg,
                message_arg,
            ],
        );

        let (digest, _) = self.sign_and_execute(tx).await?;
        Ok(digest)
    }

    /// Whether a transfer with the given destination nonce has been finalised.
    pub async fn is_transfer_finalised(&self, nonce: u64) -> Result<bool> {
        let output = self
            .call_view("is_transfer_finalised", vec![encode_pure(&nonce)?])
            .await?;
        bcs::from_bytes(&output).map_err(|e| {
            SuiBridgeClientError::BlockchainDataError(format!(
                "is_transfer_finalised returned malformed bool: {e}"
            ))
        })
    }

    /// Resolve a wire token id (`keccak256` of the canonical coin type) back
    /// to the coin type string through the bridge's on-chain token registry.
    pub async fn get_coin_type(&self, token_address: [u8; 32]) -> Result<String> {
        let output = self
            .call_view(
                "get_coin_type",
                vec![encode_pure(&Address::new(token_address))?],
            )
            .await?;
        let coin_type: Option<String> = bcs::from_bytes(&output).map_err(|e| {
            SuiBridgeClientError::BlockchainDataError(format!(
                "get_coin_type returned malformed Option<String>: {e}"
            ))
        })?;
        coin_type.ok_or_else(|| {
            SuiBridgeClientError::BlockchainDataError(format!(
                "token 0x{} is not registered in the Sui bridge token registry",
                hex::encode(token_address)
            ))
        })
    }

    /// Call a read-only `omni_bridge` view function via an unsigned
    /// simulation and return the BCS bytes of its return value.
    async fn call_view(&self, function: &str, pure_args: Vec<Vec<u8>>) -> Result<Vec<u8>> {
        let bridge = self.bridge_address()?;
        let state_id = self.state_object_id()?;
        let (state_version, _) = self.shared_object_start_version(state_id).await?;
        let sender = self
            .account
            .as_ref()
            .map_or(Address::ZERO, |account| account.address);

        let mut inputs = vec![Input::Shared(SharedInput::new(
            state_id,
            state_version,
            false,
        ))];
        inputs.extend(pure_args.into_iter().map(Input::Pure));
        let arguments = (0..inputs.len())
            .map(|i| {
                Argument::Input(u16::try_from(i).expect("view calls have a handful of inputs"))
            })
            .collect();

        // Checks are disabled, so the node synthesizes a mock gas coin for
        // the empty payment. The price must be non-zero: `price == 0` with no
        // payment classifies the transaction as "gasless" (address-balance
        // paid), which only allowlisted functions support.
        let transaction = Transaction {
            kind: TransactionKind::ProgrammableTransaction(ProgrammableTransaction {
                inputs,
                commands: vec![Command::MoveCall(MoveCall {
                    package: bridge,
                    module: Identifier::from_static(MODULE_NAME),
                    function: Identifier::new(function).map_err(|e| {
                        SuiBridgeClientError::InvalidArgument(format!(
                            "invalid view function name {function:?}: {e}"
                        ))
                    })?,
                    type_arguments: vec![],
                    arguments,
                })],
            }),
            sender,
            gas_payment: GasPayment {
                objects: vec![],
                owner: sender,
                price: 1000,
                budget: 1_000_000_000,
            },
            expiration: TransactionExpiration::None,
        };

        let request = SimulateTransactionRequest::default()
            .with_transaction(transaction)
            .with_checks(TransactionChecks::Disabled)
            .with_read_mask(FieldMask::from_paths(["command_outputs"]));

        let response = self
            .rpc
            .clone()
            .execution_client()
            .simulate_transaction(request)
            .await
            .map_err(|status| rpc::rpc_error(&status))?
            .into_inner();

        response
            .command_outputs
            .first()
            .and_then(|command| command.return_values.first())
            .and_then(|output| output.value.as_ref())
            .and_then(|bcs| bcs.value.as_ref())
            .map(|bytes| bytes.to_vec())
            .ok_or_else(|| {
                SuiBridgeClientError::BlockchainDataError(format!(
                    "{function} view returned no value"
                ))
            })
    }

    /// Returns the configured MPC finality level for this chain.
    pub fn mpc_finality(&self) -> Result<SuiFinality> {
        self.mpc_finality.clone().ok_or_else(|| {
            SuiBridgeClientError::ConfigError("MPC finality is not configured".to_string())
        })
    }

    /// Verifies that `tx_hash` has reached the configured MPC finality level
    /// and returns it for embedding in the MPC sign payload. For Sui,
    /// `Checkpointed` means the transaction executed successfully and is
    /// included in a committee-certified checkpoint.
    pub async fn check_mpc_finality(&self, tx_hash: &str) -> Result<SuiFinality> {
        let finality = self.mpc_finality()?;
        let Some(executed) = rpc::get_transaction_opt(
            &mut self.rpc.clone(),
            tx_hash,
            &["digest", "checkpoint", "effects.status"],
        )
        .await?
        else {
            return Err(SuiBridgeClientError::MpcFinalityNotReached);
        };

        if !executed.effects().status().success() {
            return Err(SuiBridgeClientError::TransactionError(format!(
                "transaction {tx_hash} failed: {}",
                executed.effects().status().error()
            )));
        }
        if executed.checkpoint.is_none() {
            return Err(SuiBridgeClientError::MpcFinalityNotReached);
        }
        Ok(finality)
    }

    /// Decode the `InitTransfer` event from a transaction.
    pub async fn get_transfer_event(&self, tx_hash: &str) -> Result<SuiInitTransferEvent> {
        let log = self.get_init_transfer_log(tx_hash).await?;
        bcs::from_bytes(&log.bcs).map_err(|e| {
            SuiBridgeClientError::BlockchainDataError(format!(
                "InitTransfer event has malformed BCS contents: {e}"
            ))
        })
    }

    /// Raw `InitTransfer` log with metadata for MPC proof construction.
    pub async fn get_init_transfer_log(&self, tx_hash: &str) -> Result<SuiEventLog> {
        self.get_event_log(tx_hash, "InitTransfer").await
    }

    /// Raw `DeployToken` log with metadata for MPC proof construction.
    pub async fn get_deploy_token_log(&self, tx_hash: &str) -> Result<SuiEventLog> {
        self.get_event_log(tx_hash, "DeployToken").await
    }

    /// Raw `FinTransfer` log with metadata for MPC proof construction.
    pub async fn get_fin_transfer_log(&self, tx_hash: &str) -> Result<SuiEventLog> {
        self.get_event_log(tx_hash, "FinTransfer").await
    }

    /// Raw `LogMetadata` log with metadata for MPC proof construction.
    pub async fn get_log_metadata_log(&self, tx_hash: &str) -> Result<SuiEventLog> {
        self.get_event_log(tx_hash, "LogMetadata").await
    }

    async fn get_event_log(&self, tx_hash: &str, event_name: &str) -> Result<SuiEventLog> {
        let bridge = self.bridge_address()?;
        let executed = rpc::get_transaction(
            &mut self.rpc.clone(),
            tx_hash,
            &["digest", "events", "effects.status"],
        )
        .await?;

        let events = &executed.events().events;
        let (event_index, event) = events
            .iter()
            .enumerate()
            .find(|(_, event)| {
                event.event_type().parse::<StructTag>().is_ok_and(|tag| {
                    *tag.address() == bridge
                        && tag.module().as_str() == MODULE_NAME
                        && tag.name().as_str() == event_name
                })
            })
            .ok_or_else(|| {
                SuiBridgeClientError::BlockchainDataError(format!(
                    "{event_name} event not found in transaction {tx_hash}"
                ))
            })?;

        // Canonical long-form type tag — must match the MPC node's
        // `normalize_type_tag` (`sui_sdk_types::TypeTag` round-trip) exactly.
        let type_tag = event
            .event_type()
            .parse::<TypeTag>()
            .map_err(|e| {
                SuiBridgeClientError::BlockchainDataError(format!(
                    "malformed event type tag {:?}: {e}",
                    event.event_type()
                ))
            })?
            .to_string();

        Ok(SuiEventLog {
            package_id: parse_address_field(event.package_id(), "package_id")?,
            transaction_module: event.module().to_string(),
            sender: parse_address_field(event.sender(), "sender")?,
            type_tag,
            bcs: event.contents().value().to_vec(),
            event_index: event_index as u64,
        })
    }

    /// Locate the `CoinMetadata<T>` (or coin-registry `Currency<T>`) object
    /// for a coin type and prepare it as a PTB input.
    async fn coin_metadata_object(&self, coin_type: &StructTag) -> Result<CoinMetadataInput> {
        let mut client = self.rpc.clone();
        let response = client
            .state_client()
            .get_coin_info(
                sui_rpc::proto::sui::rpc::v2::GetCoinInfoRequest::default()
                    .with_coin_type(coin_type.to_string()),
            )
            .await
            .map_err(|status| rpc::rpc_error(&status))?
            .into_inner();

        let metadata_id = response
            .metadata
            .as_ref()
            .and_then(|metadata| metadata.id.clone())
            .ok_or_else(|| {
                SuiBridgeClientError::BlockchainDataError(format!(
                    "no coin metadata object found for {coin_type}"
                ))
            })?;

        let object = rpc::get_object(
            &mut client,
            &metadata_id,
            &["object_id", "version", "digest", "owner", "object_type"],
        )
        .await?;
        let object_id: Address = metadata_id.parse().map_err(|e| {
            SuiBridgeClientError::BlockchainDataError(format!(
                "invalid coin metadata object id {metadata_id:?}: {e}"
            ))
        })?;

        let is_registry_currency = object.object_type().parse::<StructTag>().is_ok_and(|tag| {
            *tag.address() == Address::TWO
                && tag.module().as_str() == "coin_registry"
                && tag.name().as_str() == "Currency"
        });

        let input = match object.owner().kind() {
            OwnerKind::Immutable => {
                let digest = object.digest().parse().map_err(|e| {
                    SuiBridgeClientError::BlockchainDataError(format!(
                        "invalid object digest for {metadata_id}: {e}"
                    ))
                })?;
                ObjectInput::immutable(object_id, object.version(), digest)
            }
            OwnerKind::Shared => {
                ObjectInput::shared(object_id, object.owner().version(), false)
            }
            OwnerKind::Address
                if self
                    .account
                    .as_ref()
                    .is_some_and(|account| account.address.to_string() == object.owner().address()) =>
            {
                let digest = object.digest().parse().map_err(|e| {
                    SuiBridgeClientError::BlockchainDataError(format!(
                        "invalid object digest for {metadata_id}: {e}"
                    ))
                })?;
                ObjectInput::owned(object_id, object.version(), digest)
            }
            other => {
                return Err(SuiBridgeClientError::InvalidArgument(format!(
                    "coin metadata object {metadata_id} has unsupported ownership {other:?} (owner: {})",
                    object.owner().address()
                )))
            }
        };

        Ok(CoinMetadataInput {
            input,
            is_registry_currency,
        })
    }
}

struct CoinMetadataInput {
    input: ObjectInput,
    is_registry_currency: bool,
}

/// The objects created by publishing a token-template package.
struct CreatedTokenObjects {
    coin_type: StructTag,
    treasury_cap: ObjectInput,
    upgrade_cap: ObjectInput,
    coin_metadata: ObjectInput,
}

impl CreatedTokenObjects {
    fn from_publish_effects(executed: &ExecutedTransaction, digest: &str) -> Result<Self> {
        let mut coin_type = None;
        let mut treasury_cap = None;
        let mut upgrade_cap = None;
        let mut coin_metadata = None;

        for changed in &executed.effects().changed_objects {
            if changed.id_operation() != IdOperation::Created {
                continue;
            }
            let Ok(tag) = changed.object_type().parse::<StructTag>() else {
                continue; // the package itself has object_type "package"
            };
            if *tag.address() != Address::TWO {
                continue;
            }
            let input = || -> Result<ObjectInput> {
                let object_id: Address = changed.object_id().parse().map_err(|e| {
                    SuiBridgeClientError::BlockchainDataError(format!(
                        "invalid created object id in {digest}: {e}"
                    ))
                })?;
                let object_digest = changed.output_digest().parse().map_err(|e| {
                    SuiBridgeClientError::BlockchainDataError(format!(
                        "invalid created object digest in {digest}: {e}"
                    ))
                })?;
                Ok(ObjectInput::owned(
                    object_id,
                    changed.output_version(),
                    object_digest,
                ))
            };
            match (tag.module().as_str(), tag.name().as_str()) {
                ("coin", "TreasuryCap") => {
                    coin_type = tag.type_params().first().cloned();
                    treasury_cap = Some(input()?);
                }
                ("package", "UpgradeCap") => upgrade_cap = Some(input()?),
                ("coin", "CoinMetadata") => coin_metadata = Some(input()?),
                _ => {}
            }
        }

        let missing = |what: &str| {
            SuiBridgeClientError::BlockchainDataError(format!(
                "publish transaction {digest} did not create a {what}"
            ))
        };
        let coin_type = match coin_type.ok_or_else(|| missing("TreasuryCap with a coin type"))? {
            TypeTag::Struct(tag) => *tag,
            other => {
                return Err(SuiBridgeClientError::BlockchainDataError(format!(
                    "TreasuryCap type parameter is not a struct: {other}"
                )))
            }
        };
        Ok(Self {
            coin_type,
            treasury_cap: treasury_cap.ok_or_else(|| missing("TreasuryCap"))?,
            upgrade_cap: upgrade_cap.ok_or_else(|| missing("UpgradeCap"))?,
            coin_metadata: coin_metadata.ok_or_else(|| missing("CoinMetadata"))?,
        })
    }
}

/// Parse a base58 Sui transaction digest into its raw 32 bytes (for
/// `SuiTxId` in MPC sign payloads).
pub fn parse_transaction_digest(digest: &str) -> std::result::Result<[u8; 32], String> {
    sui_sdk_types::Digest::from_base58(digest)
        .map(sui_sdk_types::Digest::into_inner)
        .map_err(|e| format!("invalid Sui transaction digest {digest:?}: {e}"))
}

/// The wire token id for a Sui coin: `keccak256` of the canonical coin type
/// string (64-hex defining package id without `0x`, then `::module::NAME`) —
/// mirrors `std::type_name` + keccak on-chain. Generic coin types are not
/// supported (bridge tokens are plain structs).
pub fn token_address_from_coin_type(coin_type: &str) -> std::result::Result<[u8; 32], String> {
    let tag: StructTag = coin_type
        .trim()
        .parse()
        .map_err(|e| format!("invalid coin type {coin_type:?}: {e}"))?;
    if !tag.type_params().is_empty() {
        return Err(format!(
            "generic coin types are not supported as bridge tokens: {coin_type}"
        ));
    }
    let canonical = format!(
        "{}::{}::{}",
        hex::encode(tag.address().into_inner()),
        tag.module(),
        tag.name()
    );
    Ok(Keccak256::digest(canonical.as_bytes()).into())
}

fn parse_struct_tag(coin_type: &str) -> Result<StructTag> {
    coin_type.trim().parse().map_err(|e| {
        SuiBridgeClientError::InvalidArgument(format!("invalid coin type {coin_type:?}: {e}"))
    })
}

fn parse_address_field(value: &str, field: &str) -> Result<[u8; 32]> {
    value
        .parse::<Address>()
        .map(Address::into_inner)
        .map_err(|e| {
            SuiBridgeClientError::BlockchainDataError(format!("invalid event {field}: {e}"))
        })
}

fn omni_address_to_sui(address: &OmniAddress) -> Result<[u8; 32]> {
    match address {
        OmniAddress::Sui(h256) => Ok(h256.0),
        other => Err(SuiBridgeClientError::InvalidArgument(format!(
            "Expected Sui address but got {other:?}"
        ))),
    }
}

fn to_coin_value(value: u128, what: &str) -> Result<u64> {
    u64::try_from(value).map_err(|_| {
        SuiBridgeClientError::InvalidArgument(format!(
            "{what} {value} exceeds u64 (Sui coin values are u64)"
        ))
    })
}

fn encode_pure<T: serde::Serialize>(value: &T) -> Result<Vec<u8>> {
    bcs::to_bytes(value).map_err(|e| {
        SuiBridgeClientError::InvalidArgument(format!("BCS serialization failed: {e}"))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_address_of_native_sui_matches_known_value() {
        // keccak256(b"0000...0002::sui::SUI") — the omni-types native token
        // constant for Sui, identical across networks.
        let id = token_address_from_coin_type("0x2::sui::SUI").unwrap();
        assert_eq!(
            hex::encode(id),
            "6696387aecbb705205026783042f803871c190570dd0a57882d9d35ee0df700c"
        );
        // Long-form input canonicalizes to the same id.
        let long = token_address_from_coin_type(
            "0x0000000000000000000000000000000000000000000000000000000000000002::sui::SUI",
        )
        .unwrap();
        assert_eq!(id, long);
    }

    #[test]
    fn token_address_rejects_generics_and_garbage() {
        assert!(token_address_from_coin_type("0x2::coin::Coin<0x2::sui::SUI>").is_err());
        assert!(token_address_from_coin_type("not-a-type").is_err());
    }

    #[test]
    fn init_transfer_event_bcs_roundtrip() {
        let event = SuiInitTransferEvent {
            sender: [0x11; 32],
            token_address: [0x22; 32],
            coin_type: "0000000000000000000000000000000000000000000000000000000000000002::sui::SUI"
                .to_string(),
            origin_nonce: 7,
            amount: 1_000_000,
            fee: 100,
            native_fee: 50,
            recipient: "near:alice.near".to_string(),
            message: vec![0xde, 0xad],
        };
        let bytes = bcs::to_bytes(&event).unwrap();
        let decoded: SuiInitTransferEvent = bcs::from_bytes(&bytes).unwrap();
        assert_eq!(decoded.sender, event.sender);
        assert_eq!(decoded.token_address, event.token_address);
        assert_eq!(decoded.origin_nonce, 7);
        assert_eq!(decoded.amount, 1_000_000);
        assert_eq!(decoded.fee, 100);
        assert_eq!(decoded.native_fee, 50);
        assert_eq!(decoded.recipient, "near:alice.near");
        assert_eq!(decoded.message, vec![0xde, 0xad]);
    }

    #[test]
    fn parses_transaction_digest_base58() {
        let digest = sui_sdk_types::Digest::new([0xAB; 32]);
        let parsed = parse_transaction_digest(&digest.to_base58()).unwrap();
        assert_eq!(parsed, [0xAB; 32]);
        assert!(parse_transaction_digest("not base58 !!!").is_err());
    }
}
