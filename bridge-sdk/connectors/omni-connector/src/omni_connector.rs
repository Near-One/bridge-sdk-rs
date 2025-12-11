use bitcoin::{secp256k1, OutPoint, TxOut};
use bridge_connector_common::result::{BridgeSdkError, Result};
use derive_builder::Builder;
use ethers::abi::AbiEncode;
use ethers::prelude::*;
use light_client::LightClient;
use near_primitives::hash::CryptoHash;
use near_primitives::types::AccountId;
use utxo_bridge_client::error::UtxoClientError;
use utxo_utils::address::{Network, UTXOAddress};

use omni_types::locker_args::{ClaimFeeArgs, StorageDepositAction};
use omni_types::prover_args::{EvmProof, EvmVerifyProofArgs, WormholeVerifyProofArgs};
use omni_types::prover_result::ProofKind;
use omni_types::{near_events::OmniBridgeEvent, ChainKind};
use omni_types::{
    EvmAddress, FastTransferId, FastTransferStatus, Fee, OmniAddress, TransferMessage, H160,
};

use bitcoin::hashes::Hash;
use bitcoin::key::rand::rngs::OsRng;
use evm_bridge_client::{EvmBridgeClient, InitTransferFilter};
use near_bridge_client::btc::{
    BtcVerifyWithdrawArgs, ChainSpecificData, DepositMsg, FinBtcTransferArgs,
    NearToBtcTransferInfo, TokenReceiverMessage, VUTXO,
};
use near_bridge_client::{Decimals, NearBridgeClient, TransactionOptions};
use pczt::roles::{
    creator::Creator, io_finalizer::IoFinalizer, prover::Prover, tx_extractor::TransactionExtractor,
};
use sha2::Digest;
use solana_bridge_client::{
    DeployTokenData, DepositPayload, FinalizeDepositData, MetadataPayload, SolanaBridgeClient,
    TransferId,
};
use solana_sdk::pubkey::Pubkey;
use solana_sdk::signature::{Keypair, Signature};
use std::str::FromStr;
use std::sync::OnceLock;
use utxo_bridge_client::{
    types::{Bitcoin, Zcash},
    UTXOBridgeClient,
};
use utxo_utils::get_gas_fee;
use utxo_utils::InputPoint;
use wormhole_bridge_client::WormholeBridgeClient;
use zcash_address::unified::{self, Container, Encoding};
use zcash_primitives::transaction::fees::zip317;
use zcash_primitives::transaction::sighash::SignableInput;
use zcash_primitives::transaction::sighash_v5;
use zcash_primitives::transaction::txid::TxIdDigester;
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

#[allow(clippy::struct_field_names)]
#[derive(Builder, Default)]
#[builder(pattern = "owned")]
pub struct OmniConnector {
    network: Option<Network>,
    near_bridge_client: Option<NearBridgeClient>,
    eth_bridge_client: Option<EvmBridgeClient>,
    base_bridge_client: Option<EvmBridgeClient>,
    arb_bridge_client: Option<EvmBridgeClient>,
    bnb_bridge_client: Option<EvmBridgeClient>,
    solana_bridge_client: Option<SolanaBridgeClient>,
    wormhole_bridge_client: Option<WormholeBridgeClient>,
    btc_bridge_client: Option<UTXOBridgeClient<Bitcoin>>,
    zcash_bridge_client: Option<UTXOBridgeClient<Zcash>>,
    eth_light_client: Option<LightClient>,
    btc_light_client: Option<LightClient>,
    zcash_light_client: Option<LightClient>,
}

macro_rules! forward_common_utxo_method {
    ($name:ident ( $($arg:ident : $ty:ty),* ) -> $ret:ty) => {
        pub async fn $name(&self, $($arg:$ty),*) -> $ret {
            match self {
                AnyUtxoClient::Btc(c)   => c.$name($($arg),*).await,
                AnyUtxoClient::Zcash(c) => c.$name($($arg),*).await,
            }
        }
    };
}

pub enum AnyUtxoClient<'a> {
    Btc(&'a UTXOBridgeClient<Bitcoin>),
    Zcash(&'a UTXOBridgeClient<Zcash>),
}

impl AnyUtxoClient<'_> {
    forward_common_utxo_method!(get_fee_rate() -> std::result::Result<u64, UtxoClientError>);
    forward_common_utxo_method!(extract_btc_proof(tx_hash: &str) -> std::result::Result<utxo_bridge_client::types::TxProof, UtxoClientError>);
    forward_common_utxo_method!(send_tx(tx_bytes: &[u8]) -> std::result::Result<String, UtxoClientError>);

    forward_common_utxo_method!(get_tree_state(current_u: u64) -> String);
    forward_common_utxo_method!(get_current_height() -> std::result::Result<u64, UtxoClientError>);
}

pub enum WormholeDeployTokenArgs {
    Transaction {
        chain_kind: ChainKind,
        tx_hash: String,
    },
    VAA {
        chain_kind: ChainKind,
        vaa: String,
    },
}

pub enum DeployTokenArgs {
    NearDeployToken {
        chain_kind: ChainKind,
        tx_hash: String,
        transaction_options: TransactionOptions,
    },
    NearDeployTokenWithEvmProof {
        chain_kind: ChainKind,
        tx_hash: TxHash,
        transaction_options: TransactionOptions,
    },
    EvmDeployToken {
        chain_kind: ChainKind,
        event: OmniBridgeEvent,
        tx_nonce: Option<U256>,
    },
    EvmDeployTokenWithTxHash {
        chain_kind: ChainKind,
        near_tx_hash: CryptoHash,
        tx_nonce: Option<U256>,
    },
    SolanaDeployToken {
        event: OmniBridgeEvent,
    },
    SolanaDeployTokenWithTxHash {
        near_tx_hash: CryptoHash,
        sender_id: Option<AccountId>,
    },
}

pub enum BindTokenArgs {
    BindTokenWithArgs {
        chain_kind: ChainKind,
        prover_args: Vec<u8>,
        transaction_options: TransactionOptions,
    },
    BindTokenWithEvmProofTx {
        chain_kind: ChainKind,
        tx_hash: TxHash,
        transaction_options: TransactionOptions,
    },
    BindTokenWithVaaProofTx {
        chain_kind: ChainKind,
        tx_hash: String,
        transaction_options: TransactionOptions,
    },
}

pub enum InitTransferArgs {
    NearInitTransfer {
        token: String,
        amount: u128,
        recipient: OmniAddress,
        fee: u128,
        native_fee: u128,
        transaction_options: TransactionOptions,
    },
    EvmInitTransfer {
        chain_kind: ChainKind,
        token: String,
        amount: u128,
        recipient: OmniAddress,
        fee: Fee,
        message: String,
        tx_nonce: Option<U256>,
    },
    SolanaInitTransfer {
        token: Pubkey,
        amount: u128,
        recipient: OmniAddress,
        fee: u128,
        native_fee: u64,
        message: String,
    },
    SolanaInitTransferSol {
        amount: u128,
        recipient: OmniAddress,
        fee: u128,
        native_fee: u64,
        message: String,
    },
}

pub enum FinTransferArgs {
    NearFinTransferWithEvmProof {
        chain_kind: ChainKind,
        destination_chain: ChainKind,
        tx_hash: TxHash,
        storage_deposit_actions: Vec<StorageDepositAction>,
        transaction_options: TransactionOptions,
    },
    NearFinTransferWithVaa {
        chain_kind: ChainKind,
        destination_chain: ChainKind,
        storage_deposit_actions: Vec<StorageDepositAction>,
        vaa: String,
        transaction_options: TransactionOptions,
    },
    NearFinTransferBTC {
        chain_kind: ChainKind,
        btc_tx_hash: String,
        vout: usize,
        btc_deposit_args: BtcDepositArgs,
        transaction_options: TransactionOptions,
    },
    EvmFinTransfer {
        chain_kind: ChainKind,
        event: OmniBridgeEvent,
        tx_nonce: Option<U256>,
    },
    EvmFinTransferWithTxHash {
        chain_kind: ChainKind,
        near_tx_hash: CryptoHash,
        tx_nonce: Option<U256>,
    },
    SolanaFinTransfer {
        event: OmniBridgeEvent,
        solana_token: Pubkey,
    },
    SolanaFinTransferWithTxHash {
        near_tx_hash: CryptoHash,
        sender_id: Option<AccountId>,
        solana_token: Pubkey,
    },
    UTXOChainFinTransfer {
        chain: ChainKind,
        near_tx_hash: CryptoHash,
        relayer: Option<AccountId>,
    },
}

pub enum BtcDepositArgs {
    OmniDepositArgs {
        recipient_id: OmniAddress,
        fee: u128,
    },
    DepositMsg {
        msg: DepositMsg,
    },
}
impl OmniConnector {
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn near_get_transfer_message(
        &self,
        transfer_id: omni_types::TransferId,
    ) -> Result<TransferMessage> {
        let near_bridge_client = self.near_bridge_client()?;
        near_bridge_client.get_transfer_message(transfer_id).await
    }

    pub async fn near_get_token_decimals(&self, token_address: OmniAddress) -> Result<Decimals> {
        let near_bridge_client = self.near_bridge_client()?;
        near_bridge_client.get_token_decimals(token_address).await
    }

    pub async fn near_is_transfer_finalised(
        &self,
        transfer_id: omni_types::TransferId,
    ) -> Result<bool> {
        let near_bridge_client = self.near_bridge_client()?;
        near_bridge_client.is_transfer_finalised(transfer_id).await
    }

    pub async fn near_get_token_id(&self, token_address: OmniAddress) -> Result<AccountId> {
        let near_bridge_client = self.near_bridge_client()?;
        near_bridge_client.get_token_id(token_address).await
    }

    pub async fn near_get_native_token_id(&self, origin_chain: ChainKind) -> Result<AccountId> {
        let near_bridge_client = self.near_bridge_client()?;
        near_bridge_client.get_native_token_id(origin_chain).await
    }

    pub async fn near_get_fast_transfer_status(
        &self,
        fast_transfer_id: FastTransferId,
    ) -> Result<Option<FastTransferStatus>> {
        let near_bridge_client = self.near_bridge_client()?;
        near_bridge_client
            .get_fast_transfer_status(fast_transfer_id)
            .await
    }

    pub async fn near_is_fast_transfer_finalised(
        &self,
        fast_transfer_id: FastTransferId,
    ) -> Result<bool> {
        let near_bridge_client = self.near_bridge_client()?;
        near_bridge_client
            .is_fast_transfer_finalised(fast_transfer_id)
            .await
    }

    pub async fn near_log_metadata(
        &self,
        token_id: String,
        transaction_options: TransactionOptions,
    ) -> Result<CryptoHash> {
        let near_bridge_client = self.near_bridge_client()?;
        near_bridge_client
            .log_token_metadata(token_id, transaction_options)
            .await
    }

    pub async fn near_deploy_token_with_vaa_proof(
        &self,
        args: WormholeDeployTokenArgs,
        transaction_options: TransactionOptions,
    ) -> Result<CryptoHash> {
        let near_bridge_client = self.near_bridge_client()?;

        match args {
            WormholeDeployTokenArgs::Transaction {
                chain_kind,
                tx_hash,
            } => {
                let vaa = self.wormhole_get_vaa_by_tx_hash(tx_hash).await?;

                near_bridge_client
                    .deploy_token_with_vaa_proof(chain_kind, &vaa, transaction_options)
                    .await
            }
            WormholeDeployTokenArgs::VAA { chain_kind, vaa } => {
                near_bridge_client
                    .deploy_token_with_vaa_proof(chain_kind, &vaa, transaction_options)
                    .await
            }
        }
    }

    pub async fn near_bind_token(
        &self,
        bind_token_args: omni_types::locker_args::BindTokenArgs,
        transaction_options: TransactionOptions,
    ) -> Result<CryptoHash> {
        let near_bridge_client = self.near_bridge_client()?;
        near_bridge_client
            .bind_token(bind_token_args, transaction_options)
            .await
    }

    pub async fn near_get_required_storage_deposit(
        &self,
        token_id: AccountId,
        account_id: AccountId,
    ) -> Result<u128> {
        let near_bridge_client = self.near_bridge_client()?;
        near_bridge_client
            .get_required_storage_deposit(token_id, account_id)
            .await
    }

    pub async fn near_storage_deposit_for_token(
        &self,
        token_id: AccountId,
        amount: u128,
        account_id: AccountId,
        transaction_options: TransactionOptions,
    ) -> Result<CryptoHash> {
        let near_bridge_client = self.near_bridge_client()?;
        near_bridge_client
            .storage_deposit_for_token(token_id, account_id, amount, transaction_options)
            .await
    }

    pub async fn near_sign_transfer(
        &self,
        transfer_id: omni_types::TransferId,
        fee_recipient: Option<AccountId>,
        fee: Option<Fee>,
        transaction_options: TransactionOptions,
    ) -> Result<CryptoHash> {
        let near_bridge_client = self.near_bridge_client()?;
        near_bridge_client
            .sign_transfer(transfer_id, fee_recipient, fee, transaction_options)
            .await
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn near_init_transfer(
        &self,
        token_id: String,
        amount: u128,
        receiver: OmniAddress,
        fee: u128,
        native_fee: u128,
        transaction_options: TransactionOptions,
    ) -> Result<CryptoHash> {
        let near_bridge_client = self.near_bridge_client()?;
        near_bridge_client
            .init_transfer(
                token_id,
                amount,
                receiver,
                fee,
                native_fee,
                transaction_options,
            )
            .await
    }

    pub async fn near_fin_transfer_with_evm_proof(
        &self,
        chain_kind: ChainKind,
        destination_chain: ChainKind,
        tx_hash: TxHash,
        storage_deposit_actions: Vec<StorageDepositAction>,
        transaction_options: TransactionOptions,
    ) -> Result<CryptoHash> {
        let near_bridge_client = self.near_bridge_client()?;

        let proof = self
            .get_proof_for_event(tx_hash, ProofKind::InitTransfer, chain_kind)
            .await?;

        let verify_proof_args = EvmVerifyProofArgs {
            proof_kind: ProofKind::InitTransfer,
            proof,
        };

        near_bridge_client
            .fin_transfer(
                destination_chain,
                omni_types::locker_args::FinTransferArgs {
                    chain_kind,
                    storage_deposit_actions,
                    prover_args: borsh::to_vec(&verify_proof_args).map_err(|_| {
                        BridgeSdkError::EthProofError("Failed to serialize proof".to_string())
                    })?,
                },
                transaction_options,
            )
            .await
    }

    pub async fn near_sign_btc_transaction(
        &self,
        chain: ChainKind,
        btc_pending_id: String,
        sign_index: u64,
        transaction_options: TransactionOptions,
    ) -> Result<CryptoHash> {
        let near_bridge_client = self.near_bridge_client()?;

        near_bridge_client
            .sign_btc_transaction(chain, btc_pending_id, sign_index, transaction_options)
            .await
    }

    pub async fn near_sign_btc_transaction_with_tx_hash(
        &self,
        chain: ChainKind,
        near_tx_hash: CryptoHash,
        user_account_id: Option<AccountId>,
        sign_index: u64,
        transaction_options: TransactionOptions,
    ) -> Result<CryptoHash> {
        let near_bridge_client = self.near_bridge_client()?;

        near_bridge_client
            .sign_btc_transaction_with_tx_hash(
                chain,
                near_tx_hash,
                user_account_id,
                sign_index,
                transaction_options,
            )
            .await
    }

    pub async fn near_fin_transfer_btc(
        &self,
        chain: ChainKind,
        tx_hash: String,
        vout: usize,
        deposit_args: BtcDepositArgs,
        transaction_options: TransactionOptions,
    ) -> Result<CryptoHash> {
        let utxo_bridge_client = self.utxo_bridge_client(chain)?;
        let near_bridge_client = self.near_bridge_client()?;

        let proof_data = utxo_bridge_client.extract_btc_proof(&tx_hash).await?;

        let light_client = self.light_client(chain)?;
        let light_client_last_block = light_client.get_last_block_number().await?;

        let confirmations = near_bridge_client.get_confirmations(chain).await?;

        if proof_data.block_height + u64::from(confirmations) > light_client_last_block {
            return Err(BridgeSdkError::LightClientNotSynced(
                light_client_last_block,
            ));
        }

        let deposit_msg = match deposit_args {
            BtcDepositArgs::DepositMsg { msg } => msg,
            BtcDepositArgs::OmniDepositArgs { recipient_id, fee } => {
                near_bridge_client.get_deposit_msg_for_omni_bridge(recipient_id, fee)?
            }
        };

        let args = FinBtcTransferArgs {
            deposit_msg,
            tx_bytes: proof_data.tx_bytes,
            vout,
            tx_block_blockhash: proof_data.tx_block_blockhash,
            tx_index: proof_data.tx_index,
            merkle_proof: proof_data.merkle_proof,
        };

        near_bridge_client
            .fin_btc_transfer(chain, args, transaction_options)
            .await
    }

    pub async fn near_btc_verify_withdraw(
        &self,
        chain: ChainKind,
        tx_hash: String,
        transaction_options: TransactionOptions,
    ) -> Result<CryptoHash> {
        let utxo_bridge_client = self.utxo_bridge_client(chain)?;
        let near_bridge_client = self.near_bridge_client()?;

        let proof_data = utxo_bridge_client.extract_btc_proof(&tx_hash).await?;

        let light_client = self.light_client(chain)?;
        let light_client_last_block = light_client.get_last_block_number().await?;

        let confirmations = near_bridge_client.get_confirmations(chain).await?;

        if proof_data.block_height + u64::from(confirmations) > light_client_last_block {
            return Err(BridgeSdkError::LightClientNotSynced(
                light_client_last_block,
            ));
        }

        let args = BtcVerifyWithdrawArgs {
            tx_id: tx_hash,
            tx_block_blockhash: proof_data.tx_block_blockhash,
            tx_index: proof_data.tx_index,
            merkle_proof: proof_data.merkle_proof,
        };

        near_bridge_client
            .btc_verify_withdraw(chain, args, transaction_options)
            .await
    }

    pub async fn near_btc_cancel_withdraw(
        &self,
        chain: ChainKind,
        tx_hash: String,
        transaction_options: TransactionOptions,
    ) -> Result<CryptoHash> {
        let near_bridge_client = self.near_bridge_client()?;

        near_bridge_client
            .btc_cancel_withdraw(chain, tx_hash, transaction_options)
            .await
    }

    pub async fn near_btc_verify_active_utxo_management(
        &self,
        chain: ChainKind,
        tx_hash: String,
        transaction_options: TransactionOptions,
    ) -> Result<CryptoHash> {
        let utxo_bridge_client = self.utxo_bridge_client(chain)?;
        let near_bridge_client = self.near_bridge_client()?;

        let proof_data = utxo_bridge_client.extract_btc_proof(&tx_hash).await?;

        let light_client = self.light_client(chain)?;
        let light_client_last_block = light_client.get_last_block_number().await?;

        let confirmations = near_bridge_client.get_confirmations(chain).await?;

        if proof_data.block_height + u64::from(confirmations) > light_client_last_block {
            return Err(BridgeSdkError::LightClientNotSynced(
                light_client_last_block,
            ));
        }

        let args = BtcVerifyWithdrawArgs {
            tx_id: tx_hash,
            tx_block_blockhash: proof_data.tx_block_blockhash,
            tx_index: proof_data.tx_index,
            merkle_proof: proof_data.merkle_proof,
        };

        near_bridge_client
            .btc_verify_active_utxo_management(chain, args, transaction_options)
            .await
    }

    pub async fn get_btc_address(
        &self,
        chain: ChainKind,
        recipient_id: OmniAddress,
        fee: u128,
    ) -> Result<String> {
        let near_bridge_client = self.near_bridge_client()?;
        near_bridge_client
            .get_btc_address(chain, recipient_id, fee)
            .await
    }

    pub async fn active_utxo_management(
        &self,
        chain: ChainKind,
        transaction_options: TransactionOptions,
    ) -> Result<CryptoHash> {
        let utxo_bridge_client = self.utxo_bridge_client(chain)?;
        let fee_rate = utxo_bridge_client.get_fee_rate().await?;

        let near_bridge_client = self.near_bridge_client()?;

        let utxos = near_bridge_client.get_utxos(chain).await?;
        let (
            active_management_lower_limit,
            active_management_upper_limit,
            max_active_utxo_management_input_number,
            max_active_utxo_management_output_number,
        ) = near_bridge_client
            .get_active_management_limit(chain)
            .await?;

        let change_address = near_bridge_client.get_change_address(chain).await?;
        let min_deposit_amount = near_bridge_client.get_min_deposit_amount(chain).await?;

        let (out_points, tx_outs) = utxo_utils::choose_utxos_for_active_management(
            utxos,
            fee_rate,
            &change_address,
            (
                active_management_lower_limit.try_into().unwrap(),
                active_management_upper_limit.try_into().unwrap(),
            ),
            max_active_utxo_management_input_number.into(),
            max_active_utxo_management_output_number.into(),
            min_deposit_amount.try_into().unwrap(),
            chain,
            self.network()?,
        )
        .map_err(BridgeSdkError::UtxoManagementError)?;

        near_bridge_client
            .active_utxo_management(chain, out_points, tx_outs, transaction_options)
            .await
    }

    pub async fn init_near_to_bitcoin_transfer(
        &self,
        chain: ChainKind,
        target_btc_address: String,
        amount: u128,
        enable_orchard: bool,
        transaction_options: TransactionOptions,
    ) -> Result<CryptoHash> {
        let utxo_bridge_client = self.utxo_bridge_client(chain)?;
        let fee_rate = utxo_bridge_client.get_fee_rate().await?;

        let near_bridge_client = self.near_bridge_client()?;
        let utxos = near_bridge_client.get_utxos(chain).await?;

        let withdraw_fee = near_bridge_client.get_withdraw_fee(chain).await?;

        let net_amount = amount.checked_sub(withdraw_fee).ok_or_else(|| {
            BridgeSdkError::InvalidArgument("Amount is smaller than `withdraw_fee`".to_string())
        })?;

        let (selected_utxo, utxos_balance) = utxo_utils::choose_utxos(net_amount, utxos)
            .map_err(BridgeSdkError::UtxoManagementError)?;
        let out_points = utxo_utils::utxo_to_out_points(selected_utxo.clone()).map_err(|e| {
            BridgeSdkError::UtxoClientError(format!("Error on get input points: {e}"))
        })?;
        let gas_fee = get_gas_fee(
            chain,
            selected_utxo.clone().len().try_into().unwrap(),
            2 - enable_orchard as u64,
            fee_rate,
            false,
        )
        .into();
        // TODO: use extract_utxo method
        let change_address = near_bridge_client.get_change_address(chain).await?;
        let tx_outs = utxo_utils::get_tx_outs(
            &target_btc_address,
            net_amount
                .checked_sub(gas_fee)
                .ok_or_else(|| {
                    BridgeSdkError::InvalidArgument("Amount is smaller than `gas_fee`".to_string())
                })?
                .try_into()
                .map_err(|err| {
                    BridgeSdkError::InvalidLog(format!("Error on amount conversion: {err}"))
                })?,
            &change_address,
            utxos_balance
                .checked_sub(net_amount)
                .ok_or_else(|| BridgeSdkError::InsufficientUTXOBalance)?
                .try_into()
                .map_err(|err| {
                    BridgeSdkError::InvalidArgument(format!(
                        "Error on change amount conversion: {err}"
                    ))
                })?,
            chain,
            self.network()?,
        )
        .map_err(|err| BridgeSdkError::UtxoClientError(format!("Error on get tx out: {err}")))?;

        let (orchard, expiry_height, output) = if enable_orchard {
            let (orchard, expiry_height) = self
                .get_orchard_raw(
                    tx_outs[0].clone(),
                    tx_outs.get(1),
                    target_btc_address.clone(),
                    utxo_utils::utxo_to_input_points(selected_utxo).map_err(|e| {
                        BridgeSdkError::UtxoClientError(format!("Error on get input points: {e}"))
                    })?,
                )
                .await;
            let mut output = vec![];
            if tx_outs.len() == 2 {
                output.push(tx_outs[1].clone());
            }

            (Some(orchard), Some(expiry_height), output)
        } else {
            (None, None, tx_outs)
        };

        near_bridge_client
            .init_btc_transfer_near_to_btc(
                chain,
                amount,
                TokenReceiverMessage::Withdraw {
                    target_btc_address,
                    input: out_points,
                    output,
                    max_gas_fee: None,
                    chain_specific_data: Some(ChainSpecificData {
                        orchard_bundle_bytes: orchard.map(|v| v.into()),
                        expiry_height: expiry_height,
                    }),
                },
                transaction_options,
            )
            .await
    }

    fn orchard_anchor_from_legacy_orchard_tree_hex(tree_hex: &str) -> orchard::Anchor {
        let tree: incrementalmerkletree::frontier::CommitmentTree<
            orchard::tree::MerkleHashOrchard,
            32,
        > = zcash_primitives::merkle_tree::read_commitment_tree(
            hex::decode(tree_hex).unwrap().as_slice(),
        )
        .unwrap();

        let root = tree.root().to_bytes();
        orchard::Anchor::from_bytes(root).unwrap()
    }

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

    async fn get_orchard_raw(
        &self,
        tx_out: TxOut,
        tx_out_change: Option<&TxOut>,
        recipient: String,
        input_points: Vec<InputPoint>,
    ) -> (Vec<u8>, u32) {
        let (_, ua) = unified::Address::decode(&recipient).expect("Invalid unified address");
        let mut recipient = None;
        for receiver in ua.items() {
            match receiver {
                unified::Receiver::Orchard(orchard_receiver) => {
                    recipient = Some(orchard_receiver);
                }
                _ => {}
            }
        }
        let recipient = orchard::Address::from_raw_address_bytes(&recipient.unwrap());

        let utxo_bridge_client = self.utxo_bridge_client(ChainKind::Zcash).unwrap();

        let current_height = utxo_bridge_client.get_current_height().await.unwrap();
        let tree_state = utxo_bridge_client.get_tree_state(current_height).await;
        let anchor = Self::orchard_anchor_from_legacy_orchard_tree_hex(&tree_state);
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
                tx_out.value.to_sat(),
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

        let mut buf = Vec::new();
        tx.write(&mut buf).unwrap();

        let auth_data = tx.into_data();
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

        let mut writer = Vec::new();
        zcash_primitives::transaction::components::orchard::write_v5_bundle(
            tx_orchard,
            &mut writer,
        )
        .unwrap();

        (writer, auth_data.expiry_height().into())
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn near_submit_btc_transfer(
        &self,
        chain: ChainKind,
        recipient: String,
        amount: u128,
        fee_rate: Option<u64>,
        transfer_id: omni_types::TransferId,
        transaction_options: TransactionOptions,
        max_gas_fee: Option<u64>,
    ) -> Result<CryptoHash> {
        let near_bridge_client = self.near_bridge_client()?;
        let fee = near_bridge_client.get_withdraw_fee(chain).await?;
        let (out_points, tx_outs, gas_fee) = self
            .extract_utxo(
                chain,
                recipient.clone(),
                amount.checked_sub(fee).ok_or_else(|| {
                    BridgeSdkError::InvalidArgument("Amount is smaller than `fee`".to_string())
                })?,
                fee_rate,
            )
            .await?;

        let max_gas_fee = if let Some(max_gas_fee) = max_gas_fee {
            if gas_fee > max_gas_fee {
                return Err(BridgeSdkError::InsufficientUTXOGasFee(format!(
                    "Estimated gas fee = {gas_fee}, but max gas fee = {max_gas_fee}"
                )));
            }
            Some(near_sdk::json_types::U128::from(u128::from(max_gas_fee)))
        } else {
            None
        };

        near_bridge_client
            .submit_btc_transfer(
                transfer_id,
                TokenReceiverMessage::Withdraw {
                    target_btc_address: recipient,
                    input: out_points,
                    output: tx_outs,
                    max_gas_fee,
                    chain_specific_data: None,
                },
                transaction_options,
            )
            .await
    }

    pub async fn near_rbf_increase_gas_fee(
        &self,
        chain: ChainKind,
        btc_tx_hash: String,
        fee_rate: Option<u64>,
        transaction_options: TransactionOptions,
    ) -> Result<CryptoHash> {
        let near_bridge_client = self.near_bridge_client()?;

        if chain == ChainKind::Zcash {
            return near_bridge_client
                .btc_rbf_increase_gas_fee(chain, btc_tx_hash, vec![], transaction_options)
                .await;
        }

        let btc_pending_info = near_bridge_client
            .get_btc_pending_info(chain, btc_tx_hash.clone())
            .await?;
        let utxo_balance = btc_pending_info
            .vutxos
            .iter()
            .map(|utxo| match utxo {
                VUTXO::Current(utxo) => utxo.balance,
            })
            .sum::<u64>();

        let btc_tx = utxo_utils::bytes_to_btc_transaction(
            &btc_pending_info.clone().tx_bytes_with_sign.ok_or_else(|| {
                BridgeSdkError::InvalidArgument("BTC transaction is not signed".to_string())
            })?,
        );
        let change_address = near_bridge_client.get_change_address(chain).await?;

        let change_address =
            UTXOAddress::parse(&change_address, chain, self.network()?).map_err(|e| {
                BridgeSdkError::ContractConfigurationError(format!(
                    "Invalid change UTXO address '{change_address}': {e}"
                ))
            })?;
        let change_script_pubkey = change_address.script_pubkey().map_err(|e| {
            BridgeSdkError::ContractConfigurationError(format!(
                "Failed to get script_pubkey for change UTXO address '{change_address}': {e}"
            ))
        })?;

        let target_address_script_pubkey = btc_tx
            .output
            .iter()
            .find(|v| v.script_pubkey != change_script_pubkey)
            .cloned()
            .ok_or_else(|| {
                BridgeSdkError::InvalidArgument(
                    "Failed to find target address in BTC transaction outputs".to_string(),
                )
            })?
            .script_pubkey;

        let utxo_bridge_client = self.utxo_bridge_client(chain)?;
        let fee_rate = match fee_rate {
            Some(rate) => rate,
            None => utxo_bridge_client.get_fee_rate().await?,
        };
        let gas_fee = get_gas_fee(
            chain,
            u64::try_from(btc_pending_info.vutxos.len()).map_err(|e| {
                BridgeSdkError::UnknownError(format!("UTXO length unexpectedly large: {e}"))
            })?,
            2,
            fee_rate,
            false,
        );

        let net_amount = u64::try_from(
            btc_pending_info
                .transfer_amount
                .checked_sub(btc_pending_info.withdraw_fee)
                .ok_or_else(|| {
                    BridgeSdkError::InvalidArgument("Withdraw fee is too large".to_string())
                })?,
        )
        .map_err(|e| {
            BridgeSdkError::UnknownError(format!("Transaction amount unexpectedly large: {e}"))
        })?;
        let outs = utxo_utils::get_tx_outs_script_pubkey(
            target_address_script_pubkey,
            net_amount.checked_sub(gas_fee).ok_or_else(|| {
                BridgeSdkError::InvalidArgument("Amount is too small".to_string())
            })?,
            change_script_pubkey,
            utxo_balance.checked_sub(net_amount).ok_or_else(|| {
                BridgeSdkError::InvalidArgument("Utxo balance is too small".to_string())
            })?,
        );

        near_bridge_client
            .btc_rbf_increase_gas_fee(chain, btc_tx_hash, outs, transaction_options)
            .await
    }

    pub async fn near_submit_btc_transfer_with_tx_hash(
        &self,
        chain: ChainKind,
        near_tx_hash: CryptoHash,
        sender_id: Option<AccountId>,
        fee_rate: Option<u64>,
        transaction_options: TransactionOptions,
    ) -> Result<CryptoHash> {
        let near_bridge_client = self.near_bridge_client()?;
        let NearToBtcTransferInfo {
            recipient,
            amount,
            transfer_id,
            max_gas_fee,
        } = near_bridge_client
            .extract_recipient_and_amount_from_logs(near_tx_hash, sender_id)
            .await?;

        self.near_submit_btc_transfer(
            chain,
            recipient,
            amount,
            fee_rate,
            transfer_id,
            transaction_options,
            max_gas_fee,
        )
        .await
    }
    pub async fn btc_fin_transfer(
        &self,
        chain: ChainKind,
        near_tx_hash: CryptoHash,
        relayer: Option<AccountId>,
    ) -> Result<String> {
        let near_bridge_client = self.near_bridge_client().unwrap();
        let btc_tx_data = near_bridge_client
            .get_btc_tx_data(chain, near_tx_hash, relayer)
            .await
            .unwrap();

        let tx = zcash_primitives::transaction::Transaction::read(
            &btc_tx_data[..],
            zcash_protocol::consensus::BranchId::Nu6_1,
        )
        .unwrap();

        println!("TX: {:?}", tx);

        let tx_id = *tx.txid().as_ref();
        if let Some(bundle) = tx.into_data().orchard_bundle().clone() {
            bundle.verify_proof(orchard_verifying_key()).unwrap();
            let mut validator = orchard::bundle::BatchValidator::new();
            validator.add_bundle(bundle, tx_id);
            println!(
                "Validate: {:?}",
                validator.validate(orchard_verifying_key(), OsRng)
            );
            println!("Proof is verifiuyed!!");
        }

        let utxo_bridge_client = self.utxo_bridge_client(chain).unwrap();
        let tx_hash = utxo_bridge_client.send_tx(&btc_tx_data).await.unwrap();
        Ok(tx_hash)
    }

    pub async fn get_amount_to_transfer(&self, chain: ChainKind, amount: u128) -> Result<u128> {
        let near_bridge_client = self.near_bridge_client()?;
        near_bridge_client
            .get_amount_to_transfer(chain, amount)
            .await
    }

    pub async fn near_fin_transfer_with_vaa(
        &self,
        chain_kind: ChainKind,
        destination_chain: ChainKind,
        storage_deposit_actions: Vec<StorageDepositAction>,
        vaa: String,
        transaction_options: TransactionOptions,
    ) -> Result<CryptoHash> {
        let near_bridge_client = self.near_bridge_client()?;

        let verify_proof_args = WormholeVerifyProofArgs {
            proof_kind: ProofKind::InitTransfer,
            vaa,
        };

        near_bridge_client
            .fin_transfer(
                destination_chain,
                omni_types::locker_args::FinTransferArgs {
                    chain_kind,
                    storage_deposit_actions,
                    prover_args: borsh::to_vec(&verify_proof_args).map_err(|_| {
                        BridgeSdkError::EthProofError("Failed to serialize proof".to_string())
                    })?,
                },
                transaction_options,
            )
            .await
    }

    pub async fn near_claim_fee(
        &self,
        claim_fee_args: ClaimFeeArgs,
        transaction_options: TransactionOptions,
    ) -> Result<CryptoHash> {
        let near_bridge_client = self.near_bridge_client()?;
        near_bridge_client
            .claim_fee(claim_fee_args, transaction_options)
            .await
    }

    pub async fn near_bind_token_with_evm_proof(
        &self,
        chain_kind: ChainKind,
        tx_hash: TxHash,
        transaction_options: TransactionOptions,
    ) -> Result<CryptoHash> {
        let near_bridge_client = self.near_bridge_client()?;

        let proof = self
            .get_proof_for_event(tx_hash, ProofKind::DeployToken, chain_kind)
            .await?;

        let verify_proof_args = EvmVerifyProofArgs {
            proof_kind: ProofKind::DeployToken,
            proof,
        };

        near_bridge_client
            .bind_token(
                omni_types::locker_args::BindTokenArgs {
                    chain_kind,
                    prover_args: borsh::to_vec(&verify_proof_args).map_err(|_| {
                        BridgeSdkError::EthProofError("Failed to serialize proof".to_string())
                    })?,
                },
                transaction_options,
            )
            .await
    }

    pub async fn near_deploy_token_with_evm_proof(
        &self,
        chain_kind: ChainKind,
        tx_hash: TxHash,
        transaction_options: TransactionOptions,
    ) -> Result<CryptoHash> {
        let near_bridge_client = self.near_bridge_client()?;

        let proof = self
            .get_proof_for_event(tx_hash, ProofKind::LogMetadata, chain_kind)
            .await?;

        let verify_proof_args = EvmVerifyProofArgs {
            proof_kind: ProofKind::LogMetadata,
            proof,
        };

        near_bridge_client
            .deploy_token_with_evm_proof(
                omni_types::locker_args::DeployTokenArgs {
                    chain_kind,
                    prover_args: borsh::to_vec(&verify_proof_args).map_err(|_| {
                        BridgeSdkError::EthProofError("Failed to serialize proof".to_string())
                    })?,
                },
                transaction_options,
            )
            .await
    }

    pub async fn near_fast_transfer(
        &self,
        chain_kind: ChainKind,
        tx_hash: String,
        storage_deposit_amount: Option<u128>,
        transaction_options: TransactionOptions,
    ) -> Result<CryptoHash> {
        if let ChainKind::Sol | ChainKind::Near = chain_kind {
            return Err(BridgeSdkError::ConfigError(format!(
                "Fast transfer is not supported for chain kind: {chain_kind:?}"
            )));
        }

        let near_bridge_client = self.near_bridge_client()?;

        let tx_hash = TxHash::from_str(&tx_hash).map_err(|e| {
            BridgeSdkError::InvalidArgument(format!("Failed to parse tx hash: {e}"))
        })?;

        let transfer_event = self.evm_get_transfer_event(chain_kind, tx_hash).await?;

        let recipient = OmniAddress::from_str(&transfer_event.recipient).map_err(|_| {
            BridgeSdkError::InvalidArgument(format!(
                "Failed to parse recipient: {}",
                transfer_event.recipient
            ))
        })?;
        let token_address =
            OmniAddress::new_from_evm_address(chain_kind, H160(transfer_event.token_address.0))
                .map_err(|_| {
                    BridgeSdkError::InvalidArgument(format!(
                        "Failed to parse token address: {}",
                        transfer_event.token_address
                    ))
                })?;

        let token_id = near_bridge_client
            .get_token_id(token_address.clone())
            .await?;

        if transfer_event.amount < transfer_event.fee {
            return Err(BridgeSdkError::InvalidArgument(format!(
                "Transfer amount is less than fee: {} < {}",
                transfer_event.amount, transfer_event.fee
            )));
        }

        let relayer = near_bridge_client.account_id()?;
        let decimals = self.near_get_token_decimals(token_address).await?;
        let amount_to_send =
            self.denormalize_amount(&decimals, transfer_event.amount - transfer_event.fee)?;
        let balance = near_bridge_client
            .ft_balance_of(token_id.clone(), relayer)
            .await?;

        if balance < amount_to_send {
            return Err(BridgeSdkError::InsufficientBalance(format!(
                "Insufficient balance for fast transfer: {balance} < {amount_to_send}",
            )));
        }

        near_bridge_client
            .fast_fin_transfer(
                near_bridge_client::FastFinTransferArgs {
                    token_id,
                    amount_to_send,
                    recipient,
                    amount: transfer_event.amount,
                    fee: Fee {
                        fee: transfer_event.fee.into(),
                        native_fee: transfer_event.native_token_fee.into(),
                    },
                    transfer_id: omni_types::TransferId {
                        origin_chain: chain_kind,
                        origin_nonce: transfer_event.origin_nonce,
                    },
                    msg: transfer_event.message,
                    storage_deposit_amount,
                    relayer: near_bridge_client.signer()?.account_id,
                },
                transaction_options,
            )
            .await
    }

    pub async fn evm_is_transfer_finalised(
        &self,
        chain_kind: ChainKind,
        nonce: u64,
    ) -> Result<bool> {
        let evm_bridge_client = self.evm_bridge_client(chain_kind)?;
        evm_bridge_client.is_transfer_finalised(nonce).await
    }

    pub async fn evm_get_last_block_number(&self, chain_kind: ChainKind) -> Result<u64> {
        let evm_bridge_client = self.evm_bridge_client(chain_kind)?;
        evm_bridge_client.get_last_block_number().await
    }

    pub async fn evm_get_transfer_event(
        &self,
        chain_kind: ChainKind,
        tx_hash: TxHash,
    ) -> Result<InitTransferFilter> {
        let evm_bridge_client = self.evm_bridge_client(chain_kind)?;
        evm_bridge_client.get_transfer_event(tx_hash).await
    }

    pub async fn evm_log_metadata(
        &self,
        address: EvmAddress,
        chain_kind: ChainKind,
        tx_nonce: Option<U256>,
    ) -> Result<TxHash> {
        let evm_bridge_client = self.evm_bridge_client(chain_kind)?;
        evm_bridge_client.log_metadata(address, tx_nonce).await
    }

    pub async fn evm_deploy_token(
        &self,
        chain_kind: ChainKind,
        event: OmniBridgeEvent,
        tx_nonce: Option<U256>,
    ) -> Result<TxHash> {
        let evm_bridge_client = self.evm_bridge_client(chain_kind)?;
        evm_bridge_client.deploy_token(event, tx_nonce).await
    }

    pub async fn evm_deploy_token_with_tx_hash(
        &self,
        chain_kind: ChainKind,
        near_tx_hash: CryptoHash,
        tx_nonce: Option<U256>,
    ) -> Result<TxHash> {
        let near_bridge_client = self.near_bridge_client()?;
        let evm_bridge_client = self.evm_bridge_client(chain_kind)?;

        let transfer_log = near_bridge_client
            .extract_transfer_log(near_tx_hash, None, "LogMetadataEvent")
            .await?;

        evm_bridge_client
            .deploy_token(serde_json::from_str(&transfer_log)?, tx_nonce)
            .await
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn evm_init_transfer(
        &self,
        chain_kind: ChainKind,
        token: String,
        amount: u128,
        receiver: OmniAddress,
        fee: Fee,
        message: String,
        tx_nonce: Option<U256>,
    ) -> Result<TxHash> {
        let evm_bridge_client = self.evm_bridge_client(chain_kind)?;
        evm_bridge_client
            .init_transfer(
                ethers::types::H160::from_str(&token).map_err(|_| {
                    BridgeSdkError::InvalidArgument("Invalid token address".to_string())
                })?,
                amount,
                receiver,
                fee,
                message,
                tx_nonce,
            )
            .await
    }

    pub async fn evm_fin_transfer(
        &self,
        chain_kind: ChainKind,
        event: OmniBridgeEvent,
        tx_nonce: Option<U256>,
    ) -> Result<TxHash> {
        let evm_bridge_client = self.evm_bridge_client(chain_kind)?;
        evm_bridge_client.fin_transfer(event, tx_nonce).await
    }

    pub async fn evm_fin_transfer_with_tx_hash(
        &self,
        chain_kind: ChainKind,
        near_tx_hash: CryptoHash,
        tx_nonce: Option<U256>,
    ) -> Result<TxHash> {
        let evm_bridge_client = self.evm_bridge_client(chain_kind)?;
        let near_bridge_client = self.near_bridge_client()?;

        let transfer_log = near_bridge_client
            .extract_transfer_log(near_tx_hash, None, "SignTransferEvent")
            .await?;

        evm_bridge_client
            .fin_transfer(serde_json::from_str(&transfer_log)?, tx_nonce)
            .await
    }

    pub async fn solana_get_transfer_event(
        &self,
        signature: &Signature,
    ) -> Result<solana_bridge_client::Transfer> {
        let solana_bridge_client = self.solana_bridge_client()?;
        solana_bridge_client
            .get_transfer_event(signature)
            .await
            .map_err(|e| {
                BridgeSdkError::SolanaOtherError(format!("Failed to get transfer event: {e}"))
            })
    }

    pub async fn solana_is_transfer_finalised(&self, nonce: u64) -> Result<bool> {
        let solana_bridge_client = self.solana_bridge_client()?;

        solana_bridge_client
            .is_transfer_finalised(nonce)
            .await
            .map_err(|e| {
                BridgeSdkError::SolanaOtherError(format!(
                    "Failed to check transfer finalisation status: {e}"
                ))
            })
    }

    pub async fn solana_set_admin(&self, admin: Pubkey) -> Result<Signature> {
        let solana_bridge_client = self.solana_bridge_client()?;

        let signature = solana_bridge_client.set_admin(admin).await?;

        tracing::info!(
            signature = signature.to_string(),
            "Sent set admin transaction"
        );

        Ok(signature)
    }

    pub async fn solana_pause(&self) -> Result<Signature> {
        let solana_bridge_client = self.solana_bridge_client()?;

        let signature = solana_bridge_client.pause().await?;

        tracing::info!(signature = signature.to_string(), "Sent pause transaction");

        Ok(signature)
    }

    pub async fn solana_update_metadata(
        &self,
        token: Pubkey,
        name: Option<String>,
        symbol: Option<String>,
        uri: Option<String>,
    ) -> Result<Signature> {
        let solana_bridge_client = self.solana_bridge_client()?;

        let signature = solana_bridge_client
            .update_metadata(token, name, symbol, uri)
            .await?;

        tracing::info!(
            signature = signature.to_string(),
            "Sent update metadata transaction"
        );

        Ok(signature)
    }

    pub async fn solana_initialize(&self, program_keypair: Keypair) -> Result<Signature> {
        let near_bridge_account_id = self.near_bridge_client()?.omni_bridge_id()?;
        let derived_bridge_address =
            crypto_utils::derive_address(&near_bridge_account_id, "bridge-1");

        let solana_bridge_client = self.solana_bridge_client()?;

        let signature = solana_bridge_client
            .initialize(derived_bridge_address, program_keypair)
            .await?;

        tracing::info!(
            signature = signature.to_string(),
            "Sent initialize transaction"
        );

        Ok(signature)
    }

    pub async fn solana_get_version(&self) -> Result<String> {
        let solana_bridge_client = self.solana_bridge_client()?;

        let version = solana_bridge_client.get_version().await?;

        tracing::info!(version = version, "Fetched Solana program version");

        Ok(version)
    }

    pub async fn solana_log_metadata(&self, token: Pubkey) -> Result<Signature> {
        let solana_bridge_client = self.solana_bridge_client()?;

        let signature = solana_bridge_client.log_metadata(token).await?;

        tracing::info!(
            signature = signature.to_string(),
            "Sent register token transaction"
        );

        Ok(signature)
    }

    pub async fn solana_deploy_token_with_tx_hash(
        &self,
        near_tx_hash: CryptoHash,
        sender_id: Option<AccountId>,
    ) -> Result<Signature> {
        let near_bridge_client = self.near_bridge_client()?;

        let transfer_log = near_bridge_client
            .extract_transfer_log(near_tx_hash, sender_id, "LogMetadataEvent")
            .await?;

        self.solana_deploy_token_with_event(serde_json::from_str(&transfer_log)?)
            .await
    }

    pub async fn solana_deploy_token_with_event(
        &self,
        event: OmniBridgeEvent,
    ) -> Result<Signature> {
        let OmniBridgeEvent::LogMetadataEvent {
            signature,
            metadata_payload,
        } = event
        else {
            return Err(BridgeSdkError::UnknownError("Invalid event".to_string()));
        };

        let solana_bridge_client = self.solana_bridge_client()?;

        let mut signature = signature.to_bytes();
        signature[64] -= 27; // TODO: Remove recovery_id modification in OmniTypes and add it specifically when submitting to EVM chains

        let payload = DeployTokenData {
            metadata: MetadataPayload {
                token: metadata_payload.token,
                name: metadata_payload.name,
                symbol: metadata_payload.symbol,
                decimals: metadata_payload.decimals,
            },
            signature: signature.try_into().map_err(|_| {
                BridgeSdkError::ConfigError("Failed to parse signature".to_string())
            })?,
        };

        let signature = solana_bridge_client.deploy_token(payload).await?;

        tracing::info!(
            signature = signature.to_string(),
            "Sent deploy token transaction"
        );

        Ok(signature)
    }

    pub async fn solana_init_transfer(
        &self,
        token: Pubkey,
        amount: u128,
        recipient: OmniAddress,
        fee: u128,
        native_fee: u64,
        message: String,
    ) -> Result<Signature> {
        let solana_bridge_client = self.solana_bridge_client()?;

        let signature = solana_bridge_client
            .init_transfer(
                token,
                amount,
                recipient.to_string(),
                fee,
                native_fee,
                message,
            )
            .await?;

        tracing::info!(
            signature = signature.to_string(),
            "Sent init transfer transaction"
        );

        Ok(signature)
    }

    pub async fn solana_init_transfer_sol(
        &self,
        amount: u128,
        recipient: OmniAddress,
        fee: u128,
        native_fee: u64,
        message: String,
    ) -> Result<Signature> {
        let solana_bridge_client = self.solana_bridge_client()?;

        let signature = solana_bridge_client
            .init_transfer_sol(amount, recipient.to_string(), fee, native_fee, message)
            .await?;

        tracing::info!(
            signature = signature.to_string(),
            "Sent init transfer SOL transaction"
        );

        Ok(signature)
    }

    pub async fn solana_finalize_transfer_with_tx_hash(
        &self,
        near_tx_hash: CryptoHash,
        sender_id: Option<AccountId>,
        solana_token: Pubkey, // TODO: retrieve from near contract
    ) -> Result<Signature> {
        let near_bridge_client = self.near_bridge_client()?;

        let transfer_log = near_bridge_client
            .extract_transfer_log(near_tx_hash, sender_id, "SignTransferEvent")
            .await?;

        self.solana_finalize_transfer_with_event(serde_json::from_str(&transfer_log)?, solana_token)
            .await
    }

    pub async fn solana_finalize_transfer_with_event(
        &self,
        event: OmniBridgeEvent,
        solana_token: Pubkey, // TODO: retrieve from near contract
    ) -> Result<Signature> {
        let OmniBridgeEvent::SignTransferEvent {
            message_payload,
            signature,
        } = event
        else {
            return Err(BridgeSdkError::UnknownError("Invalid event".to_string()));
        };

        let solana_bridge_client = self.solana_bridge_client()?;

        let mut signature = signature.to_bytes();
        signature[64] -= 27;

        let payload = FinalizeDepositData {
            payload: DepositPayload {
                destination_nonce: message_payload.destination_nonce,
                transfer_id: TransferId {
                    origin_chain: message_payload.transfer_id.origin_chain.into(),
                    origin_nonce: message_payload.transfer_id.origin_nonce,
                },
                amount: message_payload.amount.into(),
                recipient: match message_payload.recipient {
                    OmniAddress::Sol(addr) => Pubkey::new_from_array(addr.0),
                    _ => return Err(BridgeSdkError::ConfigError("Invalid recipient".to_string())),
                },
                fee_recipient: message_payload.fee_recipient.map(|addr| addr.to_string()),
            },
            signature: signature.try_into().map_err(|_| {
                BridgeSdkError::ConfigError("Failed to parse signature".to_string())
            })?,
        };

        let signature = if solana_token == Pubkey::default() {
            solana_bridge_client.finalize_transfer_sol(payload).await?
        } else {
            solana_bridge_client
                .finalize_transfer(payload, solana_token)
                .await?
        };

        tracing::info!(
            signature = signature.to_string(),
            "Sent finalize transfer transaction"
        );

        Ok(signature)
    }

    pub async fn log_metadata(
        &self,
        token: OmniAddress,
        transaction_options: TransactionOptions,
    ) -> Result<String> {
        match &token {
            OmniAddress::Eth(address)
            | OmniAddress::Arb(address)
            | OmniAddress::Base(address)
            | OmniAddress::Bnb(address) => self
                .evm_log_metadata(
                    address.clone(),
                    token.get_chain(),
                    transaction_options.nonce.map(std::convert::Into::into),
                )
                .await
                .map(|hash| hash.to_string()),
            OmniAddress::Near(token_id) => self
                .near_log_metadata(token_id.to_string(), transaction_options)
                .await
                .map(|hash| hash.to_string()),
            OmniAddress::Sol(sol_address) => {
                let token = Pubkey::new_from_array(sol_address.0);
                self.solana_log_metadata(token)
                    .await
                    .map(|hash| hash.to_string())
            }
            OmniAddress::Btc(_) | OmniAddress::Zcash(_) => Err(BridgeSdkError::InvalidArgument(
                "Log metadata is not supported for this chain".to_string(),
            )),
        }
    }

    pub async fn deploy_token(&self, deploy_token_args: DeployTokenArgs) -> Result<String> {
        match deploy_token_args {
            DeployTokenArgs::NearDeployToken {
                chain_kind,
                tx_hash,
                transaction_options,
            } => self
                .near_deploy_token_with_vaa_proof(
                    WormholeDeployTokenArgs::Transaction {
                        chain_kind,
                        tx_hash,
                    },
                    transaction_options,
                )
                .await
                .map(|hash| hash.to_string()),
            DeployTokenArgs::NearDeployTokenWithEvmProof {
                chain_kind,
                tx_hash,
                transaction_options,
            } => self
                .near_deploy_token_with_evm_proof(chain_kind, tx_hash, transaction_options)
                .await
                .map(|hash| hash.to_string()),
            DeployTokenArgs::EvmDeployToken {
                chain_kind,
                event,
                tx_nonce,
            } => self
                .evm_deploy_token(chain_kind, event, tx_nonce)
                .await
                .map(|hash| hash.to_string()),
            DeployTokenArgs::EvmDeployTokenWithTxHash {
                chain_kind,
                near_tx_hash,
                tx_nonce,
            } => self
                .evm_deploy_token_with_tx_hash(chain_kind, near_tx_hash, tx_nonce)
                .await
                .map(|hash| hash.to_string()),
            DeployTokenArgs::SolanaDeployToken { event } => self
                .solana_deploy_token_with_event(event)
                .await
                .map(|hash| hash.to_string()),
            DeployTokenArgs::SolanaDeployTokenWithTxHash {
                near_tx_hash: tx_hash,
                sender_id,
            } => self
                .solana_deploy_token_with_tx_hash(tx_hash, sender_id)
                .await
                .map(|hash| hash.to_string()),
        }
    }

    pub async fn bind_token(&self, bind_token_args: BindTokenArgs) -> Result<String> {
        match bind_token_args {
            BindTokenArgs::BindTokenWithArgs {
                chain_kind,
                prover_args,
                transaction_options,
            } => self
                .near_bind_token(
                    omni_types::locker_args::BindTokenArgs {
                        chain_kind,
                        prover_args,
                    },
                    transaction_options,
                )
                .await
                .map(|hash| hash.to_string()),
            BindTokenArgs::BindTokenWithEvmProofTx {
                chain_kind,
                tx_hash,
                transaction_options,
            } => self
                .near_bind_token_with_evm_proof(chain_kind, tx_hash, transaction_options)
                .await
                .map(|hash| hash.to_string()),
            BindTokenArgs::BindTokenWithVaaProofTx {
                chain_kind,
                tx_hash,
                transaction_options,
            } => {
                let vaa = self.wormhole_get_vaa_by_tx_hash(tx_hash).await?;
                let args = omni_types::prover_args::WormholeVerifyProofArgs {
                    proof_kind: omni_types::prover_result::ProofKind::DeployToken,
                    vaa,
                };
                let bind_token_args = omni_types::locker_args::BindTokenArgs {
                    chain_kind,
                    prover_args: near_primitives::borsh::to_vec(&args).unwrap(),
                };

                self.near_bind_token(bind_token_args, transaction_options)
                    .await
                    .map(|hash| hash.to_string())
            }
        }
    }

    pub async fn init_transfer(&self, init_transfer_args: InitTransferArgs) -> Result<String> {
        match init_transfer_args {
            InitTransferArgs::NearInitTransfer {
                token: near_token_id,
                amount,
                recipient: receiver,
                fee,
                native_fee,
                transaction_options,
            } => self
                .near_init_transfer(
                    near_token_id,
                    amount,
                    receiver,
                    fee,
                    native_fee,
                    transaction_options,
                )
                .await
                .map(|tx_hash| tx_hash.to_string()),
            InitTransferArgs::EvmInitTransfer {
                chain_kind,
                token,
                amount,
                recipient: receiver,
                fee,
                message,
                tx_nonce,
            } => self
                .evm_init_transfer(chain_kind, token, amount, receiver, fee, message, tx_nonce)
                .await
                .map(|tx_hash| tx_hash.to_string()),
            InitTransferArgs::SolanaInitTransfer {
                token,
                amount,
                recipient,
                fee,
                native_fee,
                message,
            } => self
                .solana_init_transfer(token, amount, recipient, fee, native_fee, message)
                .await
                .map(|tx_hash| tx_hash.to_string()),
            InitTransferArgs::SolanaInitTransferSol {
                amount,
                recipient,
                fee,
                native_fee,
                message,
            } => self
                .solana_init_transfer_sol(amount, recipient, fee, native_fee, message)
                .await
                .map(|tx_hash| tx_hash.to_string()),
        }
    }

    pub async fn fin_transfer(&self, fin_transfer_args: FinTransferArgs) -> Result<String> {
        match fin_transfer_args {
            FinTransferArgs::NearFinTransferWithEvmProof {
                chain_kind,
                destination_chain,
                tx_hash: near_tx_hash,
                storage_deposit_actions,
                transaction_options,
            } => self
                .near_fin_transfer_with_evm_proof(
                    chain_kind,
                    destination_chain,
                    near_tx_hash,
                    storage_deposit_actions,
                    transaction_options,
                )
                .await
                .map(|tx_hash| tx_hash.to_string()),
            FinTransferArgs::NearFinTransferWithVaa {
                chain_kind,
                destination_chain,
                storage_deposit_actions,
                vaa,
                transaction_options,
            } => self
                .near_fin_transfer_with_vaa(
                    chain_kind,
                    destination_chain,
                    storage_deposit_actions,
                    vaa,
                    transaction_options,
                )
                .await
                .map(|tx_hash| tx_hash.to_string()),
            FinTransferArgs::NearFinTransferBTC {
                chain_kind,
                btc_tx_hash,
                vout,
                btc_deposit_args,
                transaction_options,
            } => self
                .near_fin_transfer_btc(
                    chain_kind,
                    btc_tx_hash,
                    vout,
                    btc_deposit_args,
                    transaction_options,
                )
                .await
                .map(|tx_hash| tx_hash.to_string()),
            FinTransferArgs::EvmFinTransfer {
                chain_kind,
                event,
                tx_nonce,
            } => self
                .evm_fin_transfer(chain_kind, event, tx_nonce)
                .await
                .map(|tx_hash| tx_hash.encode_hex()),
            FinTransferArgs::EvmFinTransferWithTxHash {
                chain_kind,
                near_tx_hash,
                tx_nonce,
            } => self
                .evm_fin_transfer_with_tx_hash(chain_kind, near_tx_hash, tx_nonce)
                .await
                .map(|tx_hash| tx_hash.encode_hex()),
            FinTransferArgs::SolanaFinTransfer {
                event,
                solana_token,
            } => self
                .solana_finalize_transfer_with_event(event, solana_token)
                .await
                .map(|tx_hash| tx_hash.to_string()),
            FinTransferArgs::SolanaFinTransferWithTxHash {
                near_tx_hash,
                sender_id,
                solana_token,
            } => self
                .solana_finalize_transfer_with_tx_hash(near_tx_hash, sender_id, solana_token)
                .await
                .map(|tx_hash| tx_hash.to_string()),
            FinTransferArgs::UTXOChainFinTransfer {
                chain,
                near_tx_hash,
                relayer,
            } => self.btc_fin_transfer(chain, near_tx_hash, relayer).await,
        }
    }

    pub async fn is_transfer_finalised(
        &self,
        origin_chain: Option<ChainKind>,
        destination_chain: ChainKind,
        nonce: u64,
    ) -> Result<bool> {
        match destination_chain {
            ChainKind::Near => {
                let Some(origin_chain) = origin_chain else {
                    return Err(BridgeSdkError::ConfigError(
                        "Origin chain is required to check if transfer was finalised on NEAR"
                            .to_string(),
                    ));
                };

                self.near_is_transfer_finalised(omni_types::TransferId {
                    origin_chain,
                    origin_nonce: nonce,
                })
                .await
            }
            ChainKind::Eth | ChainKind::Base | ChainKind::Arb | ChainKind::Bnb => {
                self.evm_is_transfer_finalised(destination_chain, nonce)
                    .await
            }
            ChainKind::Sol => self.solana_is_transfer_finalised(nonce).await,
            ChainKind::Zcash | ChainKind::Btc => Err(BridgeSdkError::ConfigError(
                "is_transfer_finalised is not supported for UTXO chains".to_string(),
            )),
        }
    }

    pub async fn wormhole_get_vaa<E>(
        &self,
        chain_id: u64,
        emitter: E,
        sequence: u64,
    ) -> Result<String>
    where
        E: std::fmt::Display + Send,
    {
        let wormhole_bridge_client = self.wormhole_bridge_client()?;
        wormhole_bridge_client
            .get_vaa(chain_id, emitter, sequence)
            .await
    }

    pub async fn wormhole_get_vaa_by_tx_hash(&self, tx_hash: String) -> Result<String> {
        let wormhole_bridge_client = self.wormhole_bridge_client()?;
        wormhole_bridge_client.get_vaa_by_tx_hash(tx_hash).await
    }

    pub fn denormalize_amount(&self, decimals: &Decimals, amount: u128) -> Result<u128> {
        amount
            .checked_mul(10_u128.pow((decimals.origin_decimals - decimals.decimals).into()))
            .ok_or_else(|| BridgeSdkError::UnknownError("Denormalization overflow".to_string()))
    }

    pub fn network(&self) -> Result<Network> {
        self.network.ok_or(BridgeSdkError::ConfigError(
            "Network is not configured".to_string(),
        ))
    }

    pub fn near_bridge_client(&self) -> Result<&NearBridgeClient> {
        self.near_bridge_client
            .as_ref()
            .ok_or(BridgeSdkError::ConfigError(
                "NEAR bridge client is not configured".to_string(),
            ))
            .map_err(|e| {
                BridgeSdkError::InvalidArgument(format!("Failed to denormalize amount: {e}",))
            })
    }

    pub fn evm_bridge_client(&self, chain_kind: ChainKind) -> Result<&EvmBridgeClient> {
        let bridge_client = match chain_kind {
            ChainKind::Eth => self.eth_bridge_client.as_ref(),
            ChainKind::Base => self.base_bridge_client.as_ref(),
            ChainKind::Arb => self.arb_bridge_client.as_ref(),
            ChainKind::Bnb => self.bnb_bridge_client.as_ref(),
            ChainKind::Near | ChainKind::Sol | ChainKind::Btc | ChainKind::Zcash => {
                unreachable!("Unsupported chain kind")
            }
        };

        bridge_client.ok_or(BridgeSdkError::ConfigError(
            "EVM bridge client is not configured".to_string(),
        ))
    }

    pub fn light_client(&self, chain: ChainKind) -> Result<&LightClient> {
        let light_client = match chain {
            ChainKind::Eth => self.eth_light_client.as_ref(),
            ChainKind::Btc => self.btc_light_client.as_ref(),
            ChainKind::Zcash => self.zcash_light_client.as_ref(),
            _ => {
                return Err(BridgeSdkError::ConfigError(format!(
                    "Light client is not supported for {chain:?} chain"
                )))
            }
        };

        light_client.ok_or(BridgeSdkError::ConfigError(
            "Light client is not configured".to_string(),
        ))
    }

    pub fn solana_bridge_client(&self) -> Result<&SolanaBridgeClient> {
        self.solana_bridge_client
            .as_ref()
            .ok_or(BridgeSdkError::ConfigError(
                "SOLANA bridge client is not configured".to_string(),
            ))
    }

    pub fn wormhole_bridge_client(&self) -> Result<&WormholeBridgeClient> {
        self.wormhole_bridge_client
            .as_ref()
            .ok_or(BridgeSdkError::ConfigError(
                "Wormhole bridge client is not configured".to_string(),
            ))
    }

    pub fn btc_bridge_client(&self) -> Result<&UTXOBridgeClient<Bitcoin>> {
        self.btc_bridge_client
            .as_ref()
            .ok_or(BridgeSdkError::ConfigError(
                "BTC bridge client is not configured".to_string(),
            ))
    }

    pub fn zcash_bridge_client(&self) -> Result<&UTXOBridgeClient<Zcash>> {
        self.zcash_bridge_client
            .as_ref()
            .ok_or(BridgeSdkError::ConfigError(
                "ZCash bridge client is not configured".to_string(),
            ))
    }

    pub fn utxo_bridge_client(&self, chain: ChainKind) -> Result<AnyUtxoClient<'_>> {
        match chain {
            ChainKind::Btc => Ok(AnyUtxoClient::Btc(self.btc_bridge_client()?)),
            ChainKind::Zcash => Ok(AnyUtxoClient::Zcash(self.zcash_bridge_client()?)),
            ChainKind::Near
            | ChainKind::Eth
            | ChainKind::Base
            | ChainKind::Arb
            | ChainKind::Bnb
            | ChainKind::Sol => Err(BridgeSdkError::ConfigError(
                "UTXO bridge client is not configured".to_string(),
            )),
        }
    }

    pub async fn get_proof_for_event(
        &self,
        tx_hash: TxHash,
        proof_kind: ProofKind,
        chain_kind: ChainKind,
    ) -> Result<EvmProof> {
        let evm_bridge_client = self.evm_bridge_client(chain_kind)?;
        let light_client = self.light_client(chain_kind)?;
        let last_eth_block_number_on_near = light_client.get_last_block_number().await?;
        let tx_block_number = evm_bridge_client.get_tx_block_number(tx_hash).await?;

        if last_eth_block_number_on_near < tx_block_number {
            return Err(BridgeSdkError::LightClientNotSynced(
                last_eth_block_number_on_near,
            ));
        }

        evm_bridge_client
            .get_proof_for_event(tx_hash, proof_kind)
            .await
    }

    pub async fn get_storage_deposit_actions_for_tx(
        &self,
        chain: ChainKind,
        tx_hash: String,
    ) -> Result<Vec<StorageDepositAction>> {
        match chain {
            ChainKind::Eth | ChainKind::Base | ChainKind::Arb | ChainKind::Bnb => {
                let tx_hash = TxHash::from_str(&tx_hash).map_err(|_| {
                    BridgeSdkError::InvalidArgument(format!("Failed to parse tx hash: {tx_hash}"))
                })?;
                self.get_storage_deposit_actions_for_evm_tx(chain, tx_hash)
                    .await
            }
            ChainKind::Sol => {
                let signature = Signature::from_str(&tx_hash).map_err(|_| {
                    BridgeSdkError::InvalidArgument(format!("Failed to parse signature: {tx_hash}"))
                })?;
                self.get_storage_deposit_actions_for_solana_tx(&signature)
                    .await
            }
            ChainKind::Near | ChainKind::Btc | ChainKind::Zcash => {
                Err(BridgeSdkError::ConfigError(
                    "Storage deposit actions are not supported for this chain".to_string(),
                ))
            }
        }
    }

    pub async fn get_storage_deposit_actions_for_evm_tx(
        &self,
        chain: ChainKind,
        tx_hash: TxHash,
    ) -> Result<Vec<StorageDepositAction>> {
        // TODO: add fast transfer support
        let transfer_event = self.evm_get_transfer_event(chain, tx_hash).await?;

        let token_address =
            OmniAddress::new_from_evm_address(chain, H160(transfer_event.token_address.0))
                .map_err(|_| {
                    BridgeSdkError::InvalidArgument(format!(
                        "Failed to parse token address: {}",
                        transfer_event.token_address
                    ))
                })?;

        let recipient = OmniAddress::from_str(&transfer_event.recipient).map_err(|_| {
            BridgeSdkError::InvalidArgument(format!(
                "Failed to parse recipient: {}",
                transfer_event.recipient
            ))
        })?;

        let fee_recipient = self
            .near_bridge_client()
            .and_then(NearBridgeClient::account_id)
            .map_err(|_| {
                BridgeSdkError::ConfigError("NEAR bridge client is not configured".to_string())
            })?;

        self.get_storage_deposit_actions(
            chain,
            &recipient,
            &fee_recipient,
            &token_address,
            transfer_event.fee,
            transfer_event.native_token_fee,
        )
        .await
    }

    pub async fn get_storage_deposit_actions_for_solana_tx(
        &self,
        signature: &Signature,
    ) -> Result<Vec<StorageDepositAction>> {
        let transfer_event = self.solana_get_transfer_event(signature).await?;

        let token = Pubkey::from_str(&transfer_event.token).map_err(|_| {
            BridgeSdkError::InvalidArgument(format!(
                "Failed to parse token address as Pubkey: {:?}",
                transfer_event.token
            ))
        })?;

        let token_address = OmniAddress::new_from_slice(ChainKind::Sol, &token.to_bytes())
            .map_err(|_| {
                BridgeSdkError::InvalidArgument(format!("Failed to parse token address: {token}"))
            })?;

        let recipient = OmniAddress::from_str(&transfer_event.recipient).map_err(|_| {
            BridgeSdkError::InvalidArgument(format!(
                "Failed to parse recipient: {}",
                transfer_event.recipient
            ))
        })?;

        let fee_recipient = self
            .near_bridge_client()
            .and_then(NearBridgeClient::account_id)
            .map_err(|_| {
                BridgeSdkError::ConfigError("NEAR bridge client is not configured".to_string())
            })?;

        self.get_storage_deposit_actions(
            ChainKind::Sol,
            &recipient,
            &fee_recipient,
            &token_address,
            transfer_event.fee,
            u128::from(transfer_event.native_fee),
        )
        .await
    }

    pub async fn get_storage_deposit_actions(
        &self,
        chain: ChainKind,
        recipient: &OmniAddress,
        fee_recipient: &AccountId,
        token_address: &OmniAddress,
        fee: u128,
        native_fee: u128,
    ) -> Result<Vec<StorageDepositAction>> {
        let mut storage_deposit_actions = Vec::new();
        if let OmniAddress::Near(near_recipient) = recipient {
            self.add_storage_deposit_action(
                &mut storage_deposit_actions,
                self.near_get_token_id(token_address.clone()).await?,
                near_recipient.clone(),
            )
            .await?;
        }

        if fee > 0 {
            self.add_storage_deposit_action(
                &mut storage_deposit_actions,
                self.near_get_token_id(token_address.clone()).await?,
                fee_recipient.clone(),
            )
            .await?;
        }

        if native_fee > 0 {
            let token_id = self.near_get_native_token_id(chain).await?;

            self.add_storage_deposit_action(
                &mut storage_deposit_actions,
                token_id,
                fee_recipient.clone(),
            )
            .await?;
        }

        Ok(storage_deposit_actions)
    }

    async fn add_storage_deposit_action(
        &self,
        storage_deposit_actions: &mut Vec<StorageDepositAction>,
        token_id: AccountId,
        account_id: AccountId,
    ) -> Result<()> {
        let storage_deposit_amount = match self
            .near_get_required_storage_deposit(token_id.clone(), account_id.clone())
            .await?
        {
            amount if amount > 0 => Some(amount),
            _ => None,
        };

        storage_deposit_actions.push(StorageDepositAction {
            token_id,
            account_id,
            storage_deposit_amount,
        });

        Ok(())
    }

    async fn extract_utxo(
        &self,
        chain: ChainKind,
        target_btc_address: String,
        amount: u128,
        fee_rate: Option<u64>,
    ) -> Result<(Vec<OutPoint>, Vec<TxOut>, u64)> {
        let near_bridge_client = self.near_bridge_client()?;

        let utxo_bridge_client = self.utxo_bridge_client(chain)?;
        let fee_rate = match fee_rate {
            Some(rate) => rate,
            None => utxo_bridge_client.get_fee_rate().await?,
        };

        let utxos = near_bridge_client.get_utxos(chain).await?;
        let (selected_utxo, utxos_balance) =
            utxo_utils::choose_utxos(amount, utxos).map_err(BridgeSdkError::UtxoManagementError)?;
        let out_points = utxo_utils::utxo_to_out_points(selected_utxo.clone()).map_err(|e| {
            BridgeSdkError::UtxoClientError(format!("Error on get input points: {e}"))
        })?;

        let gas_fee = get_gas_fee(
            chain,
            selected_utxo.len().try_into().unwrap(),
            2,
            fee_rate,
            false,
        )
        .into();
        let change_address = near_bridge_client.get_change_address(chain).await?;
        let tx_outs = utxo_utils::get_tx_outs(
            &target_btc_address,
            amount
                .checked_sub(gas_fee)
                .ok_or_else(|| {
                    BridgeSdkError::InvalidArgument("Amount is smaller than `gas_fee`".to_string())
                })?
                .try_into()
                .map_err(|err| {
                    BridgeSdkError::UnknownError(format!("Amount is unexpectedly large: {err}"))
                })?,
            &change_address,
            utxos_balance
                .checked_sub(amount)
                .ok_or_else(|| BridgeSdkError::InsufficientUTXOBalance)?
                .try_into()
                .map_err(|err| {
                    BridgeSdkError::InvalidArgument(format!(
                        "Error on change amount conversion: {err}"
                    ))
                })?,
            chain,
            self.network()?,
        )
        .map_err(BridgeSdkError::UtxoManagementError)?;

        Ok((
            out_points,
            tx_outs,
            gas_fee.try_into().map_err(|err| {
                BridgeSdkError::UnknownError(format!("gas_fee unexpectedly high: {err}"))
            })?,
        ))
    }
}
