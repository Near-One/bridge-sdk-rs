use std::str::FromStr;

use bridge_connector_common::result::{BridgeSdkError, Result};
use derive_builder::Builder;
use ethers::prelude::*;

use near_primitives::hash::CryptoHash;
use near_primitives::types::AccountId;

use omni_types::locker_args::{ClaimFeeArgs, StorageDepositAction};
use omni_types::prover_args::{EvmVerifyProofArgs, WormholeVerifyProofArgs};
use omni_types::prover_result::ProofKind;
use omni_types::{near_events::OmniBridgeEvent, ChainKind};
use omni_types::{EvmAddress, Fee, OmniAddress, TransferMessage, H160};

use btc_bridge_client::{BtcBridgeClient, BtcOutpoint};
use evm_bridge_client::EvmBridgeClient;
use near_bridge_client::btc_connector::FinBtcTransferArgs;
use near_bridge_client::{NearBridgeClient, TransactionOptions};
use solana_bridge_client::{
    DeployTokenData, DepositPayload, FinalizeDepositData, MetadataPayload, SolanaBridgeClient,
    TransferId,
};
use solana_sdk::pubkey::Pubkey;
use solana_sdk::signature::{Keypair, Signature};
use wormhole_bridge_client::WormholeBridgeClient;

#[derive(Builder, Default)]
#[builder(pattern = "owned")]
pub struct OmniConnector {
    near_bridge_client: Option<NearBridgeClient>,
    eth_bridge_client: Option<EvmBridgeClient>,
    base_bridge_client: Option<EvmBridgeClient>,
    arb_bridge_client: Option<EvmBridgeClient>,
    solana_bridge_client: Option<SolanaBridgeClient>,
    wormhole_bridge_client: Option<WormholeBridgeClient>,
    btc_bridge_client: Option<BtcBridgeClient>,
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
        tx_hash: TxHash,
        storage_deposit_actions: Vec<StorageDepositAction>,
        transaction_options: TransactionOptions,
    },
    NearFinTransferWithVaa {
        chain_kind: ChainKind,
        storage_deposit_actions: Vec<StorageDepositAction>,
        vaa: String,
        transaction_options: TransactionOptions,
    },
    NearFinTransferBTC {
        btc_tx_hash: String,
        tx_block_height: usize,
        vout: usize,
        recipient_id: String,
        amount: u128,
        fee: u128,
        transaction_options: TransactionOptions,
        wait_final_outcome_timeout_sec: Option<u64>,
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
        token_id: String,
        amount: u128,
        transaction_options: TransactionOptions,
    ) -> Result<CryptoHash> {
        let near_bridge_client = self.near_bridge_client()?;
        near_bridge_client
            .storage_deposit_for_token(token_id, amount, transaction_options)
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
        tx_hash: TxHash,
        storage_deposit_actions: Vec<StorageDepositAction>,
        transaction_options: TransactionOptions,
    ) -> Result<CryptoHash> {
        let near_bridge_client = self.near_bridge_client()?;
        let evm_bridge_client = self.evm_bridge_client(chain_kind)?;

        let proof = evm_bridge_client
            .get_proof_for_event(tx_hash, ProofKind::InitTransfer)
            .await?;

        let verify_proof_args = EvmVerifyProofArgs {
            proof_kind: ProofKind::InitTransfer,
            proof,
        };

        near_bridge_client
            .fin_transfer(
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

    pub async fn near_fin_transfer_btc(
        &self,
        btc_outpoint: BtcOutpoint,
        recipient_id: String,
        amount: u128,
        fee: u128,
        transaction_options: TransactionOptions,
        wait_final_outcome_timeout_sec: Option<u64>,
    ) -> Result<CryptoHash> {
        let btc_bridge = self.btc_bridge_client()?;
        let near_bridge_client = self.near_bridge_client()?;
        let proof_data = btc_bridge.extract_btc_proof(&btc_outpoint)?;
        let deposit_msg =
            near_bridge_client.get_deposit_msg_by_recipient_id(&recipient_id, amount, fee)?;
        let args = FinBtcTransferArgs {
            deposit_msg,
            tx_bytes: proof_data.tx_bytes,
            vout: btc_outpoint.vout,
            tx_block_blockhash: proof_data.tx_block_blockhash,
            tx_index: proof_data.tx_index,
            merkle_proof: proof_data.merkle_proof,
        };

        near_bridge_client
            .fin_btc_transfer(args, transaction_options, wait_final_outcome_timeout_sec)
            .await
    }

    pub async fn get_btc_address(
        &self,
        recipient_id: &str,
        amount: u128,
        fee: u128,
    ) -> Result<String> {
        let near_bridge_client = self.near_bridge_client()?;
        near_bridge_client
            .get_btc_address(recipient_id, amount, fee)
            .await
    }

    pub async fn near_fin_transfer_with_vaa(
        &self,
        chain_kind: ChainKind,
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
        let evm_bridge_client = self.evm_bridge_client(chain_kind)?;

        let proof = evm_bridge_client
            .get_proof_for_event(tx_hash, ProofKind::DeployToken)
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
        let evm_bridge_client = self.evm_bridge_client(chain_kind)?;

        let proof = evm_bridge_client
            .get_proof_for_event(tx_hash, ProofKind::LogMetadata)
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
        let evm_bridge_client = self.evm_bridge_client(chain_kind)?;

        let tx_hash = TxHash::from_str(&tx_hash).map_err(|e| {
            BridgeSdkError::InvalidArgument(format!("Failed to parse tx hash: {e}"))
        })?;

        let transfer_event = evm_bridge_client.get_transfer_event(tx_hash).await?;

        let recipient = OmniAddress::from_str(&transfer_event.recipient).map_err(|_| {
            BridgeSdkError::InvalidArgument(format!(
                "Failed to parse recipient: {}",
                transfer_event.recipient
            ))
        })?;
        let token_id = near_bridge_client
            .get_token_id(
                OmniAddress::new_from_evm_address(chain_kind, H160(transfer_event.token_address.0))
                    .map_err(|_| {
                        BridgeSdkError::InvalidArgument(format!(
                            "Failed to parse token address: {}",
                            transfer_event.token_address
                        ))
                    })?,
            )
            .await?;

        near_bridge_client
            .fast_fin_transfer(
                near_bridge_client::FastFinTransferArgs {
                    token_id,
                    amount: transfer_event.amount,
                    recipient,
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
            OmniAddress::Eth(address) | OmniAddress::Arb(address) | OmniAddress::Base(address) => {
                self.evm_log_metadata(
                    address.clone(),
                    token.get_chain(),
                    transaction_options.nonce.map(std::convert::Into::into),
                )
                .await
                .map(|hash| hash.to_string())
            }
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
                tx_hash: near_tx_hash,
                storage_deposit_actions,
                transaction_options,
            } => self
                .near_fin_transfer_with_evm_proof(
                    chain_kind,
                    near_tx_hash,
                    storage_deposit_actions,
                    transaction_options,
                )
                .await
                .map(|tx_hash| tx_hash.to_string()),
            FinTransferArgs::NearFinTransferWithVaa {
                chain_kind,
                storage_deposit_actions,
                vaa,
                transaction_options,
            } => self
                .near_fin_transfer_with_vaa(
                    chain_kind,
                    storage_deposit_actions,
                    vaa,
                    transaction_options,
                )
                .await
                .map(|tx_hash| tx_hash.to_string()),
            FinTransferArgs::NearFinTransferBTC {
                btc_tx_hash,
                tx_block_height,
                vout,
                recipient_id,
                amount,
                fee,
                transaction_options,
                wait_final_outcome_timeout_sec,
            } => self
                .near_fin_transfer_btc(
                    BtcOutpoint {
                        tx_hash: btc_tx_hash,
                        block_height: tx_block_height,
                        vout,
                    },
                    recipient_id,
                    amount,
                    fee,
                    transaction_options,
                    wait_final_outcome_timeout_sec,
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
                .map(|tx_hash| tx_hash.to_string()),
            FinTransferArgs::EvmFinTransferWithTxHash {
                chain_kind,
                near_tx_hash,
                tx_nonce,
            } => self
                .evm_fin_transfer_with_tx_hash(chain_kind, near_tx_hash, tx_nonce)
                .await
                .map(|tx_hash| tx_hash.to_string()),
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

    pub fn near_bridge_client(&self) -> Result<&NearBridgeClient> {
        self.near_bridge_client
            .as_ref()
            .ok_or(BridgeSdkError::ConfigError(
                "NEAR bridge client not configured".to_string(),
            ))
    }

    pub fn evm_bridge_client(&self, chain_kind: ChainKind) -> Result<&EvmBridgeClient> {
        let bridge_client = match chain_kind {
            ChainKind::Base => self.base_bridge_client.as_ref(),
            ChainKind::Arb => self.arb_bridge_client.as_ref(),
            ChainKind::Eth => self.eth_bridge_client.as_ref(),
            _ => unreachable!("Unsupported chain kind"),
        };

        bridge_client.ok_or(BridgeSdkError::ConfigError(
            "EVM bridge client not configured".to_string(),
        ))
    }

    pub fn solana_bridge_client(&self) -> Result<&SolanaBridgeClient> {
        self.solana_bridge_client
            .as_ref()
            .ok_or(BridgeSdkError::ConfigError(
                "SOLANA bridge client not configured".to_string(),
            ))
    }

    pub fn wormhole_bridge_client(&self) -> Result<&WormholeBridgeClient> {
        self.wormhole_bridge_client
            .as_ref()
            .ok_or(BridgeSdkError::ConfigError(
                "Wormhole bridge client not configured".to_string(),
            ))
    }

    pub fn btc_bridge_client(&self) -> Result<&BtcBridgeClient> {
        self.btc_bridge_client
            .as_ref()
            .ok_or(BridgeSdkError::ConfigError(
                "BTC bridge client not configured".to_string(),
            ))
    }
}
