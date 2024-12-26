use bridge_connector_common::result::{BridgeSdkError, Result};
use derive_builder::Builder;
use ethers::prelude::*;

use near_primitives::hash::CryptoHash;
use near_primitives::types::AccountId;

use omni_types::locker_args::{ClaimFeeArgs, StorageDepositAction};
use omni_types::prover_args::EvmVerifyProofArgs;
use omni_types::prover_result::ProofKind;
use omni_types::{near_events::Nep141LockerEvent, ChainKind};
use omni_types::{Fee, OmniAddress};

use evm_bridge_client::EvmBridgeClient;
use near_bridge_client::NearBridgeClient;
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
}

pub enum LogMetadataArgs {
    NearLogMetadata { token: String },
    SolanaLogMetadata { token: Pubkey },
}

pub enum DeployTokenArgs {
    NearDeployToken {
        chain_kind: ChainKind,
        vaa: String,
    },
    EvmDeployToken {
        chain_kind: ChainKind,
        event: Nep141LockerEvent,
    },
    EvmDeployTokenWithTxHash {
        chain_kind: ChainKind,
        near_tx_hash: CryptoHash,
    },
    SolanaDeployToken {
        event: Nep141LockerEvent,
    },
    SolanaDeployTokenWithTxHash {
        near_tx_hash: CryptoHash,
        sender_id: Option<AccountId>,
    },
}

pub enum BindTokenArgs {
    EvmBindToken {
        chain_kind: ChainKind,
        tx_hash: TxHash,
    },
    WormholeBindToken {
        bind_token_args: omni_types::locker_args::BindTokenArgs,
    },
}

pub enum InitTransferArgs {
    NearInitTransfer {
        token: String,
        amount: u128,
        receiver: String,
    },
    EvmInitTransfer {
        chain_kind: ChainKind,
        token: String,
        amount: u128,
        receiver: String,
        fee: Fee,
    },
    SolanaInitTransfer {
        token: Pubkey,
        amount: u128,
        recipient: String,
    },
    SolanaInitTransferSol {
        amount: u128,
        recipient: String,
    },
}

pub enum FinTransferArgs {
    NearFinTransfer {
        chain_kind: ChainKind,
        storage_deposit_actions: Vec<StorageDepositAction>,
        prover_args: Vec<u8>,
    },
    EvmFinTransfer {
        chain_kind: ChainKind,
        event: Nep141LockerEvent,
    },
    EvmFinTransferWithTxHash {
        chain_kind: ChainKind,
        near_tx_hash: CryptoHash,
    },
    SolanaFinTransfer {
        event: Nep141LockerEvent,
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

    pub async fn near_get_token_id(&self, token_address: OmniAddress) -> Result<AccountId> {
        let near_bridge_client = self.near_bridge_client()?;
        near_bridge_client.get_token_id(token_address).await
    }

    pub async fn near_get_native_token_id(&self, origin_chain: ChainKind) -> Result<AccountId> {
        let near_bridge_client = self.near_bridge_client()?;
        near_bridge_client.get_native_token_id(origin_chain).await
    }

    pub async fn near_log_metadata(&self, token_id: String) -> Result<CryptoHash> {
        let near_bridge_client = self.near_bridge_client()?;
        near_bridge_client.log_token_metadata(token_id).await
    }

    pub async fn near_deploy_token_with_vaa_proof(
        &self,
        chain_kind: ChainKind,
        vaa: String,
    ) -> Result<CryptoHash> {
        let near_bridge_client = self.near_bridge_client()?;
        near_bridge_client
            .deploy_token_with_vaa_proof(chain_kind, &vaa)
            .await
    }

    pub async fn near_bind_token(
        &self,
        bind_token_args: omni_types::locker_args::BindTokenArgs,
    ) -> Result<CryptoHash> {
        let near_bridge_client = self.near_bridge_client()?;
        near_bridge_client.bind_token(bind_token_args).await
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
    ) -> Result<CryptoHash> {
        let near_bridge_client = self.near_bridge_client()?;
        near_bridge_client
            .storage_deposit_for_token(token_id, amount)
            .await
    }

    pub async fn near_sign_transfer(
        &self,
        transfer_id: omni_types::TransferId,
        fee_recipient: Option<AccountId>,
        fee: Option<Fee>,
    ) -> Result<CryptoHash> {
        let near_bridge_client = self.near_bridge_client()?;
        near_bridge_client
            .sign_transfer(transfer_id, fee_recipient, fee)
            .await
    }

    pub async fn near_init_transfer(
        &self,
        token_id: String,
        amount: u128,
        receiver: String,
    ) -> Result<CryptoHash> {
        let near_bridge_client = self.near_bridge_client()?;
        near_bridge_client
            .init_transfer(token_id, amount, receiver)
            .await
    }

    pub async fn near_fin_transfer(
        &self,
        chain_kind: ChainKind,
        storage_deposit_actions: Vec<StorageDepositAction>,
        prover_args: Vec<u8>,
    ) -> Result<CryptoHash> {
        let near_bridge_client = self.near_bridge_client()?;
        near_bridge_client
            .fin_transfer(omni_types::locker_args::FinTransferArgs {
                chain_kind,
                storage_deposit_actions,
                prover_args,
            })
            .await
    }

    pub async fn near_claim_fee(&self, claim_fee_args: ClaimFeeArgs) -> Result<CryptoHash> {
        let near_bridge_client = self.near_bridge_client()?;
        near_bridge_client.claim_fee(claim_fee_args).await
    }

    pub async fn near_bind_token_with_evm_proof(
        &self,
        chain_kind: ChainKind,
        tx_hash: TxHash,
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
            .bind_token(omni_types::locker_args::BindTokenArgs {
                chain_kind,
                prover_args: borsh::to_vec(&verify_proof_args).map_err(|_| {
                    BridgeSdkError::EthProofError("Failed to serialize proof".to_string())
                })?,
            })
            .await
    }

    pub async fn evm_deploy_token(
        &self,
        chain_kind: ChainKind,
        event: Nep141LockerEvent,
    ) -> Result<TxHash> {
        let evm_bridge_client = self.evm_bridge_client(chain_kind)?;
        evm_bridge_client.deploy_token(event).await
    }

    pub async fn evm_deploy_token_with_tx_hash(
        &self,
        chain_kind: ChainKind,
        near_tx_hash: CryptoHash,
    ) -> Result<TxHash> {
        let near_bridge_client = self.near_bridge_client()?;
        let evm_bridge_client = self.evm_bridge_client(chain_kind)?;

        let transfer_log = near_bridge_client
            .extract_transfer_log(near_tx_hash, None, "LogMetadataEvent")
            .await?;

        evm_bridge_client
            .deploy_token(
                serde_json::from_str(&transfer_log).map_err(|_| BridgeSdkError::UnknownError)?,
            )
            .await
    }

    pub async fn evm_init_transfer(
        &self,
        chain_kind: ChainKind,
        near_token_id: String,
        amount: u128,
        receiver: String,
        fee: Fee,
    ) -> Result<TxHash> {
        let evm_bridge_client = self.evm_bridge_client(chain_kind)?;
        evm_bridge_client
            .init_transfer(near_token_id, amount, receiver, fee)
            .await
    }

    pub async fn evm_fin_transfer(
        &self,
        chain_kind: ChainKind,
        event: Nep141LockerEvent,
    ) -> Result<TxHash> {
        let evm_bridge_client = self.evm_bridge_client(chain_kind)?;
        evm_bridge_client.fin_transfer(event).await
    }

    pub async fn evm_fin_transfer_with_tx_hash(
        &self,
        chain_kind: ChainKind,
        near_tx_hash: CryptoHash,
    ) -> Result<TxHash> {
        let evm_bridge_client = self.evm_bridge_client(chain_kind)?;
        let near_bridge_client = self.near_bridge_client()?;

        let transfer_log = near_bridge_client
            .extract_transfer_log(near_tx_hash, None, "SignTransferEvent")
            .await?;

        evm_bridge_client
            .fin_transfer(
                serde_json::from_str(&transfer_log).map_err(|_| BridgeSdkError::UnknownError)?,
            )
            .await
    }

    pub async fn solana_initialize(&self, program_keypair: Keypair) -> Result<Signature> {
        // Derived based on near bridge account id and derivation path (bridge-1)
        const DERIVED_NEAR_BRIDGE_ADDRESS: [u8; 64] = [
            19, 55, 243, 130, 164, 28, 152, 3, 170, 254, 187, 182, 135, 17, 208, 98, 216, 182, 238,
            146, 2, 127, 83, 201, 149, 246, 138, 221, 29, 111, 186, 167, 150, 196, 102, 219, 89,
            69, 115, 114, 185, 116, 6, 233, 154, 114, 222, 142, 167, 206, 157, 39, 177, 221, 224,
            86, 146, 61, 226, 206, 55, 2, 119, 12,
        ];

        let solana_bridge_client = self.solana_bridge_client()?;

        let tx_hash = solana_bridge_client
            .initialize(DERIVED_NEAR_BRIDGE_ADDRESS, program_keypair)
            .await
            .map_err(|_| BridgeSdkError::UnknownError)?;

        tracing::info!(
            tx_hash = format!("{:?}", tx_hash),
            "Sent initialize transaction"
        );

        Ok(tx_hash)
    }

    pub async fn solana_log_metadata(&self, token: Pubkey) -> Result<Signature> {
        let solana_bridge_client = self.solana_bridge_client()?;

        let tx_hash = solana_bridge_client
            .log_metadata(token)
            .await
            .map_err(|_| BridgeSdkError::UnknownError)?;

        tracing::info!(
            tx_hash = format!("{:?}", tx_hash),
            "Sent register token transaction"
        );

        Ok(tx_hash)
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

        self.solana_deploy_token_with_event(
            serde_json::from_str(&transfer_log).map_err(|_| BridgeSdkError::UnknownError)?,
        )
        .await
        // TODO: This will silence a real error, so it must be fixed during `BridgeSdkError` refactoring
        .map_err(|_| BridgeSdkError::UnknownError)
    }

    pub async fn solana_deploy_token_with_event(
        &self,
        event: Nep141LockerEvent,
    ) -> Result<Signature> {
        let Nep141LockerEvent::LogMetadataEvent {
            signature,
            metadata_payload,
        } = event
        else {
            return Err(BridgeSdkError::UnknownError);
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

        solana_bridge_client
            .deploy_token(payload)
            .await
            .map_err(|_| BridgeSdkError::UnknownError)
    }

    pub async fn solana_init_transfer(
        &self,
        token: Pubkey,
        amount: u128,
        recipient: String,
    ) -> Result<Signature> {
        let solana_bridge_client = self.solana_bridge_client()?;

        let tx_hash = solana_bridge_client
            .init_transfer(token, amount, recipient)
            .await
            .map_err(|_| BridgeSdkError::UnknownError)?;

        tracing::info!(
            tx_hash = format!("{:?}", tx_hash),
            "Sent init transfer native transaction"
        );

        Ok(tx_hash)
    }

    pub async fn solana_init_transfer_sol(
        &self,
        amount: u128,
        recipient: String,
    ) -> Result<Signature> {
        let solana_bridge_client = self.solana_bridge_client()?;

        let tx_hash = solana_bridge_client
            .init_transfer_sol(amount, recipient)
            .await
            .map_err(|_| BridgeSdkError::UnknownError)?;

        tracing::info!(
            tx_hash = format!("{:?}", tx_hash),
            "Sent init transfer SOL transaction"
        );

        Ok(tx_hash)
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
            .await
            .map_err(|_| BridgeSdkError::UnknownError)?;

        self.solana_finalize_transfer_with_event(
            serde_json::from_str(&transfer_log).map_err(|_| BridgeSdkError::UnknownError)?,
            solana_token,
        )
        .await
        // TODO: This will silence a real error, so it must be fixed during `BridgeSdkError` refactoring
        .map_err(|_| BridgeSdkError::UnknownError)
    }

    pub async fn solana_finalize_transfer_with_event(
        &self,
        event: Nep141LockerEvent,
        solana_token: Pubkey, // TODO: retrieve from near contract
    ) -> Result<Signature> {
        let Nep141LockerEvent::SignTransferEvent {
            message_payload,
            signature,
        } = event
        else {
            return Err(BridgeSdkError::UnknownError);
        };

        let solana_bridge_client = self.solana_bridge_client()?;

        let mut signature = signature.to_bytes();
        signature[64] -= 27;

        let payload = FinalizeDepositData {
            payload: DepositPayload {
                destination_nonce: message_payload.destination_nonce,
                transfer_id: TransferId {
                    origin_chain: 1,
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

        if solana_token == Pubkey::default() {
            solana_bridge_client
                .finalize_transfer_sol(payload)
                .await
                .map_err(|_| BridgeSdkError::UnknownError)
        } else {
            solana_bridge_client
                .finalize_transfer(payload, solana_token)
                .await
                .map_err(|_| BridgeSdkError::UnknownError)
        }
    }

    pub async fn log_metadata(&self, log_metadata_args: LogMetadataArgs) -> Result<String> {
        match log_metadata_args {
            LogMetadataArgs::NearLogMetadata { token: token_id } => self
                .near_log_metadata(token_id)
                .await
                .map(|hash| hash.to_string()),
            LogMetadataArgs::SolanaLogMetadata { token } => self
                .solana_log_metadata(token)
                .await
                .map(|hash| hash.to_string()),
        }
    }

    pub async fn deploy_token(&self, deploy_token_args: DeployTokenArgs) -> Result<String> {
        match deploy_token_args {
            DeployTokenArgs::NearDeployToken { chain_kind, vaa } => self
                .near_deploy_token_with_vaa_proof(chain_kind, vaa)
                .await
                .map(|hash| hash.to_string()),
            DeployTokenArgs::EvmDeployToken { chain_kind, event } => self
                .evm_deploy_token(chain_kind, event)
                .await
                .map(|hash| hash.to_string()),
            DeployTokenArgs::EvmDeployTokenWithTxHash {
                chain_kind,
                near_tx_hash,
            } => self
                .evm_deploy_token_with_tx_hash(chain_kind, near_tx_hash)
                .await
                .map(|hash| hash.to_string()),
            DeployTokenArgs::SolanaDeployToken { event } => self
                .solana_deploy_token_with_event(event)
                .await
                .map(|hash| hash.to_string())
                .map_err(|_| BridgeSdkError::UnknownError),
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
            BindTokenArgs::EvmBindToken {
                chain_kind,
                tx_hash,
            } => self
                .near_bind_token_with_evm_proof(chain_kind, tx_hash)
                .await
                .map(|hash| hash.to_string()),
            BindTokenArgs::WormholeBindToken { bind_token_args } => self
                .near_bind_token(bind_token_args)
                .await
                .map(|hash| hash.to_string()),
        }
    }

    pub async fn init_transfer(&self, init_transfer_args: InitTransferArgs) -> Result<String> {
        match init_transfer_args {
            InitTransferArgs::NearInitTransfer {
                token: near_token_id,
                amount,
                receiver,
            } => self
                .near_init_transfer(near_token_id, amount, receiver)
                .await
                .map(|tx_hash| tx_hash.to_string()),
            InitTransferArgs::EvmInitTransfer {
                chain_kind,
                token: near_token_id,
                amount,
                receiver,
                fee,
            } => self
                .evm_init_transfer(chain_kind, near_token_id, amount, receiver, fee)
                .await
                .map(|tx_hash| tx_hash.to_string()),
            InitTransferArgs::SolanaInitTransfer {
                token,
                amount,
                recipient,
            } => self
                .solana_init_transfer(token, amount, recipient)
                .await
                .map(|tx_hash| tx_hash.to_string()),
            InitTransferArgs::SolanaInitTransferSol { amount, recipient } => self
                .solana_init_transfer_sol(amount, recipient)
                .await
                .map(|tx_hash| tx_hash.to_string()),
        }
    }

    pub async fn fin_transfer(&self, fin_transfer_args: FinTransferArgs) -> Result<String> {
        match fin_transfer_args {
            FinTransferArgs::NearFinTransfer {
                chain_kind,
                storage_deposit_actions,
                prover_args,
            } => self
                .near_fin_transfer(chain_kind, storage_deposit_actions, prover_args)
                .await
                .map(|tx_hash| tx_hash.to_string()),
            FinTransferArgs::EvmFinTransfer { chain_kind, event } => self
                .evm_fin_transfer(chain_kind, event)
                .await
                .map(|tx_hash| tx_hash.to_string()),
            FinTransferArgs::EvmFinTransferWithTxHash {
                chain_kind,
                near_tx_hash,
            } => self
                .evm_fin_transfer_with_tx_hash(chain_kind, near_tx_hash)
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
}
