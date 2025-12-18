use base64::Engine;
use bitvec::array::BitArray;
use borsh::{BorshDeserialize, BorshSerialize};
use derive_builder::Builder;
use instructions::UpdateMetadata;
use sha2::{Digest, Sha256};
use solana_client::{nonblocking::rpc_client::RpcClient, rpc_config::RpcTransactionConfig};
use solana_sdk::{
    bs58,
    commitment_config::CommitmentConfig,
    instruction::{AccountMeta, Instruction},
    program_option::COption,
    program_pack::Pack,
    pubkey::Pubkey,
    signature::{Keypair, Signature},
    signer::Signer,
    sysvar,
    transaction::Transaction,
};
use solana_system_interface::program;
use solana_transaction_status_client_types::{
    option_serializer::OptionSerializer, EncodedTransaction, UiMessage, UiTransactionEncoding,
};
use spl_token::state::Mint;

use crate::{
    error::SolanaBridgeClientError,
    instructions::{
        DeployToken, FinalizeTransfer, FinalizeTransferInstructionPayload, FinalizeTransferSol,
        InitTransfer, InitTransferSol, Initialize, LogMetadata, Pause, SetAdmin,
    },
};

pub mod error;
mod instructions;

const DISCRIMINATOR_LEN: usize = 8;
const INIT_TRANSFER_DISCRIMINATOR: [u8; DISCRIMINATOR_LEN] = [174, 50, 134, 99, 122, 243, 243, 224];
const INIT_TRANSFER_SOL_DISCRIMINATOR: [u8; DISCRIMINATOR_LEN] =
    [124, 167, 164, 191, 81, 140, 108, 30];
const GET_VERSION_DISCRIMINATOR: [u8; 8] = [168, 85, 244, 45, 81, 56, 130, 50];

const INIT_TRANSFER_SENDER_INDEX: usize = 5;
const INIT_TRANSFER_TOKEN_INDEX: usize = 1;
const INIT_TRANSFER_EMITTER_INDEX: usize = 6;
const INIT_TRANSFER_SOL_SENDER_INDEX: usize = 1;
const INIT_TRANSFER_SOL_EMITTER_INDEX: usize = 2;

const USED_NONCES_PER_ACCOUNT: u64 = 1024;

const OLD_WORMHOLE_VERSION: &str = "0.2.4";

#[allow(
    clippy::cast_possible_truncation,
    clippy::as_conversions,
    clippy::manual_div_ceil
)]
const BIT_BYTES: usize = (USED_NONCES_PER_ACCOUNT as usize + 7) / 8;

#[derive(BorshSerialize, BorshDeserialize, Debug)]
pub struct MetadataPayload {
    pub token: String,
    pub name: String,
    pub symbol: String,
    pub decimals: u8,
}

#[derive(BorshSerialize, BorshDeserialize, Debug)]
pub struct DeployTokenData {
    pub metadata: MetadataPayload,
    pub signature: [u8; 65],
}

#[derive(BorshSerialize, BorshDeserialize, Debug)]
pub struct TransferId {
    pub origin_chain: u8,
    pub origin_nonce: u64,
}

#[derive(BorshSerialize, BorshDeserialize, Debug)]
pub struct DepositPayload {
    pub destination_nonce: u64,
    pub transfer_id: TransferId,
    pub amount: u128,
    pub recipient: Pubkey,
    pub fee_recipient: Option<String>,
}

#[derive(BorshSerialize, BorshDeserialize, Debug)]
struct InitTransferPayload {
    pub amount: u128,
    pub recipient: String,
    pub fee: u128,
    pub native_fee: u64,
    pub message: String,
}

#[derive(BorshSerialize, BorshDeserialize, Debug)]
pub struct Transfer {
    pub amount: u128,
    pub token: String,
    pub sender: String,
    pub recipient: String,
    pub fee: u128,
    pub native_fee: u64,
    pub message: String,
    pub emitter: String,
    pub sequence: u64,
}

#[derive(BorshSerialize, BorshDeserialize, Debug)]
pub struct FinalizeDepositData {
    pub payload: DepositPayload,
    pub signature: [u8; 65],
}

#[derive(Clone, BorshDeserialize)]
pub struct WormholeSequence {
    pub sequence: u64,
}

#[derive(Builder)]
#[builder(pattern = "owned")]
pub struct SolanaBridgeClient {
    client: Option<RpcClient>,
    program_id: Option<Pubkey>,
    wormhole_core: Option<Pubkey>,
    wormhole_post_message_shim_program_id: Option<Pubkey>,
    wormhole_post_message_shim_event_authority: Option<Pubkey>,
    keypair: Option<Keypair>,
}

impl SolanaBridgeClient {
    pub async fn initialize(
        &self,
        derived_near_bridge_address: [u8; 64],
        program_keypair: Keypair,
    ) -> Result<Signature, SolanaBridgeClientError> {
        let program_id = self.program_id()?;
        let wormhole_core = self.wormhole_core()?;
        let keypair = self.keypair()?;

        let (config, _) = Pubkey::find_program_address(&[b"config"], program_id);
        let (authority, _) = Pubkey::find_program_address(&[b"authority"], program_id);
        let (sol_vault, _) = Pubkey::find_program_address(&[b"sol_vault"], program_id);

        let (wormhole_bridge, wormhole_fee_collector, wormhole_sequence) =
            self.get_wormhole_accounts()?;
        let wormhole_message = Keypair::new();

        let instruction_data = Initialize {
            admin: keypair.pubkey(),
            pausable_admin: keypair.pubkey(),
            metadata_admin: keypair.pubkey(),
            derived_near_bridge_address,
        };

        let instruction = Instruction::new_with_borsh(
            *program_id,
            &instruction_data,
            vec![
                AccountMeta::new(config, false),
                AccountMeta::new(authority, false),
                AccountMeta::new(sol_vault, false),
                AccountMeta::new(wormhole_bridge, false),
                AccountMeta::new(wormhole_fee_collector, false),
                AccountMeta::new(wormhole_sequence, false),
                AccountMeta::new(wormhole_message.pubkey(), true),
                AccountMeta::new(keypair.pubkey(), true),
                AccountMeta::new_readonly(sysvar::clock::ID, false),
                AccountMeta::new_readonly(sysvar::rent::ID, false),
                AccountMeta::new_readonly(program::ID, false),
                AccountMeta::new_readonly(*wormhole_core, false),
                AccountMeta::new_readonly(*program_id, true),
            ],
        );

        self.send_and_confirm_transaction(
            vec![instruction],
            &[keypair, &wormhole_message, &program_keypair],
        )
        .await
    }

    pub async fn get_version(&self) -> Result<String, SolanaBridgeClientError> {
        use solana_client::rpc_config::RpcSimulateTransactionConfig;

        let client = self.client()?;
        let program_id = self.program_id()?;
        let fee_payer = self.keypair()?.pubkey();

        let instruction = Instruction {
            program_id: *program_id,
            accounts: vec![],
            data: GET_VERSION_DISCRIMINATOR.to_vec(),
        };

        let recent_blockhash = client.get_latest_blockhash().await?;
        let tx = Transaction::new_unsigned(solana_sdk::message::Message::new_with_blockhash(
            &[instruction],
            Some(&fee_payer),
            &recent_blockhash,
        ));

        let sim = client
            .simulate_transaction_with_config(
                &tx,
                RpcSimulateTransactionConfig {
                    sig_verify: false,
                    replace_recent_blockhash: true,
                    commitment: Some(CommitmentConfig::processed()),
                    ..Default::default()
                },
            )
            .await?;

        if let Some(err) = sim.value.err {
            let logs = sim.value.logs.unwrap_or_default().join("\n");
            return Err(SolanaBridgeClientError::InvalidArgument(format!(
                "Simulate error: {err:?}\n{logs}"
            )));
        }

        let Some(return_data) = sim.value.return_data else {
            let logs = sim.value.logs.unwrap_or_default().join("\n");
            return Err(SolanaBridgeClientError::InvalidArgument(format!(
                "No return data from get_version.\n{logs}"
            )));
        };

        let (b64, _enc) = return_data.data;
        let raw = base64::engine::general_purpose::STANDARD
            .decode(b64)
            .map_err(|e| SolanaBridgeClientError::InvalidAccountData(e.to_string()))?;

        if raw.len() < 4 {
            return Err(SolanaBridgeClientError::InvalidAccountData(
                "returnData too short".into(),
            ));
        }
        let len = usize::try_from(u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]])).map_err(
            |_| SolanaBridgeClientError::InvalidAccountData("Invalid length in returnData".into()),
        )?;
        if raw.len() < 4 + len {
            return Err(SolanaBridgeClientError::InvalidAccountData(format!(
                "returnData length mismatch: {} < {}",
                raw.len(),
                4 + len
            )));
        }

        let version = String::from_utf8(raw[4..4 + len].to_vec())
            .map_err(|e| SolanaBridgeClientError::InvalidAccountData(e.to_string()))?;

        Ok(version)
    }

    pub async fn set_admin(&self, admin: Pubkey) -> Result<Signature, SolanaBridgeClientError> {
        let program_id = self.program_id()?;
        let keypair = self.keypair()?;

        let (config, _) = Pubkey::find_program_address(&[b"config"], program_id);

        let instruction_data = SetAdmin { admin };

        let instruction = Instruction::new_with_borsh(
            *program_id,
            &instruction_data,
            vec![
                AccountMeta::new(config, false),
                AccountMeta::new(keypair.pubkey(), true),
            ],
        );

        self.send_and_confirm_transaction(vec![instruction], &[keypair])
            .await
    }

    pub async fn get_transfer_event(
        &self,
        signature: &Signature,
    ) -> Result<Transfer, SolanaBridgeClientError> {
        let client = self.client()?;
        let tx = client
            .get_transaction_with_config(
                signature,
                RpcTransactionConfig {
                    encoding: Some(UiTransactionEncoding::Json),
                    commitment: Some(CommitmentConfig::confirmed()),
                    max_supported_transaction_version: Some(0),
                },
            )
            .await?;

        if let EncodedTransaction::Json(ref transaction) = tx.transaction.transaction {
            if let UiMessage::Raw(ref raw) = transaction.message {
                for instruction in &raw.instructions {
                    let decoded_data = bs58::decode(&instruction.data).into_vec().unwrap();

                    let account_keys = instruction
                        .accounts
                        .clone()
                        .into_iter()
                        .map(|i| raw.account_keys.get(usize::from(i)).cloned())
                        .collect::<Vec<_>>();

                    let get_key = |idx: usize| -> Result<&String, SolanaBridgeClientError> {
                        account_keys
                            .get(idx)
                            .and_then(Option::as_ref)
                            .ok_or(SolanaBridgeClientError::InvalidEvent)
                    };

                    if let Some(discriminator) =
                        [INIT_TRANSFER_DISCRIMINATOR, INIT_TRANSFER_SOL_DISCRIMINATOR]
                            .into_iter()
                            .find(|discriminator| decoded_data.starts_with(discriminator))
                    {
                        let mut payload_data = &decoded_data[discriminator.len()..];

                        if let Ok(payload) = InitTransferPayload::deserialize(&mut payload_data) {
                            let (sender_index, token_index, emitter_index) =
                                if discriminator == INIT_TRANSFER_DISCRIMINATOR {
                                    (
                                        INIT_TRANSFER_SENDER_INDEX,
                                        Some(INIT_TRANSFER_TOKEN_INDEX),
                                        INIT_TRANSFER_EMITTER_INDEX,
                                    )
                                } else {
                                    (
                                        INIT_TRANSFER_SOL_SENDER_INDEX,
                                        None,
                                        INIT_TRANSFER_SOL_EMITTER_INDEX,
                                    )
                                };

                            let sender = get_key(sender_index)?.clone();
                            let token = if let Some(token_index) = token_index {
                                get_key(token_index)?.clone()
                            } else {
                                Pubkey::default().to_string()
                            };
                            let emitter = get_key(emitter_index)?.clone();

                            if let Some(OptionSerializer::Some(logs)) =
                                tx.transaction.clone().meta.map(|meta| meta.log_messages)
                            {
                                let sequence = logs
                                    .iter()
                                    .find(|log| log.contains("Sequence"))
                                    .and_then(|log| log.split_ascii_whitespace().last())
                                    .ok_or_else(|| SolanaBridgeClientError::InvalidEvent)?
                                    .parse::<u64>()
                                    .map_err(|_| SolanaBridgeClientError::InvalidEvent)?;

                                return Ok(Transfer {
                                    amount: payload.amount,
                                    token: token.clone(),
                                    sender: sender.clone(),
                                    recipient: payload.recipient.clone(),
                                    fee: payload.fee,
                                    native_fee: payload.native_fee,
                                    message: payload.message.clone(),
                                    emitter: emitter.clone(),
                                    sequence,
                                });
                            }
                        }
                    }
                }
            }
        }

        Err(SolanaBridgeClientError::InvalidArgument(
            "InitTransfer event not found".to_string(),
        ))
    }

    pub async fn update_metadata(
        &self,
        token: Pubkey,
        name: Option<String>,
        symbol: Option<String>,
        uri: Option<String>,
    ) -> Result<Signature, SolanaBridgeClientError> {
        let program_id = self.program_id()?;
        let keypair = self.keypair()?;

        let (config, _) = Pubkey::find_program_address(&[b"config"], program_id);
        let (authority, _) = Pubkey::find_program_address(&[b"authority"], program_id);

        let metadata_program_id: Pubkey = mpl_token_metadata::ID.to_bytes().into();
        let (metadata, _) = Pubkey::find_program_address(
            &[b"metadata", metadata_program_id.as_ref(), token.as_ref()],
            &metadata_program_id,
        );

        let instruction_data = UpdateMetadata { name, symbol, uri };

        let instruction = Instruction::new_with_borsh(
            *program_id,
            &instruction_data,
            vec![
                AccountMeta::new_readonly(config, false),
                AccountMeta::new_readonly(authority, false),
                AccountMeta::new_readonly(token, false),
                AccountMeta::new(metadata, false),
                AccountMeta::new_readonly(spl_token::ID, false),
                AccountMeta::new_readonly(metadata_program_id, false),
                AccountMeta::new(keypair.pubkey(), true),
            ],
        );

        self.send_and_confirm_transaction(vec![instruction], &[keypair])
            .await
    }

    pub async fn pause(&self) -> Result<Signature, SolanaBridgeClientError> {
        let program_id = self.program_id()?;
        let keypair = self.keypair()?;

        let (config, _) = Pubkey::find_program_address(&[b"config"], program_id);

        let instruction_data = Pause {};

        let instruction = Instruction::new_with_borsh(
            *program_id,
            &instruction_data,
            vec![
                AccountMeta::new(config, false),
                AccountMeta::new(keypair.pubkey(), true),
            ],
        );

        self.send_and_confirm_transaction(vec![instruction], &[keypair])
            .await
    }

    pub async fn log_metadata(&self, token: Pubkey) -> Result<Signature, SolanaBridgeClientError> {
        let program_id = self.program_id()?;
        let wormhole_core = self.wormhole_core()?;
        let keypair = self.keypair()?;

        let (config, _) = Pubkey::find_program_address(&[b"config"], program_id);
        let (authority, _) = Pubkey::find_program_address(&[b"authority"], program_id);
        let (vault, _) = Pubkey::find_program_address(&[b"vault", token.as_ref()], program_id);

        let metadata_program_id: Pubkey = mpl_token_metadata::ID.to_bytes().into();
        let (metadata, _) = Pubkey::find_program_address(
            &[b"metadata", metadata_program_id.as_ref(), token.as_ref()],
            &metadata_program_id,
        );

        let token_program_id = self.get_mint_owner(token).await?;
        if token_program_id != spl_token::ID && token_program_id != spl_token_2022::ID {
            return Err(SolanaBridgeClientError::InvalidArgument(format!(
                "Not a Solana token: {token}"
            )));
        }

        let (wormhole_bridge, wormhole_fee_collector, wormhole_sequence) =
            self.get_wormhole_accounts()?;
        let wormhole_message = Keypair::new();

        let version = self
            .get_version()
            .await
            .unwrap_or(OLD_WORMHOLE_VERSION.to_owned());

        let instruction_data = LogMetadata {
            override_name: String::new(),
            override_symbol: String::new(),
        };

        let (data, signers) = if version == OLD_WORMHOLE_VERSION {
            (
                vec![
                    AccountMeta::new_readonly(authority, false),
                    AccountMeta::new_readonly(token, false),
                    AccountMeta::new(metadata, false),
                    AccountMeta::new(vault, false),
                    AccountMeta::new_readonly(config, false),
                    AccountMeta::new(wormhole_bridge, false),
                    AccountMeta::new(wormhole_fee_collector, false),
                    AccountMeta::new(wormhole_sequence, false),
                    AccountMeta::new(wormhole_message.pubkey(), true),
                    AccountMeta::new(keypair.pubkey(), true),
                    AccountMeta::new_readonly(sysvar::clock::ID, false),
                    AccountMeta::new_readonly(sysvar::rent::ID, false),
                    AccountMeta::new_readonly(*wormhole_core, false),
                    AccountMeta::new_readonly(program::ID, false),
                    AccountMeta::new_readonly(program::ID, false),
                    AccountMeta::new_readonly(token_program_id, false),
                    AccountMeta::new_readonly(spl_associated_token_account::ID, false),
                ],
                vec![keypair, &wormhole_message],
            )
        } else {
            let wormhole_post_message_shim_program_id =
                self.wormhole_post_message_shim_program_id()?;
            let wormhole_post_message_shim_event_authority =
                self.wormhole_post_message_shim_event_authority()?;
            let (shim_message, _) = Pubkey::find_program_address(
                &[config.as_ref()],
                wormhole_post_message_shim_program_id,
            );

            (
                vec![
                    AccountMeta::new_readonly(authority, false),
                    AccountMeta::new_readonly(token, false),
                    AccountMeta::new(metadata, false),
                    AccountMeta::new(vault, false),
                    AccountMeta::new_readonly(config, false),
                    AccountMeta::new(wormhole_bridge, false),
                    AccountMeta::new(wormhole_fee_collector, false),
                    AccountMeta::new(wormhole_sequence, false),
                    AccountMeta::new(shim_message, false),
                    AccountMeta::new(keypair.pubkey(), true),
                    AccountMeta::new_readonly(sysvar::clock::ID, false),
                    AccountMeta::new_readonly(sysvar::rent::ID, false),
                    AccountMeta::new_readonly(*wormhole_core, false),
                    AccountMeta::new_readonly(program::ID, false),
                    AccountMeta::new_readonly(*wormhole_post_message_shim_program_id, false),
                    AccountMeta::new_readonly(*wormhole_post_message_shim_event_authority, false),
                    AccountMeta::new_readonly(program::ID, false),
                    AccountMeta::new_readonly(token_program_id, false),
                    AccountMeta::new_readonly(spl_associated_token_account::ID, false),
                ],
                vec![keypair],
            )
        };

        let instruction = Instruction::new_with_borsh(*program_id, &instruction_data, data);

        self.send_and_confirm_transaction(vec![instruction], &signers)
            .await
    }

    pub async fn deploy_token(
        &self,
        data: DeployTokenData,
    ) -> Result<Signature, SolanaBridgeClientError> {
        let program_id = self.program_id()?;
        let wormhole_core = self.wormhole_core()?;
        let keypair = self.keypair()?;

        let (config, _) = Pubkey::find_program_address(&[b"config"], program_id);
        let (authority, _) = Pubkey::find_program_address(&[b"authority"], program_id);

        let token_bytes = data.metadata.token.as_bytes();
        let token = if token_bytes.len() > 32 {
            let mut token = [0u8; 32];
            token.copy_from_slice(&Sha256::digest(token_bytes));
            token
        } else {
            let mut padded_token_bytes = [0u8; 32];
            padded_token_bytes[..token_bytes.len()].copy_from_slice(token_bytes);
            padded_token_bytes
        };
        let (mint, _) = Pubkey::find_program_address(&[b"wrapped_mint", &token], program_id);

        let metadata_program_id: Pubkey = mpl_token_metadata::ID.to_bytes().into();
        let (metadata, _) = Pubkey::find_program_address(
            &[b"metadata", metadata_program_id.as_ref(), mint.as_ref()],
            &metadata_program_id,
        );

        let (wormhole_bridge, wormhole_fee_collector, wormhole_sequence) =
            self.get_wormhole_accounts()?;
        let wormhole_message = Keypair::new();

        let version = self
            .get_version()
            .await
            .unwrap_or(OLD_WORMHOLE_VERSION.to_owned());

        let instruction_data = DeployToken { data };

        let (data, signers) = if version == OLD_WORMHOLE_VERSION {
            (
                vec![
                    AccountMeta::new_readonly(authority, false),
                    AccountMeta::new(mint, false),
                    AccountMeta::new(metadata, false),
                    AccountMeta::new_readonly(config, false),
                    AccountMeta::new(wormhole_bridge, false),
                    AccountMeta::new(wormhole_fee_collector, false),
                    AccountMeta::new(wormhole_sequence, false),
                    AccountMeta::new(wormhole_message.pubkey(), true),
                    AccountMeta::new(keypair.pubkey(), true),
                    AccountMeta::new_readonly(sysvar::clock::ID, false),
                    AccountMeta::new_readonly(sysvar::rent::ID, false),
                    AccountMeta::new_readonly(*wormhole_core, false),
                    AccountMeta::new_readonly(program::ID, false),
                    AccountMeta::new_readonly(program::ID, false),
                    AccountMeta::new_readonly(spl_token::ID, false),
                    AccountMeta::new_readonly(metadata_program_id, false),
                ],
                vec![keypair, &wormhole_message],
            )
        } else {
            let wormhole_post_message_shim_program_id =
                self.wormhole_post_message_shim_program_id()?;
            let wormhole_post_message_shim_event_authority =
                self.wormhole_post_message_shim_event_authority()?;
            let (shim_message, _) = Pubkey::find_program_address(
                &[config.as_ref()],
                wormhole_post_message_shim_program_id,
            );

            (
                vec![
                    AccountMeta::new_readonly(authority, false),
                    AccountMeta::new(mint, false),
                    AccountMeta::new(metadata, false),
                    AccountMeta::new_readonly(config, false),
                    AccountMeta::new(wormhole_bridge, false),
                    AccountMeta::new(wormhole_fee_collector, false),
                    AccountMeta::new(wormhole_sequence, false),
                    AccountMeta::new(shim_message, false),
                    AccountMeta::new(keypair.pubkey(), true),
                    AccountMeta::new_readonly(sysvar::clock::ID, false),
                    AccountMeta::new_readonly(sysvar::rent::ID, false),
                    AccountMeta::new_readonly(*wormhole_core, false),
                    AccountMeta::new_readonly(program::ID, false),
                    AccountMeta::new_readonly(*wormhole_post_message_shim_program_id, false),
                    AccountMeta::new_readonly(*wormhole_post_message_shim_event_authority, false),
                    AccountMeta::new_readonly(program::ID, false),
                    AccountMeta::new_readonly(spl_token::ID, false),
                    AccountMeta::new_readonly(metadata_program_id, false),
                ],
                vec![keypair],
            )
        };

        let instruction = Instruction::new_with_borsh(*program_id, &instruction_data, data);

        self.send_and_confirm_transaction(vec![instruction], &signers)
            .await
    }

    #[allow(clippy::too_many_lines)]
    pub async fn init_transfer(
        &self,
        token: Pubkey,
        amount: u128,
        recipient: String,
        fee: u128,
        native_fee: u64,
        message: String,
    ) -> Result<Signature, SolanaBridgeClientError> {
        let program_id = self.program_id()?;
        let wormhole_core = self.wormhole_core()?;
        let keypair = self.keypair()?;

        let (config, _) = Pubkey::find_program_address(&[b"config"], program_id);
        let (authority, _) = Pubkey::find_program_address(&[b"authority"], program_id);
        let (sol_vault, _) = Pubkey::find_program_address(&[b"sol_vault"], program_id);

        let token_program_id = self.get_mint_owner(token).await?;
        if token_program_id != spl_token::ID && token_program_id != spl_token_2022::ID {
            return Err(SolanaBridgeClientError::InvalidArgument(format!(
                "Not a Solana token: {token}"
            )));
        }

        let (from_token_account, _) = Pubkey::find_program_address(
            &[
                keypair.pubkey().as_ref(),
                token_program_id.as_ref(),
                token.as_ref(),
            ],
            &spl_associated_token_account::ID,
        );

        let (wormhole_bridge, wormhole_fee_collector, wormhole_sequence) =
            self.get_wormhole_accounts()?;
        let wormhole_message = Keypair::new();

        let version = self
            .get_version()
            .await
            .unwrap_or(OLD_WORMHOLE_VERSION.to_owned());

        let is_bridged_token = match self.get_token_owner(token).await? {
            COption::Some(owner) => owner == authority,
            COption::None => false,
        };

        // TODO: Proved fee&native fee through the arguments
        let instruction_data = InitTransfer {
            amount,
            recipient,
            fee,
            native_fee,
            message,
        };

        let (data, signers) = if version == OLD_WORMHOLE_VERSION {
            (
                vec![
                    AccountMeta::new_readonly(authority, false),
                    AccountMeta::new(token, false),
                    AccountMeta::new(from_token_account, false),
                    if is_bridged_token {
                        AccountMeta::new(*program_id, false) // Vault is not present for non-native tokens
                    } else {
                        let (vault, _) =
                            Pubkey::find_program_address(&[b"vault", token.as_ref()], program_id);
                        AccountMeta::new(vault, false)
                    },
                    AccountMeta::new(sol_vault, false),
                    AccountMeta::new(keypair.pubkey(), true),
                    AccountMeta::new_readonly(config, false),
                    AccountMeta::new(wormhole_bridge, false),
                    AccountMeta::new(wormhole_fee_collector, false),
                    AccountMeta::new(wormhole_sequence, false),
                    AccountMeta::new(wormhole_message.pubkey(), true),
                    AccountMeta::new(keypair.pubkey(), true),
                    AccountMeta::new_readonly(sysvar::clock::ID, false),
                    AccountMeta::new_readonly(sysvar::rent::ID, false),
                    AccountMeta::new_readonly(*wormhole_core, false),
                    AccountMeta::new_readonly(program::ID, false),
                    AccountMeta::new_readonly(token_program_id, false),
                ],
                vec![keypair, &wormhole_message],
            )
        } else {
            let wormhole_post_message_shim_program_id =
                self.wormhole_post_message_shim_program_id()?;
            let wormhole_post_message_shim_event_authority =
                self.wormhole_post_message_shim_event_authority()?;
            let (shim_message, _) = Pubkey::find_program_address(
                &[config.as_ref()],
                wormhole_post_message_shim_program_id,
            );

            (
                vec![
                    AccountMeta::new_readonly(authority, false),
                    AccountMeta::new(token, false),
                    AccountMeta::new(from_token_account, false),
                    if is_bridged_token {
                        AccountMeta::new(*program_id, false) // Vault is not present for non-native tokens
                    } else {
                        let (vault, _) =
                            Pubkey::find_program_address(&[b"vault", token.as_ref()], program_id);
                        AccountMeta::new(vault, false)
                    },
                    AccountMeta::new(sol_vault, false),
                    AccountMeta::new(keypair.pubkey(), true),
                    AccountMeta::new_readonly(config, false),
                    AccountMeta::new(wormhole_bridge, false),
                    AccountMeta::new(wormhole_fee_collector, false),
                    AccountMeta::new(wormhole_sequence, false),
                    AccountMeta::new(shim_message, false),
                    AccountMeta::new(keypair.pubkey(), true),
                    AccountMeta::new_readonly(sysvar::clock::ID, false),
                    AccountMeta::new_readonly(sysvar::rent::ID, false),
                    AccountMeta::new_readonly(*wormhole_core, false),
                    AccountMeta::new_readonly(program::ID, false),
                    AccountMeta::new_readonly(*wormhole_post_message_shim_program_id, false),
                    AccountMeta::new_readonly(*wormhole_post_message_shim_event_authority, false),
                    AccountMeta::new_readonly(token_program_id, false),
                ],
                vec![keypair],
            )
        };

        let instruction = Instruction::new_with_borsh(*program_id, &instruction_data, data);

        self.send_and_confirm_transaction(vec![instruction], &signers)
            .await
    }

    pub async fn is_transfer_finalised(&self, nonce: u64) -> Result<bool, SolanaBridgeClientError> {
        let program_id = self.program_id()?;
        let (used_nonces, _) = Pubkey::find_program_address(
            &[
                b"used_nonces",
                (nonce / USED_NONCES_PER_ACCOUNT).to_le_bytes().as_ref(),
            ],
            program_id,
        );

        let account = match self.client()?.get_account(&used_nonces).await {
            Ok(account) => account,
            Err(err) => {
                return if err.to_string().contains("AccountNotFound") {
                    Ok(false)
                } else {
                    Err(err.into())
                };
            }
        };
        let data = &account.data;

        if data.len() < DISCRIMINATOR_LEN + BIT_BYTES {
            return Err(SolanaBridgeClientError::InvalidAccountData(format!(
                "Account data too small: {} bytes (need at least {})",
                data.len(),
                DISCRIMINATOR_LEN + BIT_BYTES
            )));
        }

        let raw_bits = &data[DISCRIMINATOR_LEN..DISCRIMINATOR_LEN + BIT_BYTES];
        let mut buf = [0u8; BIT_BYTES];
        buf.copy_from_slice(raw_bits);

        let bits = BitArray::<[u8; BIT_BYTES]>::new(buf);

        let slot = usize::try_from(nonce % USED_NONCES_PER_ACCOUNT).map_err(|_| {
            SolanaBridgeClientError::InvalidArgument(format!(
                "Nonce out of range: {nonce} (max: {})",
                USED_NONCES_PER_ACCOUNT - 1
            ))
        })?;

        let bit = bits.get(slot);
        match bit {
            Some(bit) => Ok(*bit),
            None => Err(SolanaBridgeClientError::InvalidArgument(format!(
                "Slot index out of range: {slot} (bits len: {})",
                bits.len()
            ))),
        }
    }

    pub async fn init_transfer_sol(
        &self,
        amount: u128,
        recipient: String,
        fee: u128,
        native_fee: u64,
        message: String,
    ) -> Result<Signature, SolanaBridgeClientError> {
        let program_id = self.program_id()?;
        let wormhole_core = self.wormhole_core()?;
        let keypair = self.keypair()?;

        let (config, _) = Pubkey::find_program_address(&[b"config"], program_id);
        let (sol_vault, _) = Pubkey::find_program_address(&[b"sol_vault"], program_id);

        let (wormhole_bridge, wormhole_fee_collector, wormhole_sequence) =
            self.get_wormhole_accounts()?;
        let wormhole_message = Keypair::new();

        let version = self
            .get_version()
            .await
            .unwrap_or(OLD_WORMHOLE_VERSION.to_owned());

        let instruction_data = InitTransferSol {
            amount,
            recipient,
            fee,
            native_fee,
            message,
        };

        let (data, signers) = if version == OLD_WORMHOLE_VERSION {
            (
                vec![
                    AccountMeta::new(sol_vault, false),
                    AccountMeta::new_readonly(keypair.pubkey(), true),
                    AccountMeta::new_readonly(config, false),
                    AccountMeta::new(wormhole_bridge, false),
                    AccountMeta::new(wormhole_fee_collector, false),
                    AccountMeta::new(wormhole_sequence, false),
                    AccountMeta::new(wormhole_message.pubkey(), true),
                    AccountMeta::new(keypair.pubkey(), true),
                    AccountMeta::new_readonly(sysvar::clock::ID, false),
                    AccountMeta::new_readonly(sysvar::rent::ID, false),
                    AccountMeta::new_readonly(*wormhole_core, false),
                    AccountMeta::new_readonly(program::ID, false),
                ],
                vec![keypair, &wormhole_message],
            )
        } else {
            let wormhole_post_message_shim_program_id =
                self.wormhole_post_message_shim_program_id()?;
            let wormhole_post_message_shim_event_authority =
                self.wormhole_post_message_shim_event_authority()?;
            let (shim_message, _) = Pubkey::find_program_address(
                &[config.as_ref()],
                wormhole_post_message_shim_program_id,
            );

            (
                vec![
                    AccountMeta::new(sol_vault, false),
                    AccountMeta::new_readonly(keypair.pubkey(), true),
                    AccountMeta::new_readonly(config, false),
                    AccountMeta::new(wormhole_bridge, false),
                    AccountMeta::new(wormhole_fee_collector, false),
                    AccountMeta::new(wormhole_sequence, false),
                    AccountMeta::new(shim_message, false),
                    AccountMeta::new(keypair.pubkey(), true),
                    AccountMeta::new_readonly(sysvar::clock::ID, false),
                    AccountMeta::new_readonly(sysvar::rent::ID, false),
                    AccountMeta::new_readonly(*wormhole_core, false),
                    AccountMeta::new_readonly(program::ID, false),
                    AccountMeta::new_readonly(*wormhole_post_message_shim_program_id, false),
                    AccountMeta::new_readonly(*wormhole_post_message_shim_event_authority, false),
                ],
                vec![keypair],
            )
        };

        let instruction = Instruction::new_with_borsh(*program_id, &instruction_data, data);

        self.send_and_confirm_transaction(vec![instruction], &signers)
            .await
    }

    #[allow(clippy::too_many_lines)]
    pub async fn finalize_transfer(
        &self,
        data: FinalizeDepositData,
        solana_token: Pubkey,
    ) -> Result<Signature, SolanaBridgeClientError> {
        let program_id = self.program_id()?;
        let wormhole_core = self.wormhole_core()?;
        let keypair = self.keypair()?;

        let (config, _) = Pubkey::find_program_address(&[b"config"], program_id);

        let (used_nonces, _) = Pubkey::find_program_address(
            &[
                b"used_nonces",
                (data.payload.destination_nonce / USED_NONCES_PER_ACCOUNT)
                    .to_le_bytes()
                    .as_ref(),
            ],
            program_id,
        );
        let recipient = data.payload.recipient;
        let (authority, _) = Pubkey::find_program_address(&[b"authority"], program_id);

        let token_program_id = self.get_mint_owner(solana_token).await?;
        if token_program_id != spl_token::ID && token_program_id != spl_token_2022::ID {
            return Err(SolanaBridgeClientError::InvalidArgument(format!(
                "Not a Solana token: {solana_token}"
            )));
        }

        let (token_account, _) = Pubkey::find_program_address(
            &[
                recipient.as_ref(),
                token_program_id.as_ref(),
                solana_token.as_ref(),
            ],
            &spl_associated_token_account::ID,
        );

        let (wormhole_bridge, wormhole_fee_collector, wormhole_sequence) =
            self.get_wormhole_accounts()?;
        let wormhole_message = Keypair::new();

        let version = self
            .get_version()
            .await
            .unwrap_or(OLD_WORMHOLE_VERSION.to_owned());

        let instruction_data = FinalizeTransfer {
            payload: FinalizeTransferInstructionPayload {
                destination_nonce: data.payload.destination_nonce,
                transfer_id: data.payload.transfer_id,
                amount: data.payload.amount,
                fee_recipient: data.payload.fee_recipient,
            },
            signature: data.signature,
        };

        let is_bridged_token = match self.get_token_owner(solana_token).await? {
            COption::Some(owner) => owner == authority,
            COption::None => false,
        };

        let (data, signers) = if version == OLD_WORMHOLE_VERSION {
            (
                vec![
                    AccountMeta::new(used_nonces, false),
                    AccountMeta::new(authority, false),
                    AccountMeta::new_readonly(recipient, false),
                    AccountMeta::new(solana_token, false),
                    if is_bridged_token {
                        AccountMeta::new(*program_id, false) // Vault is not present for non-native tokens
                    } else {
                        let (vault, _) = Pubkey::find_program_address(
                            &[b"vault", solana_token.as_ref()],
                            program_id,
                        );
                        AccountMeta::new(vault, false)
                    },
                    AccountMeta::new(token_account, false),
                    AccountMeta::new_readonly(config, false),
                    AccountMeta::new(wormhole_bridge, false),
                    AccountMeta::new(wormhole_fee_collector, false),
                    AccountMeta::new(wormhole_sequence, false),
                    AccountMeta::new(wormhole_message.pubkey(), true),
                    AccountMeta::new(keypair.pubkey(), true),
                    AccountMeta::new_readonly(sysvar::clock::ID, false),
                    AccountMeta::new_readonly(sysvar::rent::ID, false),
                    AccountMeta::new_readonly(*wormhole_core, false),
                    AccountMeta::new_readonly(program::ID, false),
                    AccountMeta::new_readonly(spl_associated_token_account::ID, false),
                    AccountMeta::new_readonly(program::ID, false),
                    AccountMeta::new_readonly(token_program_id, false),
                ],
                vec![keypair, &wormhole_message],
            )
        } else {
            let wormhole_post_message_shim_program_id =
                self.wormhole_post_message_shim_program_id()?;
            let wormhole_post_message_shim_event_authority =
                self.wormhole_post_message_shim_event_authority()?;
            let (shim_message, _) = Pubkey::find_program_address(
                &[config.as_ref()],
                wormhole_post_message_shim_program_id,
            );

            (
                vec![
                    AccountMeta::new(used_nonces, false),
                    AccountMeta::new(authority, false),
                    AccountMeta::new_readonly(recipient, false),
                    AccountMeta::new(solana_token, false),
                    if is_bridged_token {
                        AccountMeta::new(*program_id, false) // Vault is not present for non-native tokens
                    } else {
                        let (vault, _) = Pubkey::find_program_address(
                            &[b"vault", solana_token.as_ref()],
                            program_id,
                        );
                        AccountMeta::new(vault, false)
                    },
                    AccountMeta::new(token_account, false),
                    AccountMeta::new_readonly(config, false),
                    AccountMeta::new(wormhole_bridge, false),
                    AccountMeta::new(wormhole_fee_collector, false),
                    AccountMeta::new(wormhole_sequence, false),
                    AccountMeta::new(shim_message, false),
                    AccountMeta::new(keypair.pubkey(), true),
                    AccountMeta::new_readonly(sysvar::clock::ID, false),
                    AccountMeta::new_readonly(sysvar::rent::ID, false),
                    AccountMeta::new_readonly(*wormhole_core, false),
                    AccountMeta::new_readonly(program::ID, false),
                    AccountMeta::new_readonly(*wormhole_post_message_shim_program_id, false),
                    AccountMeta::new_readonly(*wormhole_post_message_shim_event_authority, false),
                    AccountMeta::new_readonly(spl_associated_token_account::ID, false),
                    AccountMeta::new_readonly(program::ID, false),
                    AccountMeta::new_readonly(token_program_id, false),
                ],
                vec![keypair],
            )
        };

        let instruction = Instruction::new_with_borsh(*program_id, &instruction_data, data);

        self.send_and_confirm_transaction(vec![instruction], &signers)
            .await
    }

    pub async fn finalize_transfer_sol(
        &self,
        data: FinalizeDepositData,
    ) -> Result<Signature, SolanaBridgeClientError> {
        let program_id = self.program_id()?;
        let wormhole_core = self.wormhole_core()?;
        let keypair = self.keypair()?;

        let (config, _) = Pubkey::find_program_address(&[b"config"], program_id);
        let (sol_vault, _) = Pubkey::find_program_address(&[b"sol_vault"], program_id);

        let (used_nonces, _) = Pubkey::find_program_address(
            &[
                b"used_nonces",
                (data.payload.destination_nonce / USED_NONCES_PER_ACCOUNT)
                    .to_le_bytes()
                    .as_ref(),
            ],
            program_id,
        );
        let recipient = data.payload.recipient;
        let (authority, _) = Pubkey::find_program_address(&[b"authority"], program_id);

        let (wormhole_bridge, wormhole_fee_collector, wormhole_sequence) =
            self.get_wormhole_accounts()?;
        let wormhole_message = Keypair::new();

        let version = self
            .get_version()
            .await
            .unwrap_or(OLD_WORMHOLE_VERSION.to_owned());

        let instruction_data = FinalizeTransferSol {
            payload: FinalizeTransferInstructionPayload {
                destination_nonce: data.payload.destination_nonce,
                transfer_id: data.payload.transfer_id,
                amount: data.payload.amount,
                fee_recipient: data.payload.fee_recipient,
            },
            signature: data.signature,
        };

        let (data, signers) = if version == OLD_WORMHOLE_VERSION {
            (
                vec![
                    AccountMeta::new(config, false),
                    AccountMeta::new(used_nonces, false),
                    AccountMeta::new(authority, false),
                    AccountMeta::new_readonly(recipient, false),
                    AccountMeta::new(sol_vault, false),
                    AccountMeta::new_readonly(config, false),
                    AccountMeta::new(wormhole_bridge, false),
                    AccountMeta::new(wormhole_fee_collector, false),
                    AccountMeta::new(wormhole_sequence, false),
                    AccountMeta::new(wormhole_message.pubkey(), true),
                    AccountMeta::new(keypair.pubkey(), true),
                    AccountMeta::new_readonly(sysvar::clock::ID, false),
                    AccountMeta::new_readonly(sysvar::rent::ID, false),
                    AccountMeta::new_readonly(*wormhole_core, false),
                    AccountMeta::new_readonly(program::ID, false),
                    AccountMeta::new_readonly(program::ID, false),
                ],
                vec![keypair, &wormhole_message],
            )
        } else {
            let wormhole_post_message_shim_program_id =
                self.wormhole_post_message_shim_program_id()?;
            let wormhole_post_message_shim_event_authority =
                self.wormhole_post_message_shim_event_authority()?;
            let (shim_message, _) = Pubkey::find_program_address(
                &[config.as_ref()],
                wormhole_post_message_shim_program_id,
            );

            (
                vec![
                    AccountMeta::new(config, false),
                    AccountMeta::new(used_nonces, false),
                    AccountMeta::new(authority, false),
                    AccountMeta::new(recipient, false),
                    AccountMeta::new(sol_vault, false),
                    AccountMeta::new_readonly(config, false),
                    AccountMeta::new(wormhole_bridge, false),
                    AccountMeta::new(wormhole_fee_collector, false),
                    AccountMeta::new(wormhole_sequence, false),
                    AccountMeta::new(shim_message, false),
                    AccountMeta::new(keypair.pubkey(), true),
                    AccountMeta::new_readonly(sysvar::clock::ID, false),
                    AccountMeta::new_readonly(sysvar::rent::ID, false),
                    AccountMeta::new_readonly(*wormhole_core, false),
                    AccountMeta::new_readonly(program::ID, false),
                    AccountMeta::new_readonly(*wormhole_post_message_shim_program_id, false),
                    AccountMeta::new_readonly(*wormhole_post_message_shim_event_authority, false),
                    AccountMeta::new_readonly(program::ID, false),
                ],
                vec![keypair],
            )
        };

        let instruction = Instruction::new_with_borsh(*program_id, &instruction_data, data);

        self.send_and_confirm_transaction(vec![instruction], &signers)
            .await
    }

    fn get_wormhole_accounts(&self) -> Result<(Pubkey, Pubkey, Pubkey), SolanaBridgeClientError> {
        let program_id = self.program_id()?;
        let wormhole_core = self.wormhole_core()?;

        let (config, _) = Pubkey::find_program_address(&[b"config"], program_id);
        let (wormhole_bridge, _) = Pubkey::find_program_address(&[b"Bridge"], wormhole_core);
        let (wormhole_fee_collector, _) =
            Pubkey::find_program_address(&[b"fee_collector"], wormhole_core);
        let (wormhole_sequence, _) =
            Pubkey::find_program_address(&[b"Sequence", config.as_ref()], wormhole_core);

        Ok((wormhole_bridge, wormhole_fee_collector, wormhole_sequence))
    }

    async fn send_and_confirm_transaction(
        &self,
        instructions: Vec<Instruction>,
        signers: &[&Keypair],
    ) -> Result<Signature, SolanaBridgeClientError> {
        let client = self.client()?;

        let recent_blockhash = client.get_latest_blockhash().await?;

        let transaction = Transaction::new_signed_with_payer(
            &instructions,
            Some(&signers[0].pubkey()),
            signers,
            recent_blockhash,
        );

        let signature = client.send_and_confirm_transaction(&transaction).await?;
        Ok(signature)
    }

    async fn get_token_owner(
        &self,
        token: Pubkey,
    ) -> Result<COption<Pubkey>, SolanaBridgeClientError> {
        const MINT_BASIC_DATA_SIZE: usize = 82;

        let client = self.client()?;

        let mint_account = client.get_account(&token).await?;
        let mint_data = Mint::unpack(&mint_account.data[..MINT_BASIC_DATA_SIZE])
            .map_err(|e| SolanaBridgeClientError::InvalidAccountData(e.to_string()))?;

        Ok(mint_data.mint_authority)
    }

    async fn get_mint_owner(&self, token: Pubkey) -> Result<Pubkey, SolanaBridgeClientError> {
        let client = self.client()?;

        let mint_account = client.get_account(&token).await?;

        Ok(mint_account.owner)
    }

    pub fn client(&self) -> Result<&RpcClient, SolanaBridgeClientError> {
        self.client
            .as_ref()
            .ok_or(SolanaBridgeClientError::ConfigError(
                "Client not initialized".to_string(),
            ))
    }

    pub fn program_id(&self) -> Result<&Pubkey, SolanaBridgeClientError> {
        self.program_id
            .as_ref()
            .ok_or(SolanaBridgeClientError::ConfigError(
                "Program ID not initialized".to_string(),
            ))
    }

    pub fn wormhole_core(&self) -> Result<&Pubkey, SolanaBridgeClientError> {
        self.wormhole_core
            .as_ref()
            .ok_or(SolanaBridgeClientError::ConfigError(
                "Wormhole Core not initialized".to_string(),
            ))
    }

    pub fn wormhole_post_message_shim_program_id(
        &self,
    ) -> Result<&Pubkey, SolanaBridgeClientError> {
        self.wormhole_post_message_shim_program_id.as_ref().ok_or(
            SolanaBridgeClientError::ConfigError(
                "Wormhole Post Message Shim Program ID not initialized".to_string(),
            ),
        )
    }

    pub fn wormhole_post_message_shim_event_authority(
        &self,
    ) -> Result<&Pubkey, SolanaBridgeClientError> {
        self.wormhole_post_message_shim_event_authority
            .as_ref()
            .ok_or(SolanaBridgeClientError::ConfigError(
                "Wormhole Post Message Shim Event Authority not initialized".to_string(),
            ))
    }

    pub fn keypair(&self) -> Result<&Keypair, SolanaBridgeClientError> {
        self.keypair
            .as_ref()
            .ok_or(SolanaBridgeClientError::ConfigError(
                "Keypair not initialized".to_string(),
            ))
    }
}
