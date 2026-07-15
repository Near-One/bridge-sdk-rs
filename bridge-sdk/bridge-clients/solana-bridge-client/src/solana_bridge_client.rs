use base64::Engine;
#[cfg(feature = "client")]
use bitvec::array::BitArray;
use borsh::{BorshDeserialize, BorshSerialize};
use derive_builder::Builder;
use instructions::UpdateMetadata;
use sha2::{Digest, Sha256};
#[cfg(feature = "client")]
use solana_commitment_config::CommitmentConfig;
use solana_instruction::{AccountMeta, Instruction};
use solana_keypair::Keypair;
#[cfg(feature = "client")]
use solana_program_option::COption;
#[cfg(feature = "client")]
use solana_program_pack::Pack;
use solana_pubkey::Pubkey;
#[cfg(feature = "client")]
use solana_rpc_client::nonblocking::rpc_client::RpcClient;
#[cfg(feature = "client")]
use solana_rpc_client_api::config::RpcTransactionConfig;
use solana_sdk_ids::sysvar;
#[cfg(any(feature = "client", test))]
use solana_signature::Signature;
use solana_signer::Signer;
use solana_system_interface::program;
use solana_transaction::Transaction;
#[cfg(feature = "client")]
use solana_transaction_status_client_types::{
    option_serializer::OptionSerializer, EncodedTransaction, UiMessage, UiTransactionEncoding,
};
#[cfg(feature = "client")]
use spl_token::state::Mint;

#[cfg(feature = "client")]
use crate::instructions::Initialize;
use crate::{
    error::SolanaBridgeClientError,
    instructions::{
        DeployToken, FinalizeTransfer, FinalizeTransferInstructionPayload, FinalizeTransferSol,
        InitTransfer, InitTransferSol, LogMetadata, Pause, SetAdmin,
    },
};

pub mod error;
mod instructions;

/// Metaplex Token Metadata program id. The mpl-token-metadata crate is not
/// used because it has no stable release on the modern solana crate line
/// (only 5.1.2-alpha.2); the id is all we need (PDA seeds).
pub const MPL_TOKEN_METADATA_PROGRAM_ID: Pubkey =
    Pubkey::from_str_const("metaqbxxUerdq28cj1RbAWkYQm3ybzjb6a8bt518x1s");

#[cfg(any(feature = "client", test))]
const DISCRIMINATOR_LEN: usize = 8;
#[cfg(any(feature = "client", test))]
const INIT_TRANSFER_DISCRIMINATOR: [u8; DISCRIMINATOR_LEN] = [174, 50, 134, 99, 122, 243, 243, 224];
#[cfg(any(feature = "client", test))]
const INIT_TRANSFER_SOL_DISCRIMINATOR: [u8; DISCRIMINATOR_LEN] =
    [124, 167, 164, 191, 81, 140, 108, 30];
#[cfg(feature = "client")]
const GET_VERSION_DISCRIMINATOR: [u8; 8] = [168, 85, 244, 45, 81, 56, 130, 50];

#[cfg(feature = "client")]
const INIT_TRANSFER_SENDER_INDEX: usize = 5;
#[cfg(feature = "client")]
const INIT_TRANSFER_TOKEN_INDEX: usize = 1;
#[cfg(feature = "client")]
const INIT_TRANSFER_EMITTER_INDEX: usize = 6;
#[cfg(feature = "client")]
const INIT_TRANSFER_SOL_SENDER_INDEX: usize = 1;
#[cfg(feature = "client")]
const INIT_TRANSFER_SOL_EMITTER_INDEX: usize = 2;

const USED_NONCES_PER_ACCOUNT: u64 = 1024;

#[cfg(feature = "client")]
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

#[cfg(feature = "client")]
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

/// Transaction signer: a real keypair, or — for dry-run/offline-signing flows —
/// only the signer's public key (no private key required).
pub enum SvmSigner {
    Keypair(Keypair),
    DryRun(Pubkey),
}

impl SvmSigner {
    pub fn pubkey(&self) -> Pubkey {
        match self {
            SvmSigner::Keypair(keypair) => keypair.pubkey(),
            SvmSigner::DryRun(pubkey) => *pubkey,
        }
    }

    pub fn keypair(&self) -> Result<&Keypair, SolanaBridgeClientError> {
        match self {
            SvmSigner::Keypair(keypair) => Ok(keypair),
            SvmSigner::DryRun(_) => Err(SolanaBridgeClientError::ConfigError(
                "Operation requires a keypair but the client is in dry-run mode".to_string(),
            )),
        }
    }

    pub const fn is_dry_run(&self) -> bool {
        matches!(self, SvmSigner::DryRun(_))
    }
}

#[derive(Builder)]
#[builder(pattern = "owned")]
pub struct SolanaBridgeClient {
    #[cfg(feature = "client")]
    client: Option<RpcClient>,
    program_id: Option<Pubkey>,
    wormhole_core: Option<Pubkey>,
    wormhole_post_message_shim_program_id: Option<Pubkey>,
    signer: Option<SvmSigner>,
}

impl SolanaBridgeClient {
    #[cfg(feature = "client")]
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

        self.send_and_confirm_transaction(vec![instruction], &[&wormhole_message, &program_keypair])
            .await
    }

    #[cfg(feature = "client")]
    pub async fn get_version(&self) -> Result<String, SolanaBridgeClientError> {
        use solana_rpc_client_api::config::RpcSimulateTransactionConfig;

        let client = self.client()?;
        let program_id = self.program_id()?;
        let fee_payer = self.signer()?.pubkey();

        let instruction = Instruction {
            program_id: *program_id,
            accounts: vec![],
            data: GET_VERSION_DISCRIMINATOR.to_vec(),
        };

        let recent_blockhash = client.get_latest_blockhash().await?;
        let tx = Transaction::new_unsigned(solana_message::Message::new_with_blockhash(
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

    pub fn build_set_admin_instruction(
        &self,
        admin: Pubkey,
        payer: Pubkey,
    ) -> Result<Instruction, SolanaBridgeClientError> {
        let program_id = self.program_id()?;

        let (config, _) = Pubkey::find_program_address(&[b"config"], program_id);

        let instruction_data = SetAdmin { admin };

        Ok(Instruction::new_with_borsh(
            *program_id,
            &instruction_data,
            vec![
                AccountMeta::new(config, false),
                AccountMeta::new(payer, true),
            ],
        ))
    }

    #[cfg(feature = "client")]
    pub async fn set_admin(&self, admin: Pubkey) -> Result<Signature, SolanaBridgeClientError> {
        let payer = self.signer()?.pubkey();
        let instruction = self.build_set_admin_instruction(admin, payer)?;
        self.send_and_confirm_transaction(vec![instruction], &[])
            .await
    }

    #[cfg(feature = "client")]
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

    pub fn build_update_metadata_instruction(
        &self,
        token: Pubkey,
        name: Option<String>,
        symbol: Option<String>,
        uri: Option<String>,
        payer: Pubkey,
    ) -> Result<Instruction, SolanaBridgeClientError> {
        let program_id = self.program_id()?;

        let (config, _) = Pubkey::find_program_address(&[b"config"], program_id);
        let (authority, _) = Pubkey::find_program_address(&[b"authority"], program_id);

        let metadata_program_id = MPL_TOKEN_METADATA_PROGRAM_ID;
        let (metadata, _) = Pubkey::find_program_address(
            &[b"metadata", metadata_program_id.as_ref(), token.as_ref()],
            &metadata_program_id,
        );

        let instruction_data = UpdateMetadata { name, symbol, uri };

        Ok(Instruction::new_with_borsh(
            *program_id,
            &instruction_data,
            vec![
                AccountMeta::new_readonly(config, false),
                AccountMeta::new_readonly(authority, false),
                AccountMeta::new_readonly(token, false),
                AccountMeta::new(metadata, false),
                AccountMeta::new_readonly(spl_token::ID, false),
                AccountMeta::new_readonly(metadata_program_id, false),
                AccountMeta::new(payer, true),
            ],
        ))
    }

    #[cfg(feature = "client")]
    pub async fn update_metadata(
        &self,
        token: Pubkey,
        name: Option<String>,
        symbol: Option<String>,
        uri: Option<String>,
    ) -> Result<Signature, SolanaBridgeClientError> {
        let payer = self.signer()?.pubkey();
        let instruction =
            self.build_update_metadata_instruction(token, name, symbol, uri, payer)?;
        self.send_and_confirm_transaction(vec![instruction], &[])
            .await
    }

    pub fn build_pause_instruction(
        &self,
        payer: Pubkey,
    ) -> Result<Instruction, SolanaBridgeClientError> {
        let program_id = self.program_id()?;

        let (config, _) = Pubkey::find_program_address(&[b"config"], program_id);

        let instruction_data = Pause {};

        Ok(Instruction::new_with_borsh(
            *program_id,
            &instruction_data,
            vec![
                AccountMeta::new(config, false),
                AccountMeta::new(payer, true),
            ],
        ))
    }

    #[cfg(feature = "client")]
    pub async fn pause(&self) -> Result<Signature, SolanaBridgeClientError> {
        let payer = self.signer()?.pubkey();
        let instruction = self.build_pause_instruction(payer)?;
        self.send_and_confirm_transaction(vec![instruction], &[])
            .await
    }

    /// `token_program_id` is a consensus-critical input: it must be the
    /// program that owns `token`'s mint account — get it from
    /// `fetch_token_program_id` (requires the `client` feature) or an
    /// equally trusted source. It is
    /// validated against the SPL Token / Token-2022 program ids and passed as
    /// the token-program account the bridge program invokes; a mismatched
    /// value builds a valid-looking instruction that fails or misroutes
    /// on chain.
    pub fn build_log_metadata_instruction(
        &self,
        token: Pubkey,
        token_program_id: Pubkey,
        payer: Pubkey,
    ) -> Result<Instruction, SolanaBridgeClientError> {
        let program_id = self.program_id()?;
        let wormhole_core = self.wormhole_core()?;

        let (config, _) = Pubkey::find_program_address(&[b"config"], program_id);
        let (authority, _) = Pubkey::find_program_address(&[b"authority"], program_id);
        let (vault, _) = Pubkey::find_program_address(&[b"vault", token.as_ref()], program_id);

        let metadata_program_id = MPL_TOKEN_METADATA_PROGRAM_ID;
        let (metadata, _) = Pubkey::find_program_address(
            &[b"metadata", metadata_program_id.as_ref(), token.as_ref()],
            &metadata_program_id,
        );

        if token_program_id != spl_token::ID && token_program_id != spl_token_2022_interface::ID {
            return Err(SolanaBridgeClientError::InvalidArgument(format!(
                "Not a Solana token program: {token_program_id}"
            )));
        }

        let (wormhole_bridge, wormhole_fee_collector, wormhole_sequence) =
            self.get_wormhole_accounts()?;

        let wormhole_post_message_shim_program_id = self.wormhole_post_message_shim_program_id()?;
        let (wormhole_post_message_shim_event_authority, _) = Pubkey::find_program_address(
            &[b"__event_authority"],
            wormhole_post_message_shim_program_id,
        );
        let (shim_message, _) =
            Pubkey::find_program_address(&[config.as_ref()], wormhole_post_message_shim_program_id);

        let instruction_data = LogMetadata {
            override_name: String::new(),
            override_symbol: String::new(),
        };

        Ok(Instruction::new_with_borsh(
            *program_id,
            &instruction_data,
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
                AccountMeta::new(payer, true),
                AccountMeta::new_readonly(sysvar::clock::ID, false),
                AccountMeta::new_readonly(sysvar::rent::ID, false),
                AccountMeta::new_readonly(*wormhole_core, false),
                AccountMeta::new_readonly(program::ID, false),
                AccountMeta::new_readonly(*wormhole_post_message_shim_program_id, false),
                AccountMeta::new_readonly(wormhole_post_message_shim_event_authority, false),
                AccountMeta::new_readonly(program::ID, false),
                AccountMeta::new_readonly(token_program_id, false),
                AccountMeta::new_readonly(
                    spl_associated_token_account_interface::program::ID,
                    false,
                ),
            ],
        ))
    }

    #[cfg(feature = "client")]
    pub async fn log_metadata(&self, token: Pubkey) -> Result<Signature, SolanaBridgeClientError> {
        let payer = self.signer()?.pubkey();
        let token_program_id = self.fetch_token_program_id(token).await?;
        let instruction = self.build_log_metadata_instruction(token, token_program_id, payer)?;
        self.send_and_confirm_transaction(vec![instruction], &[])
            .await
    }

    pub fn build_deploy_token_instruction(
        &self,
        data: DeployTokenData,
        payer: Pubkey,
    ) -> Result<Instruction, SolanaBridgeClientError> {
        let program_id = self.program_id()?;
        let wormhole_core = self.wormhole_core()?;

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

        let metadata_program_id = MPL_TOKEN_METADATA_PROGRAM_ID;
        let (metadata, _) = Pubkey::find_program_address(
            &[b"metadata", metadata_program_id.as_ref(), mint.as_ref()],
            &metadata_program_id,
        );

        let (wormhole_bridge, wormhole_fee_collector, wormhole_sequence) =
            self.get_wormhole_accounts()?;

        let wormhole_post_message_shim_program_id = self.wormhole_post_message_shim_program_id()?;
        let (wormhole_post_message_shim_event_authority, _) = Pubkey::find_program_address(
            &[b"__event_authority"],
            wormhole_post_message_shim_program_id,
        );
        let (shim_message, _) =
            Pubkey::find_program_address(&[config.as_ref()], wormhole_post_message_shim_program_id);

        let instruction_data = DeployToken { data };

        Ok(Instruction::new_with_borsh(
            *program_id,
            &instruction_data,
            vec![
                AccountMeta::new_readonly(authority, false),
                AccountMeta::new(mint, false),
                AccountMeta::new(metadata, false),
                AccountMeta::new_readonly(config, false),
                AccountMeta::new(wormhole_bridge, false),
                AccountMeta::new(wormhole_fee_collector, false),
                AccountMeta::new(wormhole_sequence, false),
                AccountMeta::new(shim_message, false),
                AccountMeta::new(payer, true),
                AccountMeta::new_readonly(sysvar::clock::ID, false),
                AccountMeta::new_readonly(sysvar::rent::ID, false),
                AccountMeta::new_readonly(*wormhole_core, false),
                AccountMeta::new_readonly(program::ID, false),
                AccountMeta::new_readonly(*wormhole_post_message_shim_program_id, false),
                AccountMeta::new_readonly(wormhole_post_message_shim_event_authority, false),
                AccountMeta::new_readonly(program::ID, false),
                AccountMeta::new_readonly(spl_token::ID, false),
                AccountMeta::new_readonly(metadata_program_id, false),
            ],
        ))
    }

    #[cfg(feature = "client")]
    pub async fn deploy_token(
        &self,
        data: DeployTokenData,
    ) -> Result<Signature, SolanaBridgeClientError> {
        let payer = self.signer()?.pubkey();
        let instruction = self.build_deploy_token_instruction(data, payer)?;
        self.send_and_confirm_transaction(vec![instruction], &[])
            .await
    }

    /// `token_program_id` and `is_bridged_token` are consensus-critical
    /// inputs: they determine which token account and vault this instruction
    /// moves funds into/out of. Get both from `fetch_token_context`
    /// (requires the `client` feature) or an equally trusted source — a
    /// wrong value builds a valid-looking instruction that targets the
    /// wrong vault or token account.
    #[allow(clippy::too_many_arguments)]
    pub fn build_init_transfer_instruction(
        &self,
        token: Pubkey,
        amount: u128,
        recipient: String,
        fee: u128,
        native_fee: u64,
        message: String,
        token_program_id: Pubkey,
        is_bridged_token: bool,
        payer: Pubkey,
    ) -> Result<Instruction, SolanaBridgeClientError> {
        let program_id = self.program_id()?;
        let wormhole_core = self.wormhole_core()?;

        let (config, _) = Pubkey::find_program_address(&[b"config"], program_id);
        let (authority, _) = Pubkey::find_program_address(&[b"authority"], program_id);
        let (sol_vault, _) = Pubkey::find_program_address(&[b"sol_vault"], program_id);

        if token_program_id != spl_token::ID && token_program_id != spl_token_2022_interface::ID {
            return Err(SolanaBridgeClientError::InvalidArgument(format!(
                "Not a Solana token program: {token_program_id}"
            )));
        }

        let (from_token_account, _) = Pubkey::find_program_address(
            &[payer.as_ref(), token_program_id.as_ref(), token.as_ref()],
            &spl_associated_token_account_interface::program::ID,
        );

        let (wormhole_bridge, wormhole_fee_collector, wormhole_sequence) =
            self.get_wormhole_accounts()?;

        let wormhole_post_message_shim_program_id = self.wormhole_post_message_shim_program_id()?;
        let (wormhole_post_message_shim_event_authority, _) = Pubkey::find_program_address(
            &[b"__event_authority"],
            wormhole_post_message_shim_program_id,
        );
        let (shim_message, _) =
            Pubkey::find_program_address(&[config.as_ref()], wormhole_post_message_shim_program_id);

        let instruction_data = InitTransfer {
            amount,
            recipient,
            fee,
            native_fee,
            message,
        };

        Ok(Instruction::new_with_borsh(
            *program_id,
            &instruction_data,
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
                AccountMeta::new(payer, true),
                AccountMeta::new_readonly(config, false),
                AccountMeta::new(wormhole_bridge, false),
                AccountMeta::new(wormhole_fee_collector, false),
                AccountMeta::new(wormhole_sequence, false),
                AccountMeta::new(shim_message, false),
                AccountMeta::new(payer, true),
                AccountMeta::new_readonly(sysvar::clock::ID, false),
                AccountMeta::new_readonly(sysvar::rent::ID, false),
                AccountMeta::new_readonly(*wormhole_core, false),
                AccountMeta::new_readonly(program::ID, false),
                AccountMeta::new_readonly(*wormhole_post_message_shim_program_id, false),
                AccountMeta::new_readonly(wormhole_post_message_shim_event_authority, false),
                AccountMeta::new_readonly(token_program_id, false),
            ],
        ))
    }

    #[cfg(feature = "client")]
    pub async fn init_transfer(
        &self,
        token: Pubkey,
        amount: u128,
        recipient: String,
        fee: u128,
        native_fee: u64,
        message: String,
    ) -> Result<Signature, SolanaBridgeClientError> {
        let payer = self.signer()?.pubkey();
        let (token_program_id, is_bridged_token) = self.fetch_token_context(token).await?;
        let instruction = self.build_init_transfer_instruction(
            token,
            amount,
            recipient,
            fee,
            native_fee,
            message,
            token_program_id,
            is_bridged_token,
            payer,
        )?;
        self.send_and_confirm_transaction(vec![instruction], &[])
            .await
    }

    #[cfg(feature = "client")]
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

    pub fn build_init_transfer_sol_instruction(
        &self,
        amount: u128,
        recipient: String,
        fee: u128,
        native_fee: u64,
        message: String,
        payer: Pubkey,
    ) -> Result<Instruction, SolanaBridgeClientError> {
        let program_id = self.program_id()?;
        let wormhole_core = self.wormhole_core()?;

        let (config, _) = Pubkey::find_program_address(&[b"config"], program_id);
        let (sol_vault, _) = Pubkey::find_program_address(&[b"sol_vault"], program_id);

        let (wormhole_bridge, wormhole_fee_collector, wormhole_sequence) =
            self.get_wormhole_accounts()?;

        let wormhole_post_message_shim_program_id = self.wormhole_post_message_shim_program_id()?;
        let (wormhole_post_message_shim_event_authority, _) = Pubkey::find_program_address(
            &[b"__event_authority"],
            wormhole_post_message_shim_program_id,
        );
        let (shim_message, _) =
            Pubkey::find_program_address(&[config.as_ref()], wormhole_post_message_shim_program_id);

        let instruction_data = InitTransferSol {
            amount,
            recipient,
            fee,
            native_fee,
            message,
        };

        Ok(Instruction::new_with_borsh(
            *program_id,
            &instruction_data,
            vec![
                AccountMeta::new(sol_vault, false),
                AccountMeta::new_readonly(payer, true),
                AccountMeta::new_readonly(config, false),
                AccountMeta::new(wormhole_bridge, false),
                AccountMeta::new(wormhole_fee_collector, false),
                AccountMeta::new(wormhole_sequence, false),
                AccountMeta::new(shim_message, false),
                AccountMeta::new(payer, true),
                AccountMeta::new_readonly(sysvar::clock::ID, false),
                AccountMeta::new_readonly(sysvar::rent::ID, false),
                AccountMeta::new_readonly(*wormhole_core, false),
                AccountMeta::new_readonly(program::ID, false),
                AccountMeta::new_readonly(*wormhole_post_message_shim_program_id, false),
                AccountMeta::new_readonly(wormhole_post_message_shim_event_authority, false),
            ],
        ))
    }

    #[cfg(feature = "client")]
    pub async fn init_transfer_sol(
        &self,
        amount: u128,
        recipient: String,
        fee: u128,
        native_fee: u64,
        message: String,
    ) -> Result<Signature, SolanaBridgeClientError> {
        let payer = self.signer()?.pubkey();
        let instruction = self.build_init_transfer_sol_instruction(
            amount, recipient, fee, native_fee, message, payer,
        )?;
        self.send_and_confirm_transaction(vec![instruction], &[])
            .await
    }

    /// `token_program_id` and `is_bridged_token` are consensus-critical
    /// inputs: they determine which token account and vault this instruction
    /// releases funds from. Get both from `fetch_token_context` (requires
    /// the `client` feature) or an equally trusted source — a wrong value
    /// builds a valid-looking instruction that targets the wrong vault or
    /// token account.
    pub fn build_finalize_transfer_instruction(
        &self,
        data: FinalizeDepositData,
        solana_token: Pubkey,
        token_program_id: Pubkey,
        is_bridged_token: bool,
        payer: Pubkey,
    ) -> Result<Instruction, SolanaBridgeClientError> {
        let program_id = self.program_id()?;
        let wormhole_core = self.wormhole_core()?;

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

        if token_program_id != spl_token::ID && token_program_id != spl_token_2022_interface::ID {
            return Err(SolanaBridgeClientError::InvalidArgument(format!(
                "Not a Solana token program: {token_program_id}"
            )));
        }

        let (token_account, _) = Pubkey::find_program_address(
            &[
                recipient.as_ref(),
                token_program_id.as_ref(),
                solana_token.as_ref(),
            ],
            &spl_associated_token_account_interface::program::ID,
        );

        let (wormhole_bridge, wormhole_fee_collector, wormhole_sequence) =
            self.get_wormhole_accounts()?;

        let wormhole_post_message_shim_program_id = self.wormhole_post_message_shim_program_id()?;
        let (wormhole_post_message_shim_event_authority, _) = Pubkey::find_program_address(
            &[b"__event_authority"],
            wormhole_post_message_shim_program_id,
        );
        let (shim_message, _) =
            Pubkey::find_program_address(&[config.as_ref()], wormhole_post_message_shim_program_id);

        let instruction_data = FinalizeTransfer {
            payload: FinalizeTransferInstructionPayload {
                destination_nonce: data.payload.destination_nonce,
                transfer_id: data.payload.transfer_id,
                amount: data.payload.amount,
                fee_recipient: data.payload.fee_recipient,
            },
            signature: data.signature,
        };

        let accounts = vec![
            AccountMeta::new(config, false),
            AccountMeta::new(used_nonces, false),
            AccountMeta::new(authority, false),
            AccountMeta::new_readonly(recipient, false),
            AccountMeta::new(solana_token, false),
            if is_bridged_token {
                AccountMeta::new(*program_id, false) // Vault is not present for non-native tokens
            } else {
                let (vault, _) =
                    Pubkey::find_program_address(&[b"vault", solana_token.as_ref()], program_id);
                AccountMeta::new(vault, false)
            },
            AccountMeta::new(token_account, false),
            AccountMeta::new_readonly(config, false),
            AccountMeta::new(wormhole_bridge, false),
            AccountMeta::new(wormhole_fee_collector, false),
            AccountMeta::new(wormhole_sequence, false),
            AccountMeta::new(shim_message, false),
            AccountMeta::new(payer, true),
            AccountMeta::new_readonly(sysvar::clock::ID, false),
            AccountMeta::new_readonly(sysvar::rent::ID, false),
            AccountMeta::new_readonly(*wormhole_core, false),
            AccountMeta::new_readonly(program::ID, false),
            AccountMeta::new_readonly(*wormhole_post_message_shim_program_id, false),
            AccountMeta::new_readonly(wormhole_post_message_shim_event_authority, false),
            AccountMeta::new_readonly(spl_associated_token_account_interface::program::ID, false),
            AccountMeta::new_readonly(program::ID, false),
            AccountMeta::new_readonly(token_program_id, false),
        ];

        Ok(Instruction::new_with_borsh(
            *program_id,
            &instruction_data,
            accounts,
        ))
    }

    #[cfg(feature = "client")]
    pub async fn finalize_transfer(
        &self,
        data: FinalizeDepositData,
        solana_token: Pubkey,
    ) -> Result<Signature, SolanaBridgeClientError> {
        let payer = self.signer()?.pubkey();
        let (token_program_id, is_bridged_token) = self.fetch_token_context(solana_token).await?;
        let instruction = self.build_finalize_transfer_instruction(
            data,
            solana_token,
            token_program_id,
            is_bridged_token,
            payer,
        )?;
        self.send_and_confirm_transaction(vec![instruction], &[])
            .await
    }

    pub fn build_finalize_transfer_sol_instruction(
        &self,
        data: FinalizeDepositData,
        payer: Pubkey,
    ) -> Result<Instruction, SolanaBridgeClientError> {
        let program_id = self.program_id()?;
        let wormhole_core = self.wormhole_core()?;

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

        let wormhole_post_message_shim_program_id = self.wormhole_post_message_shim_program_id()?;
        let (wormhole_post_message_shim_event_authority, _) = Pubkey::find_program_address(
            &[b"__event_authority"],
            wormhole_post_message_shim_program_id,
        );
        let (shim_message, _) =
            Pubkey::find_program_address(&[config.as_ref()], wormhole_post_message_shim_program_id);

        let instruction_data = FinalizeTransferSol {
            payload: FinalizeTransferInstructionPayload {
                destination_nonce: data.payload.destination_nonce,
                transfer_id: data.payload.transfer_id,
                amount: data.payload.amount,
                fee_recipient: data.payload.fee_recipient,
            },
            signature: data.signature,
        };

        Ok(Instruction::new_with_borsh(
            *program_id,
            &instruction_data,
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
                AccountMeta::new(payer, true),
                AccountMeta::new_readonly(sysvar::clock::ID, false),
                AccountMeta::new_readonly(sysvar::rent::ID, false),
                AccountMeta::new_readonly(*wormhole_core, false),
                AccountMeta::new_readonly(program::ID, false),
                AccountMeta::new_readonly(*wormhole_post_message_shim_program_id, false),
                AccountMeta::new_readonly(wormhole_post_message_shim_event_authority, false),
                AccountMeta::new_readonly(program::ID, false),
            ],
        ))
    }

    #[cfg(feature = "client")]
    pub async fn finalize_transfer_sol(
        &self,
        data: FinalizeDepositData,
    ) -> Result<Signature, SolanaBridgeClientError> {
        let payer = self.signer()?.pubkey();
        let instruction = self.build_finalize_transfer_sol_instruction(data, payer)?;
        self.send_and_confirm_transaction(vec![instruction], &[])
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

    /// Assembles the instructions into an unsigned transaction with a freshly
    /// fetched blockhash. The transaction carries placeholder (all-zero)
    /// signatures and must be signed and submitted within the blockhash
    /// validity window (~60-90 seconds).
    #[cfg(feature = "client")]
    pub async fn build_unsigned_transaction(
        &self,
        instructions: Vec<Instruction>,
        payer: Pubkey,
    ) -> Result<Transaction, SolanaBridgeClientError> {
        let client = self.client()?;
        let recent_blockhash = client.get_latest_blockhash().await?;
        Ok(self.build_unsigned_transaction_with_blockhash(instructions, payer, recent_blockhash))
    }

    /// Assembles an unsigned transaction from a caller-supplied blockhash —
    /// fully offline, no RPC. See `build_unsigned_transaction` for the
    /// RPC-fetching variant.
    pub fn build_unsigned_transaction_with_blockhash(
        &self,
        instructions: Vec<Instruction>,
        payer: Pubkey,
        recent_blockhash: solana_hash::Hash,
    ) -> Transaction {
        Transaction::new_unsigned(solana_message::Message::new_with_blockhash(
            &instructions,
            Some(&payer),
            &recent_blockhash,
        ))
    }

    #[cfg(feature = "client")]
    async fn send_and_confirm_transaction(
        &self,
        instructions: Vec<Instruction>,
        extra_signers: &[&Keypair],
    ) -> Result<Signature, SolanaBridgeClientError> {
        match self.signer()? {
            SvmSigner::DryRun(payer) => {
                if !extra_signers.is_empty() {
                    return Err(SolanaBridgeClientError::ConfigError(
                        "Operation requires additional signers and cannot be dry-run".to_string(),
                    ));
                }
                let payer = *payer;
                let transaction = self.build_unsigned_transaction(instructions, payer).await?;
                print_unsigned_transaction(&transaction)?;
                Ok(Signature::default())
            }
            SvmSigner::Keypair(keypair) => {
                let client = self.client()?;
                let recent_blockhash = client.get_latest_blockhash().await?;

                let mut signers: Vec<&Keypair> = vec![keypair];
                signers.extend_from_slice(extra_signers);

                let transaction = Transaction::new_signed_with_payer(
                    &instructions,
                    Some(&keypair.pubkey()),
                    &signers,
                    recent_blockhash,
                );

                let signature = client.send_and_confirm_transaction(&transaction).await?;
                Ok(signature)
            }
        }
    }

    #[cfg(feature = "client")]
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

    #[cfg(feature = "client")]
    async fn get_mint_owner(&self, token: Pubkey) -> Result<Pubkey, SolanaBridgeClientError> {
        let client = self.client()?;

        let mint_account = client.get_account(&token).await?;

        Ok(mint_account.owner)
    }

    /// Resolves the on-chain token program that owns `token`'s mint account.
    #[cfg(feature = "client")]
    pub async fn fetch_token_program_id(
        &self,
        token: Pubkey,
    ) -> Result<Pubkey, SolanaBridgeClientError> {
        let token_program_id = self.get_mint_owner(token).await?;
        // Same allowlist as the sync builder cores, but with the legacy
        // "Not a Solana token" message — CLI output parity. Do not dedup
        // into the cores' check without preserving both messages.
        if token_program_id != spl_token::ID && token_program_id != spl_token_2022_interface::ID {
            return Err(SolanaBridgeClientError::InvalidArgument(format!(
                "Not a Solana token: {token}"
            )));
        }
        Ok(token_program_id)
    }

    /// Resolves the RPC-derived inputs the init/finalize builders need:
    /// the token program id and whether the mint is a bridged (wrapped) token.
    #[cfg(feature = "client")]
    pub async fn fetch_token_context(
        &self,
        token: Pubkey,
    ) -> Result<(Pubkey, bool), SolanaBridgeClientError> {
        let token_program_id = self.fetch_token_program_id(token).await?;
        let program_id = self.program_id()?;
        let (authority, _) = Pubkey::find_program_address(&[b"authority"], program_id);
        let is_bridged_token = match self.get_token_owner(token).await? {
            COption::Some(owner) => owner == authority,
            COption::None => false,
        };
        Ok((token_program_id, is_bridged_token))
    }

    pub fn get_token_vault(&self, token: Pubkey) -> Result<Pubkey, SolanaBridgeClientError> {
        let program_id = self.program_id()?;
        let (vault, _) = if token == Pubkey::default() {
            Pubkey::find_program_address(&[b"sol_vault"], program_id)
        } else {
            Pubkey::find_program_address(&[b"vault", token.as_ref()], program_id)
        };
        Ok(vault)
    }

    #[cfg(feature = "client")]
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

    pub fn signer(&self) -> Result<&SvmSigner, SolanaBridgeClientError> {
        self.signer
            .as_ref()
            .ok_or(SolanaBridgeClientError::ConfigError(
                "Signer not initialized".to_string(),
            ))
    }

    pub fn keypair(&self) -> Result<&Keypair, SolanaBridgeClientError> {
        self.signer()?.keypair()
    }
}

/// Encodes a transaction as base64 bincode — the wire format `sendTransaction`
/// accepts once the placeholder signatures are replaced with real ones.
pub fn serialize_unsigned_transaction(
    transaction: &Transaction,
) -> Result<String, SolanaBridgeClientError> {
    let bytes = bincode::serialize(transaction)
        .map_err(|e| SolanaBridgeClientError::SerializationError(e.to_string()))?;
    Ok(base64::engine::general_purpose::STANDARD.encode(bytes))
}

#[cfg(feature = "client")]
fn print_unsigned_transaction(transaction: &Transaction) -> Result<(), SolanaBridgeClientError> {
    let serialized = serialize_unsigned_transaction(transaction)?;
    let message = &transaction.message;

    println!();
    println!("DRY RUN — transaction was NOT signed or broadcast");
    println!(
        "fee payer:        {}",
        message
            .account_keys
            .first()
            .map_or_else(String::new, ToString::to_string)
    );
    println!(
        "recent blockhash: {} (expires in ~60-90 seconds)",
        message.recent_blockhash
    );
    println!("required signers:");
    for key in message
        .account_keys
        .iter()
        .take(usize::from(message.header.num_required_signatures))
    {
        println!("  {key}");
    }
    for (index, instruction) in message.instructions.iter().enumerate() {
        let program_id = message
            .account_keys
            .get(usize::from(instruction.program_id_index))
            .map_or_else(String::new, ToString::to_string);
        let name = instructions::instruction_name_from_data(&instruction.data).unwrap_or("unknown");
        println!(
            "instruction #{index}: {name} (program {program_id}, {} accounts, {} data bytes)",
            instruction.accounts.len(),
            instruction.data.len(),
        );
    }
    println!("unsigned transaction (base64-encoded bincode):");
    println!("{serialized}");
    println!("Sign it offline and submit within the blockhash validity window.");
    println!("Ignore any signature/confirmation logged below.");
    println!();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn svm_signer_keypair_mode() {
        let keypair = Keypair::new();
        let expected = keypair.pubkey();
        let signer = SvmSigner::Keypair(keypair);
        assert_eq!(signer.pubkey(), expected);
        assert!(!signer.is_dry_run());
        assert!(signer.keypair().is_ok());
    }

    #[test]
    fn svm_signer_dry_run_mode() {
        let pubkey = Pubkey::new_unique();
        let signer = SvmSigner::DryRun(pubkey);
        assert_eq!(signer.pubkey(), pubkey);
        assert!(signer.is_dry_run());
        assert!(signer.keypair().is_err());
    }

    #[test]
    fn unsigned_transaction_round_trips_through_base64_bincode() {
        let payer = Pubkey::new_unique();
        let instruction = Instruction {
            program_id: Pubkey::new_unique(),
            accounts: vec![AccountMeta::new(payer, true)],
            data: vec![1, 2, 3],
        };
        let transaction = Transaction::new_unsigned(solana_message::Message::new_with_blockhash(
            &[instruction],
            Some(&payer),
            &solana_hash::Hash::default(),
        ));

        let encoded = serialize_unsigned_transaction(&transaction).unwrap();
        let decoded: Transaction = bincode::deserialize(
            &base64::engine::general_purpose::STANDARD
                .decode(encoded)
                .unwrap(),
        )
        .unwrap();

        assert_eq!(decoded.message, transaction.message);
        assert_eq!(
            decoded.signatures.len(),
            usize::from(transaction.message.header.num_required_signatures)
        );
        assert!(decoded
            .signatures
            .iter()
            .all(|s| *s == Signature::default()));
    }

    #[test]
    fn instruction_names_resolve_from_discriminators() {
        assert_eq!(
            instructions::instruction_name_from_data(&INIT_TRANSFER_DISCRIMINATOR),
            Some("init_transfer")
        );
        assert_eq!(
            instructions::instruction_name_from_data(&INIT_TRANSFER_SOL_DISCRIMINATOR),
            Some("init_transfer_sol")
        );
        assert_eq!(instructions::instruction_name_from_data(&[0u8; 8]), None);
        assert_eq!(instructions::instruction_name_from_data(&[1, 2]), None);
    }

    fn test_client() -> SolanaBridgeClient {
        let builder = SolanaBridgeClientBuilder::default();
        #[cfg(feature = "client")]
        let builder = builder.client(None);
        builder
            .program_id(Some(
                "dahPEoZGXfyV58JqqH85okdHmpN8U2q8owgPUXSCPxe"
                    .parse()
                    .unwrap(),
            ))
            .wormhole_core(Some(
                "worm2ZoG2kUd4vFXhvjh93UUH596ayRfgQ2MgjNMTth"
                    .parse()
                    .unwrap(),
            ))
            .wormhole_post_message_shim_program_id(Some(Pubkey::new_unique()))
            .signer(None)
            .build()
            .unwrap()
    }

    #[test]
    fn init_transfer_sol_builder_encodes_discriminator_and_payer() {
        let client = test_client();
        let payer = Pubkey::new_unique();

        let instruction = client
            .build_init_transfer_sol_instruction(
                1_000_000,
                "eth:0x0000000000000000000000000000000000000001".to_string(),
                0,
                10,
                String::new(),
                payer,
            )
            .unwrap();

        assert_eq!(instruction.program_id, *client.program_id().unwrap());
        assert_eq!(instruction.data[..8], INIT_TRANSFER_SOL_DISCRIMINATOR);
        assert_eq!(instruction.accounts.len(), 14);
        // payer appears as the readonly signer (index 1) and the writable payer (index 7)
        assert_eq!(instruction.accounts[1].pubkey, payer);
        assert!(instruction.accounts[1].is_signer && !instruction.accounts[1].is_writable);
        assert_eq!(instruction.accounts[7].pubkey, payer);
        assert!(instruction.accounts[7].is_signer && instruction.accounts[7].is_writable);
        // no other account is marked signer
        let signer_count = instruction.accounts.iter().filter(|a| a.is_signer).count();
        assert_eq!(signer_count, 2);
    }

    #[test]
    fn set_admin_builder_encodes_admin_and_signer() {
        let client = test_client();
        let payer = Pubkey::new_unique();
        let admin = Pubkey::new_unique();

        let instruction = client.build_set_admin_instruction(admin, payer).unwrap();

        assert_eq!(
            instructions::instruction_name_from_data(&instruction.data),
            Some("set_admin")
        );
        assert_eq!(instruction.data.len(), 8 + 32);
        assert_eq!(instruction.data[8..], admin.to_bytes());
        assert_eq!(instruction.accounts.len(), 2);
        assert_eq!(instruction.accounts[1].pubkey, payer);
        assert!(instruction.accounts[1].is_signer);
    }

    #[test]
    fn deploy_token_builder_resolves_name_and_needs_no_rpc() {
        let client = test_client();
        let payer = Pubkey::new_unique();

        let instruction = client
            .build_deploy_token_instruction(
                DeployTokenData {
                    metadata: MetadataPayload {
                        token: "wrap.testnet".to_string(),
                        name: "Wrapped NEAR".to_string(),
                        symbol: "wNEAR".to_string(),
                        decimals: 24,
                    },
                    signature: [1u8; 65],
                },
                payer,
            )
            .unwrap();

        assert_eq!(
            instructions::instruction_name_from_data(&instruction.data),
            Some("deploy_token")
        );
        assert_eq!(instruction.accounts.len(), 18);
        assert_eq!(instruction.accounts[8].pubkey, payer);
        assert!(instruction.accounts[8].is_signer);
    }

    #[test]
    fn finalize_transfer_sol_builder_encodes_recipient_account() {
        let client = test_client();
        let payer = Pubkey::new_unique();
        let recipient = Pubkey::new_unique();

        let instruction = client
            .build_finalize_transfer_sol_instruction(
                FinalizeDepositData {
                    payload: DepositPayload {
                        destination_nonce: 7,
                        transfer_id: TransferId {
                            origin_chain: 1,
                            origin_nonce: 42,
                        },
                        amount: 1_000,
                        recipient,
                        fee_recipient: None,
                    },
                    signature: [2u8; 65],
                },
                payer,
            )
            .unwrap();

        assert_eq!(
            instructions::instruction_name_from_data(&instruction.data),
            Some("finalize_transfer_sol")
        );
        assert_eq!(instruction.accounts[3].pubkey, recipient);
        assert_eq!(instruction.accounts[10].pubkey, payer);
        assert!(instruction.accounts[10].is_signer);
    }

    #[test]
    fn init_transfer_builder_vault_branches() {
        let client = test_client();
        let payer = Pubkey::new_unique();
        let token = Pubkey::new_unique();
        let program_id = *client.program_id().unwrap();

        let bridged = client
            .build_init_transfer_instruction(
                token,
                10,
                "near:alice.near".to_string(),
                0,
                5,
                String::new(),
                spl_token::ID,
                true,
                payer,
            )
            .unwrap();
        // bridged token: vault slot (index 3) holds the program id placeholder
        assert_eq!(bridged.accounts[3].pubkey, program_id);

        let native = client
            .build_init_transfer_instruction(
                token,
                10,
                "near:alice.near".to_string(),
                0,
                5,
                String::new(),
                spl_token_2022_interface::ID,
                false,
                payer,
            )
            .unwrap();
        let (vault, _) = Pubkey::find_program_address(&[b"vault", token.as_ref()], &program_id);
        assert_eq!(native.accounts[3].pubkey, vault);
        // ATA is derived from the payer and the supplied token program
        let (ata, _) = Pubkey::find_program_address(
            &[
                payer.as_ref(),
                spl_token_2022_interface::ID.as_ref(),
                token.as_ref(),
            ],
            &spl_associated_token_account_interface::program::ID,
        );
        assert_eq!(native.accounts[2].pubkey, ata);
        assert_eq!(
            instructions::instruction_name_from_data(&native.data),
            Some("init_transfer")
        );

        // invalid token program is rejected offline
        assert!(client
            .build_init_transfer_instruction(
                token,
                10,
                "near:alice.near".to_string(),
                0,
                5,
                String::new(),
                Pubkey::new_unique(),
                false,
                payer,
            )
            .is_err());
    }

    #[test]
    fn finalize_transfer_builder_vault_branches() {
        let client = test_client();
        let payer = Pubkey::new_unique();
        let token = Pubkey::new_unique();
        let program_id = *client.program_id().unwrap();
        let data = || FinalizeDepositData {
            payload: DepositPayload {
                destination_nonce: 1,
                transfer_id: TransferId {
                    origin_chain: 1,
                    origin_nonce: 2,
                },
                amount: 3,
                recipient: Pubkey::new_unique(),
                fee_recipient: None,
            },
            signature: [3u8; 65],
        };

        let bridged = client
            .build_finalize_transfer_instruction(data(), token, spl_token::ID, true, payer)
            .unwrap();
        assert_eq!(bridged.accounts[5].pubkey, program_id);

        let native = client
            .build_finalize_transfer_instruction(data(), token, spl_token::ID, false, payer)
            .unwrap();
        let (vault, _) = Pubkey::find_program_address(&[b"vault", token.as_ref()], &program_id);
        assert_eq!(native.accounts[5].pubkey, vault);
        assert_eq!(
            instructions::instruction_name_from_data(&native.data),
            Some("finalize_transfer")
        );
    }

    #[test]
    fn log_metadata_and_admin_builders_encode() {
        let client = test_client();
        let payer = Pubkey::new_unique();
        let token = Pubkey::new_unique();

        let log = client
            .build_log_metadata_instruction(token, spl_token::ID, payer)
            .unwrap();
        assert_eq!(
            instructions::instruction_name_from_data(&log.data),
            Some("log_metadata")
        );
        assert_eq!(log.accounts[9].pubkey, payer);
        assert!(log.accounts[9].is_signer);

        let pause = client.build_pause_instruction(payer).unwrap();
        assert_eq!(
            instructions::instruction_name_from_data(&pause.data),
            Some("pause")
        );
        assert_eq!(pause.accounts[1].pubkey, payer);

        let update = client
            .build_update_metadata_instruction(token, Some("n".into()), None, None, payer)
            .unwrap();
        assert_eq!(
            instructions::instruction_name_from_data(&update.data),
            Some("update_metadata")
        );
        assert_eq!(update.accounts[6].pubkey, payer);
        assert!(update.accounts[6].is_signer);
    }
}
