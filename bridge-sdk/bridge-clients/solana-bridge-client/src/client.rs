use base64::Engine;
use bitvec::array::BitArray;
use borsh::{BorshDeserialize, BorshSerialize};
use solana_commitment_config::CommitmentConfig;
use solana_instruction::{AccountMeta, Instruction};
use solana_keypair::Keypair;
use solana_program_option::COption;
use solana_program_pack::Pack;
use solana_pubkey::Pubkey;
use solana_rpc_client::nonblocking::rpc_client::RpcClient;
use solana_rpc_client_api::config::RpcTransactionConfig;
use solana_sdk_ids::sysvar;
use solana_signature::Signature;
use solana_signer::Signer;
use solana_system_interface::program;
use solana_transaction::Transaction;
use solana_transaction_status_client_types::{
    option_serializer::OptionSerializer, EncodedTransaction, UiMessage, UiTransactionEncoding,
};
use spl_token::state::Mint;

use crate::{
    error::SolanaBridgeClientError, instructions::Initialize, DeployTokenData, FinalizeDepositData,
    SolanaBridgeClient, SvmSigner, Transfer, DISCRIMINATOR_LEN, INIT_TRANSFER_DISCRIMINATOR,
    INIT_TRANSFER_SOL_DISCRIMINATOR, USED_NONCES_PER_ACCOUNT,
};

const GET_VERSION_DISCRIMINATOR: [u8; 8] = [168, 85, 244, 45, 81, 56, 130, 50];

const INIT_TRANSFER_SENDER_INDEX: usize = 5;
const INIT_TRANSFER_TOKEN_INDEX: usize = 1;
const INIT_TRANSFER_EMITTER_INDEX: usize = 6;
const INIT_TRANSFER_SOL_SENDER_INDEX: usize = 1;
const INIT_TRANSFER_SOL_EMITTER_INDEX: usize = 2;

#[allow(
    clippy::cast_possible_truncation,
    clippy::as_conversions,
    clippy::manual_div_ceil
)]
const BIT_BYTES: usize = (USED_NONCES_PER_ACCOUNT as usize + 7) / 8;

#[derive(BorshSerialize, BorshDeserialize, Debug)]
struct InitTransferPayload {
    pub amount: u128,
    pub recipient: String,
    pub fee: u128,
    pub native_fee: u64,
    pub message: String,
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

        self.send_and_confirm_transaction(vec![instruction], &[&wormhole_message, &program_keypair])
            .await
    }

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

    pub async fn set_admin(&self, admin: Pubkey) -> Result<Signature, SolanaBridgeClientError> {
        let payer = self.signer()?.pubkey();
        let instruction = self.build_set_admin_instruction(admin, payer)?;
        self.send_and_confirm_transaction(vec![instruction], &[])
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
        let payer = self.signer()?.pubkey();
        let instruction =
            self.build_update_metadata_instruction(token, name, symbol, uri, payer)?;
        self.send_and_confirm_transaction(vec![instruction], &[])
            .await
    }

    pub async fn pause(&self) -> Result<Signature, SolanaBridgeClientError> {
        let payer = self.signer()?.pubkey();
        let instruction = self.build_pause_instruction(payer)?;
        self.send_and_confirm_transaction(vec![instruction], &[])
            .await
    }

    pub async fn log_metadata(&self, token: Pubkey) -> Result<Signature, SolanaBridgeClientError> {
        let payer = self.signer()?.pubkey();
        let token_program_id = self.fetch_token_program_id(token).await?;
        let instruction = self.build_log_metadata_instruction(token, token_program_id, payer)?;
        self.send_and_confirm_transaction(vec![instruction], &[])
            .await
    }

    pub async fn deploy_token(
        &self,
        data: DeployTokenData,
    ) -> Result<Signature, SolanaBridgeClientError> {
        let payer = self.signer()?.pubkey();
        let instruction = self.build_deploy_token_instruction(data, payer)?;
        self.send_and_confirm_transaction(vec![instruction], &[])
            .await
    }

    pub async fn init_transfer(
        &self,
        token: Pubkey,
        amount: u128,
        recipient: String,
        fee: u128,
        native_fee: u64,
        message: String,
    ) -> Result<Signature, SolanaBridgeClientError> {
        let signer_pubkey = self.signer()?.pubkey();
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
            signer_pubkey,
            signer_pubkey,
        )?;
        self.send_and_confirm_transaction(vec![instruction], &[])
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
        let signer_pubkey = self.signer()?.pubkey();
        let instruction = self.build_init_transfer_sol_instruction(
            amount,
            recipient,
            fee,
            native_fee,
            message,
            signer_pubkey,
            signer_pubkey,
        )?;
        self.send_and_confirm_transaction(vec![instruction], &[])
            .await
    }

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

    pub async fn finalize_transfer_sol(
        &self,
        data: FinalizeDepositData,
    ) -> Result<Signature, SolanaBridgeClientError> {
        let payer = self.signer()?.pubkey();
        let instruction = self.build_finalize_transfer_sol_instruction(data, payer)?;
        self.send_and_confirm_transaction(vec![instruction], &[])
            .await
    }

    /// Assembles the instructions into an unsigned transaction with a freshly
    /// fetched blockhash. The transaction carries placeholder (all-zero)
    /// signatures and must be signed and submitted within the blockhash
    /// validity window (~60-90 seconds).
    pub async fn build_unsigned_transaction(
        &self,
        instructions: Vec<Instruction>,
        payer: Pubkey,
    ) -> Result<Transaction, SolanaBridgeClientError> {
        let client = self.client()?;
        let recent_blockhash = client.get_latest_blockhash().await?;
        Ok(self.build_unsigned_transaction_with_blockhash(instructions, payer, recent_blockhash))
    }

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

    /// Resolves the on-chain token program that owns `token`'s mint account.
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

    pub fn client(&self) -> Result<&RpcClient, SolanaBridgeClientError> {
        self.client
            .as_ref()
            .ok_or(SolanaBridgeClientError::ConfigError(
                "Client not initialized".to_string(),
            ))
    }
}

impl From<solana_rpc_client_api::client_error::Error> for SolanaBridgeClientError {
    fn from(err: solana_rpc_client_api::client_error::Error) -> Self {
        SolanaBridgeClientError::RpcError(Box::new(err))
    }
}

fn print_unsigned_transaction(transaction: &Transaction) -> Result<(), SolanaBridgeClientError> {
    let serialized = crate::serialize_unsigned_transaction(transaction)?;
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
        let name =
            crate::instructions::instruction_name_from_data(&instruction.data).unwrap_or("unknown");
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
