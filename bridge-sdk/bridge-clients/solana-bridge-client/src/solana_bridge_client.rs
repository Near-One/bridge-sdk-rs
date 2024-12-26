use borsh::{BorshDeserialize, BorshSerialize};
use derive_builder::Builder;
use solana_client::nonblocking::rpc_client::RpcClient;
use solana_sdk::{
    instruction::{AccountMeta, Instruction},
    program_option::COption,
    program_pack::Pack,
    pubkey::Pubkey,
    signature::{Keypair, Signature},
    signer::Signer,
    system_program, sysvar,
    transaction::Transaction,
};
use spl_token::state::Mint;

use crate::{error::SolanaClientError, instructions::*};

mod error;
mod instructions;

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
    keypair: Option<Keypair>,
}

impl SolanaBridgeClient {
    pub async fn initialize(
        &self,
        derived_near_bridge_address: [u8; 64],
        program_keypair: Keypair,
    ) -> Result<Signature, SolanaClientError> {
        let program_id = self.program_id()?;
        let wormhole_core = self.wormhole_core()?;
        let keypair = self.keypair()?;

        let (config, _) = Pubkey::find_program_address(&[b"config"], program_id);
        let (authority, _) = Pubkey::find_program_address(&[b"authority"], program_id);
        let (sol_vault, _) = Pubkey::find_program_address(&[b"sol_vault"], program_id);

        let (wormhole_bridge, wormhole_fee_collector, wormhole_sequence) =
            self.get_wormhole_accounts().await?;
        let wormhole_message = Keypair::new();

        let instruction_data = Initialize {
            admin: keypair.pubkey(),
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
                AccountMeta::new_readonly(system_program::ID, false),
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

    pub async fn log_metadata(&self, token: Pubkey) -> Result<Signature, SolanaClientError> {
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

        let (wormhole_bridge, wormhole_fee_collector, wormhole_sequence) =
            self.get_wormhole_accounts().await?;
        let wormhole_message = Keypair::new();

        let instruction_data = LogMetadata {
            override_name: String::new(),
            override_symbol: String::new(),
        };

        let instruction = Instruction::new_with_borsh(
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
                AccountMeta::new(wormhole_message.pubkey(), true),
                AccountMeta::new(keypair.pubkey(), true),
                AccountMeta::new_readonly(sysvar::clock::ID, false),
                AccountMeta::new_readonly(sysvar::rent::ID, false),
                AccountMeta::new_readonly(*wormhole_core, false),
                AccountMeta::new_readonly(system_program::ID, false),
                AccountMeta::new_readonly(system_program::ID, false),
                AccountMeta::new_readonly(spl_token::ID, false),
                AccountMeta::new_readonly(spl_associated_token_account::ID, false),
            ],
        );

        self.send_and_confirm_transaction(vec![instruction], &[keypair, &wormhole_message])
            .await
    }

    pub async fn deploy_token(
        &self,
        data: DeployTokenData,
    ) -> Result<Signature, SolanaClientError> {
        let program_id = self.program_id()?;
        let wormhole_core = self.wormhole_core()?;
        let keypair = self.keypair()?;

        let (config, _) = Pubkey::find_program_address(&[b"config"], program_id);
        let (authority, _) = Pubkey::find_program_address(&[b"authority"], program_id);
        let (mint, _) = Pubkey::find_program_address(
            &[b"wrapped_mint", data.metadata.token.as_bytes()],
            program_id,
        );

        let metadata_program_id: Pubkey = mpl_token_metadata::ID.to_bytes().into();
        let (metadata, _) = Pubkey::find_program_address(
            &[b"metadata", metadata_program_id.as_ref(), mint.as_ref()],
            &metadata_program_id,
        );

        let (wormhole_bridge, wormhole_fee_collector, wormhole_sequence) =
            self.get_wormhole_accounts().await?;
        let wormhole_message = Keypair::new();

        let instruction_data = DeployToken { data };

        let instruction = Instruction::new_with_borsh(
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
                AccountMeta::new(wormhole_message.pubkey(), true),
                AccountMeta::new(keypair.pubkey(), true),
                AccountMeta::new_readonly(sysvar::clock::ID, false),
                AccountMeta::new_readonly(sysvar::rent::ID, false),
                AccountMeta::new_readonly(*wormhole_core, false),
                AccountMeta::new_readonly(system_program::ID, false),
                AccountMeta::new_readonly(system_program::ID, false),
                AccountMeta::new_readonly(spl_token::ID, false),
                AccountMeta::new_readonly(metadata_program_id, false),
            ],
        );

        self.send_and_confirm_transaction(vec![instruction], &[keypair, &wormhole_message])
            .await
    }

    pub async fn init_transfer(
        &self,
        token: Pubkey,
        amount: u128,
        recipient: String,
    ) -> Result<Signature, SolanaClientError> {
        let program_id = self.program_id()?;
        let wormhole_core = self.wormhole_core()?;
        let keypair = self.keypair()?;

        let (config, _) = Pubkey::find_program_address(&[b"config"], program_id);
        let (authority, _) = Pubkey::find_program_address(&[b"authority"], program_id);
        let (sol_vault, _) = Pubkey::find_program_address(&[b"sol_vault"], program_id);

        let (from_token_account, _) = Pubkey::find_program_address(
            &[
                keypair.pubkey().as_ref(),
                spl_token::ID.as_ref(),
                token.as_ref(),
            ],
            &spl_associated_token_account::ID,
        );

        let (wormhole_bridge, wormhole_fee_collector, wormhole_sequence) =
            self.get_wormhole_accounts().await?;
        let wormhole_message = Keypair::new();

        let is_bridged_token = match self.get_token_owner(token).await? {
            COption::Some(owner) => owner == authority,
            COption::None => false,
        };

        // TODO: Proved fee&native fee through the arguments
        let instruction_data = InitTransfer {
            amount,
            recipient,
            fee: 20,
            native_fee: 10,
        };

        let instruction = Instruction::new_with_borsh(
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
                AccountMeta::new_readonly(system_program::ID, false),
                AccountMeta::new_readonly(spl_token::ID, false),
            ],
        );

        self.send_and_confirm_transaction(vec![instruction], &[keypair, &wormhole_message])
            .await
    }

    pub async fn init_transfer_sol(
        &self,
        amount: u128,
        recipient: String,
    ) -> Result<Signature, SolanaClientError> {
        let program_id = self.program_id()?;
        let wormhole_core = self.wormhole_core()?;
        let keypair = self.keypair()?;

        let (config, _) = Pubkey::find_program_address(&[b"config"], program_id);
        let (authority, _) = Pubkey::find_program_address(&[b"authority"], program_id);
        let (sol_vault, _) = Pubkey::find_program_address(&[b"sol_vault"], program_id);

        let (wormhole_bridge, wormhole_fee_collector, wormhole_sequence) =
            self.get_wormhole_accounts().await?;

        let wormhole_message = Keypair::new();

        let instruction_data = InitTransferSol {
            amount,
            recipient,
            fee: 0,
            native_fee: 10,
        };

        let instruction = Instruction::new_with_borsh(
            *program_id,
            &instruction_data,
            vec![
                AccountMeta::new_readonly(authority, false),
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
                AccountMeta::new_readonly(system_program::ID, false),
            ],
        );

        self.send_and_confirm_transaction(vec![instruction], &[keypair, &wormhole_message])
            .await
    }

    pub async fn finalize_transfer(
        &self,
        data: FinalizeDepositData,
        solana_token: Pubkey,
    ) -> Result<Signature, SolanaClientError> {
        let program_id = self.program_id()?;
        let wormhole_core = self.wormhole_core()?;
        let keypair = self.keypair()?;

        let (config, _) = Pubkey::find_program_address(&[b"config"], program_id);

        const USED_NONCES_PER_ACCOUNT: u64 = 1024;
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
        let (token_account, _) = Pubkey::find_program_address(
            &[
                recipient.as_ref(),
                spl_token::ID.as_ref(),
                solana_token.as_ref(),
            ],
            &spl_associated_token_account::ID,
        );

        let (wormhole_bridge, wormhole_fee_collector, wormhole_sequence) =
            self.get_wormhole_accounts().await?;
        let wormhole_message = Keypair::new();

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

        let instruction = Instruction::new_with_borsh(
            *program_id,
            &instruction_data,
            vec![
                AccountMeta::new(config, false),
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
                AccountMeta::new_readonly(system_program::ID, false),
                AccountMeta::new_readonly(spl_associated_token_account::ID, false),
                AccountMeta::new_readonly(system_program::ID, false),
                AccountMeta::new_readonly(spl_token::ID, false),
            ],
        );

        self.send_and_confirm_transaction(vec![instruction], &[keypair, &wormhole_message])
            .await
    }

    pub async fn finalize_transfer_sol(
        &self,
        data: FinalizeDepositData,
    ) -> Result<Signature, SolanaClientError> {
        let program_id = self.program_id()?;
        let wormhole_core = self.wormhole_core()?;
        let keypair = self.keypair()?;

        let (config, _) = Pubkey::find_program_address(&[b"config"], program_id);
        let (sol_vault, _) = Pubkey::find_program_address(&[b"sol_vault"], program_id);

        const USED_NONCES_PER_ACCOUNT: u64 = 1024;
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
            self.get_wormhole_accounts().await?;
        let wormhole_message = Keypair::new();

        let instruction_data = FinalizeTransferSol {
            payload: FinalizeTransferInstructionPayload {
                destination_nonce: data.payload.destination_nonce,
                transfer_id: data.payload.transfer_id,
                amount: data.payload.amount,
                fee_recipient: data.payload.fee_recipient,
            },
            signature: data.signature,
        };

        let instruction = Instruction::new_with_borsh(
            *program_id,
            &instruction_data,
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
                AccountMeta::new_readonly(system_program::ID, false),
                AccountMeta::new_readonly(system_program::ID, false),
            ],
        );

        self.send_and_confirm_transaction(vec![instruction], &[keypair, &wormhole_message])
            .await
    }

    async fn get_wormhole_accounts(&self) -> Result<(Pubkey, Pubkey, Pubkey), SolanaClientError> {
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
    ) -> Result<Signature, SolanaClientError> {
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

    async fn get_token_owner(&self, token: Pubkey) -> Result<COption<Pubkey>, SolanaClientError> {
        let client = self.client()?;

        let mint_account = client.get_account(&token).await?;

        let mint_data = Mint::unpack(&mint_account.data)
            .map_err(|e| SolanaClientError::InvalidAccountData(e.to_string()))?;

        Ok(mint_data.mint_authority)
    }

    pub fn client(&self) -> Result<&RpcClient, SolanaClientError> {
        self.client.as_ref().ok_or(SolanaClientError::ConfigError(
            "Client not initialized".to_string(),
        ))
    }

    pub fn program_id(&self) -> Result<&Pubkey, SolanaClientError> {
        self.program_id
            .as_ref()
            .ok_or(SolanaClientError::ConfigError(
                "Program ID not initialized".to_string(),
            ))
    }

    pub fn wormhole_core(&self) -> Result<&Pubkey, SolanaClientError> {
        self.wormhole_core
            .as_ref()
            .ok_or(SolanaClientError::ConfigError(
                "Wormhole Core not initialized".to_string(),
            ))
    }

    pub fn keypair(&self) -> Result<&Keypair, SolanaClientError> {
        self.keypair.as_ref().ok_or(SolanaClientError::ConfigError(
            "Keypair not initialized".to_string(),
        ))
    }
}
