use crate::{DeployTokenData, TransferId};
use borsh::BorshSerialize;
use sha2::{Digest, Sha256};
use solana_sdk::pubkey::Pubkey;

fn get_instruction_identifier(instruction_name: &str) -> [u8; 8] {
    let mut identifier = Sha256::new();
    identifier.update(instruction_name.as_bytes());
    identifier.finalize()[..8].try_into().unwrap()
}

pub struct Initialize {
    pub admin: Pubkey,
    pub derived_near_bridge_address: [u8; 64],
}

impl BorshSerialize for Initialize {
    fn serialize<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        writer.write_all(&get_instruction_identifier("global:initialize"))?;
        writer.write_all(&self.admin.to_bytes())?;
        writer.write_all(&self.derived_near_bridge_address)?;
        Ok(())
    }
}

pub struct DeployToken {
    pub data: DeployTokenData,
}

impl BorshSerialize for DeployToken {
    fn serialize<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        writer.write_all(&get_instruction_identifier("global:deploy_token"))?;
        self.data.serialize(writer)?;
        Ok(())
    }
}

#[derive(BorshSerialize)]
pub struct FinalizeTransferInstructionPayload {
    pub destination_nonce: u64,
    pub transfer_id: TransferId,
    pub amount: u128,
    pub fee_recipient: Option<String>,
}

pub struct FinalizeTransfer {
    pub payload: FinalizeTransferInstructionPayload,
    pub signature: [u8; 65],
}

impl BorshSerialize for FinalizeTransfer {
    fn serialize<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        writer.write_all(&get_instruction_identifier("global:finalize_transfer"))?;
        self.payload.serialize(writer)?;
        writer.write_all(&self.signature)?;
        Ok(())
    }
}

pub struct FinalizeTransferSol {
    pub payload: FinalizeTransferInstructionPayload,
    pub signature: [u8; 65],
}

impl BorshSerialize for FinalizeTransferSol {
    fn serialize<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        writer.write_all(&get_instruction_identifier("global:finalize_transfer_sol"))?;
        self.payload.serialize(writer)?;
        writer.write_all(&self.signature)?;
        Ok(())
    }
}

pub struct LogMetadata {
    pub override_name: String,
    pub override_symbol: String,
}

impl BorshSerialize for LogMetadata {
    fn serialize<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        writer.write_all(&get_instruction_identifier("global:log_metadata"))?;
        self.override_name.serialize(writer)?;
        self.override_symbol.serialize(writer)?;
        Ok(())
    }
}

pub struct InitTransfer {
    pub amount: u128,
    pub recipient: String,
    pub fee: u128,
    pub native_fee: u64,
}

impl BorshSerialize for InitTransfer {
    fn serialize<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        writer.write_all(&get_instruction_identifier("global:init_transfer"))?;
        self.amount.serialize(writer)?;
        self.recipient.serialize(writer)?;
        self.fee.serialize(writer)?;
        self.native_fee.serialize(writer)?;
        Ok(())
    }
}

pub struct InitTransferSol {
    pub amount: u128,
    pub recipient: String,
    pub fee: u128,
    pub native_fee: u64,
}

impl BorshSerialize for InitTransferSol {
    fn serialize<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        writer.write_all(&get_instruction_identifier("global:init_transfer_sol"))?;
        self.amount.serialize(writer)?;
        self.recipient.serialize(writer)?;
        self.fee.serialize(writer)?;
        self.native_fee.serialize(writer)?;
        Ok(())
    }
}
