use bitcoin::{
    consensus::{encode, serialize},
    hex::FromHex,
};
use bitcoincore_rpc::bitcoin::hashes::Hash;
use bridge_connector_common::result::{BridgeSdkError, Result};
use merkle_tools::H256;
use zebra_chain::{
    self,
    serialization::{ZcashDeserialize, ZcashSerialize},
};

#[derive(Debug)]
pub struct TxProof {
    pub tx_bytes: Vec<u8>,
    pub tx_block_blockhash: String,
    pub tx_index: u64,
    pub merkle_proof: Vec<String>,
}

pub trait UTXOChainBlock {
    fn from_str(str: &str) -> Result<Self>
    where
        Self: Sized;
    fn hash(&self) -> String;
    fn transactions(&self) -> Vec<H256>;
    fn tx_data(&self, tx_index: usize) -> Vec<u8>;
}

impl UTXOChainBlock for bitcoin::Block {
    fn from_str(str: &str) -> Result<Self> {
        encode::deserialize_hex(str)
            .map_err(|e| BridgeSdkError::BtcClientError(format!("Failed to parse block: {e}")))
    }

    fn hash(&self) -> String {
        self.header.block_hash().to_string()
    }

    fn transactions(&self) -> Vec<H256> {
        self.txdata
            .iter()
            .map(|tx| tx.compute_txid().to_byte_array().into())
            .collect()
    }

    fn tx_data(&self, tx_index: usize) -> Vec<u8> {
        serialize(&self.txdata[tx_index])
    }
}

impl UTXOChainBlock for zebra_chain::block::Block {
    fn from_str(str: &str) -> Result<Self> {
        let bytes = Vec::from_hex(str).expect("Invalid hex");
        let mut cursor = std::io::Cursor::new(bytes);
        zebra_chain::block::Block::zcash_deserialize(&mut cursor)
            .map_err(|e| BridgeSdkError::BtcClientError(format!("Deserialization failed: {e}")))
    }

    fn hash(&self) -> String {
        self.header.hash().to_string()
    }

    fn transactions(&self) -> Vec<H256> {
        self.transactions
            .iter()
            .map(|tx| tx.hash().0.into())
            .collect()
    }

    fn tx_data(&self, tx_index: usize) -> Vec<u8> {
        let mut tx_data = Vec::new();
        self.transactions[tx_index]
            .zcash_serialize(&mut tx_data)
            .expect("Serialization failed");
        tx_data
    }
}

pub trait UTXOChain {
    type Block: UTXOChainBlock;

    fn is_zcash() -> bool;
}

pub struct Bitcoin;
impl UTXOChain for Bitcoin {
    type Block = bitcoin::Block;

    fn is_zcash() -> bool {
        false
    }
}

pub struct Zcash;
impl UTXOChain for Zcash {
    type Block = zebra_chain::block::Block;

    fn is_zcash() -> bool {
        true
    }
}
