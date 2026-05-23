use bitcoin::{
    consensus::{encode, serialize},
    hex::FromHex,
};
use bitcoincore_rpc::bitcoin::hashes::Hash;
use merkle_tools::H256;
use zebra_chain::{
    self,
    serialization::{ZcashDeserialize, ZcashSerialize},
};

use crate::error::UtxoClientError;

#[derive(Debug)]
pub struct TxProof {
    pub block_height: u64,
    pub tx_bytes: Vec<u8>,
    pub tx_block_blockhash: String,
    pub tx_index: u64,
    pub merkle_proof: Vec<String>,
    pub outputs: Vec<TxOutputView>,
}

/// Chain-agnostic view of a UTXO transparent output, sufficient for the
/// fin-transfer / refund / vout-resolution flows. Bitcoin and Zcash have the
/// same transparent-output shape (a satoshi value plus a `scriptPubKey`) but
/// incompatible whole-transaction serializations, so carrying these alongside
/// the proof lets downstream callers consume outputs without re-parsing the
/// raw tx bytes.
#[derive(Debug, Clone)]
pub struct TxOutputView {
    pub value_sat: u64,
    pub script_pubkey: Vec<u8>,
}

/// Bundle of work already done for a deposit BTC tx. Produced by
/// `resolve_deposit_vout` and threaded into a follow-up
/// `build_fin_btc_transfer_args` / `btc_request_refund` to skip a second
/// `extract_btc_proof` round-trip.
#[derive(Debug)]
pub struct PrefetchedTxData {
    pub proof: TxProof,
}

pub struct UtxoBridgeTransactionData {
    pub tx_hash: String,
    pub deposit_address: String,
    pub amount: u64,
    pub vout: u32,
}

pub trait UTXOChainBlock {
    fn from_str(str: &str) -> Result<Self, UtxoClientError>
    where
        Self: Sized;
    fn hash(&self) -> String;
    fn transactions(&self) -> Vec<H256>;
    fn tx_data(&self, tx_index: usize) -> Vec<u8>;
}

impl UTXOChainBlock for bitcoin::Block {
    fn from_str(str: &str) -> Result<Self, UtxoClientError> {
        encode::deserialize_hex(str)
            .map_err(|e| UtxoClientError::Other(format!("Failed to parse block: {e}")))
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
    fn from_str(str: &str) -> Result<Self, UtxoClientError> {
        let bytes = Vec::from_hex(str).expect("Invalid hex");
        let mut cursor = std::io::Cursor::new(bytes);
        zebra_chain::block::Block::zcash_deserialize(&mut cursor)
            .map_err(|e| UtxoClientError::Other(format!("Deserialization failed: {e}")))
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
