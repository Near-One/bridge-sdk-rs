use bitcoin::consensus::{encode, serialize};
use bitcoincore_rpc::bitcoin::hashes::Hash;
use merkle_tools::H256;
use zcash_primitives::block::BlockHeader;
use zcash_primitives::transaction::Transaction;
use zcash_protocol::consensus::BranchId;

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

/// A Zcash block: a `zcash_primitives` header followed by its transactions.
///
/// Replaces the former `zebra_chain::block::Block` so the whole workspace shares
/// the Near-One librustzcash fork's (stable-RustCrypto) `zcash_primitives` rather
/// than dragging in Zebra's separate, RC-pinned `zcash_primitives` copy.
pub struct ZcashBlock {
    header: BlockHeader,
    transactions: Vec<Transaction>,
}

impl UTXOChainBlock for ZcashBlock {
    fn from_str(str: &str) -> Result<Self, UtxoClientError> {
        let bytes = hex::decode(str)
            .map_err(|e| UtxoClientError::Other(format!("Invalid block hex: {e}")))?;
        let mut cursor = std::io::Cursor::new(bytes);

        let header = BlockHeader::read(&mut cursor).map_err(|e| {
            UtxoClientError::Other(format!("Zcash header deserialization failed: {e}"))
        })?;

        let tx_count = zcash_encoding::CompactSize::read(&mut cursor).map_err(|e| {
            UtxoClientError::Other(format!("Zcash tx count deserialization failed: {e}"))
        })?;

        let mut transactions = Vec::new();
        for _ in 0..tx_count {
            // V5 transactions carry their own consensus branch id, which `read` parses
            // from the stream; the argument is only a hint for pre-V5 formats. The blocks
            // the bridge handles are post-NU5 (all V5), so the value passed is unused there.
            let tx = Transaction::read(&mut cursor, BranchId::Nu5).map_err(|e| {
                UtxoClientError::Other(format!("Zcash tx deserialization failed: {e}"))
            })?;
            transactions.push(tx);
        }

        Ok(Self {
            header,
            transactions,
        })
    }

    fn hash(&self) -> String {
        // `BlockHash`'s `Display` emits big-endian hex — identical to the former zebra
        // output and to what `bitcoin::BlockHash::from_str` consumes downstream.
        self.header.hash().to_string()
    }

    fn transactions(&self) -> Vec<H256> {
        // `TxId` stores bytes little-endian internally (same convention as
        // `bitcoin::Txid::to_byte_array` and `merkle_tools::H256`), so the merkle tree
        // and `to_string()` comparisons behave exactly as they did with zebra.
        self.transactions
            .iter()
            .map(|tx| <[u8; 32]>::from(tx.txid()).into())
            .collect()
    }

    fn tx_data(&self, tx_index: usize) -> Vec<u8> {
        let mut tx_data = Vec::new();
        self.transactions[tx_index]
            .write(&mut tx_data)
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
    type Block = ZcashBlock;

    fn is_zcash() -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Real Zcash mainnet block 2,300,000 (post-NU5): a single V5 coinbase tx.
    // Oracle values (block hash + txid) cross-checked against blockchair.com.
    const ZCASH_BLOCK_2300000: &str = include_str!("test_data/zcash_block_2300000.hex");
    const EXPECTED_BLOCK_HASH: &str =
        "00000000005ac7bf0554036dac0c5682fe35efe6979899ab3b84e436b44f0271";
    const EXPECTED_TXID: &str = "6909955680fd2fe6389c384c5947ddcda3fb1839ccb1c2ae8e2aa7c97cb9160d";

    #[test]
    fn zcash_block_parses_hash_txids_and_roundtrips_tx_bytes() {
        let block_hex = ZCASH_BLOCK_2300000.trim();
        let block = ZcashBlock::from_str(block_hex).expect("block should deserialize");

        // Block hash: big-endian display, exactly what `bitcoin::BlockHash::from_str` expects.
        assert_eq!(block.hash(), EXPECTED_BLOCK_HASH);

        // One coinbase txid, in the same byte convention `merkle_tools` and the queried
        // `tx_hash` string use (internal little-endian; `Display` reverses to big-endian).
        let txids = block.transactions();
        assert_eq!(txids.len(), 1);
        assert_eq!(txids[0].to_string(), EXPECTED_TXID);

        // `tx_data` round-trips: the re-serialized coinbase is byte-identical to the
        // tx bytes that followed the header + tx-count in the original block.
        let tx_bytes = block.tx_data(0);
        assert!(!tx_bytes.is_empty());
        assert!(
            block_hex.ends_with(&hex::encode(&tx_bytes)),
            "re-serialized tx must match the original block's trailing tx bytes"
        );
    }
}
