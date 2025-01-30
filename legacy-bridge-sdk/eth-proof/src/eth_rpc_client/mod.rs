use ::serde::Deserialize;
use ethereum_types::{H256, U64};
use reqwest::Client;
use serde_json::{json, Value};
use types::{BlockHeader, TransactionReceipt};

mod serde;
pub mod types;

#[derive(thiserror::Error, Debug)]
pub enum EthClientError {
    #[error("Ethereum RPC error: {0}")]
    TransportError(#[from] reqwest::Error),
    #[error("Couldn't deserialize Ethereum RPC response: {0}")]
    ParseError(#[from] serde_json::Error),
}

pub struct EthRPCClient {
    endpoint_url: String,
    client: Client,
}

impl EthRPCClient {
    pub fn new(endpoint_url: &str) -> Self {
        Self {
            endpoint_url: endpoint_url.to_string(),
            client: reqwest::Client::new(),
        }
    }

    pub async fn get_transaction_receipt_by_hash(
        &self,
        tx_hash: &H256,
    ) -> Result<TransactionReceipt, EthClientError> {
        let json_value = json!({
            "id": 1,
            "jsonrpc": "2.0",
            "method": "eth_getTransactionReceipt",
            "params": [format!("{tx_hash:#x}")]
        });

        let res = self
            .client
            .post(&self.endpoint_url)
            .json(&json_value)
            .send()
            .await?
            .text()
            .await?;

        let val: Value = serde_json::from_str(&res)?;
        let receipt = TransactionReceipt::deserialize(&val["result"])?;

        Ok(receipt)
    }

    pub async fn get_block_by_number(
        &self,
        block_number: U64,
    ) -> Result<BlockHeader, EthClientError> {
        let json_value = json!({
            "id": 1,
            "jsonrpc": "2.0",
            "method": "eth_getBlockByNumber",
            "params": [format!("0x{:x}", block_number), false]
        });

        let res = self
            .client
            .post(&self.endpoint_url)
            .json(&json_value)
            .send()
            .await?
            .text()
            .await?;

        let val: Value = serde_json::from_str(&res)?;
        let header = BlockHeader::deserialize(&val["result"])?;

        Ok(header)
    }

    pub async fn get_block_receipts(
        &self,
        block_number: U64,
    ) -> Result<Vec<TransactionReceipt>, EthClientError> {
        let json_value = json!({
            "id": 1,
            "jsonrpc": "2.0",
            "method": "eth_getBlockReceipts",
            "params": [format!("0x{:x}", block_number)]
        });

        let res = self
            .client
            .post(&self.endpoint_url)
            .json(&json_value)
            .send()
            .await?
            .text()
            .await?;

        let val: Value = serde_json::from_str(&res)?;
        let receipts = Vec::<TransactionReceipt>::deserialize(&val["result"])?;

        Ok(receipts)
    }
}
