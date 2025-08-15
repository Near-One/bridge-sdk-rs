use crate::bitcoin::transaction;
use bitcoin::consensus::encode::Error;
use bitcoin::consensus::{deserialize, Decodable};
use bitcoin::hex::FromHex;
use bitcoin::io::Read;
use bitcoin::{BlockHash, Transaction};
use bitcoincore_rpc::bitcoin::hashes::Hash;
use bitcoincore_rpc::jsonrpc::minreq_http::HttpError;
use bitcoincore_rpc::jsonrpc::Transport;
use bitcoincore_rpc::{bitcoin, jsonrpc, RawTx, RpcApi};
use bridge_connector_common::result::{BridgeSdkError, Result as BridgeResult};
use jsonrpc::{Request, Response};
use std::str::FromStr;
use zcash_primitives::consensus::BranchId;
use zebra_chain;
use zebra_chain::serialization::{ZcashDeserialize, ZcashSerialize};

struct CustomMinreqHttpTransport {
    url: String,
    timeout: std::time::Duration,
    basic_auth: Option<String>,
    headers: Vec<(String, String)>,
}

impl CustomMinreqHttpTransport {
    fn request<R>(&self, req: impl serde::Serialize) -> Result<R, jsonrpc::minreq_http::Error>
    where
        R: for<'a> serde::de::Deserialize<'a>,
    {
        let req = match &self.basic_auth {
            Some(auth) => minreq::Request::new(minreq::Method::Post, &self.url)
                .with_timeout(self.timeout.as_secs())
                .with_header("Authorization", auth)
                .with_headers(self.headers.clone())
                .with_json(&req)?,
            None => minreq::Request::new(minreq::Method::Post, &self.url)
                .with_timeout(self.timeout.as_secs())
                .with_json(&req)?,
        };

        // Send the request and parse the response. If the response is an error that does not
        // contain valid JSON in its body (for instance if the bitcoind HTTP server work queue
        // depth is exceeded), return the raw HTTP error so users can match against it.
        let resp = req.send()?;
        match resp.json() {
            Ok(json) => Ok(json),
            Err(minreq_err) => {
                if resp.status_code == 200 {
                    Err(jsonrpc::minreq_http::Error::Minreq(minreq_err))
                } else {
                    Err(jsonrpc::minreq_http::Error::Http(HttpError {
                        status_code: resp.status_code,
                        body: resp.as_str().unwrap_or("").to_string(),
                    }))
                }
            }
        }
    }

    pub fn basic_auth(user: String, pass: Option<String>) -> String {
        let mut s = user;
        s.push(':');
        if let Some(ref pass) = pass {
            s.push_str(pass.as_ref());
        }
        format!("Basic {}", &jsonrpc::base64::encode(s.as_bytes()))
    }
}

impl Transport for CustomMinreqHttpTransport {
    fn send_request(&self, req: Request) -> Result<Response, jsonrpc::Error> {
        Ok(self.request(req)?)
    }

    fn send_batch(&self, reqs: &[Request]) -> Result<Vec<Response>, jsonrpc::Error> {
        Ok(self.request(reqs)?)
    }

    fn fmt_target(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", self.url)
    }
}

#[derive(Debug)]
pub struct TxProof {
    pub tx_bytes: Vec<u8>,
    pub tx_block_blockhash: String,
    pub tx_index: u64,
    pub merkle_proof: Vec<String>,
}

pub struct BtcBridgeClient {
    bitcoin_client: bitcoincore_rpc::Client,
}

impl BtcBridgeClient {
    pub fn new(
        btc_endpoint: &str,
        btc_user: Option<String>,
        btc_password: Option<String>,
        btc_headers: Option<Vec<String>>,
    ) -> Self {
        let client = CustomMinreqHttpTransport {
            url: btc_endpoint.to_string(),
            timeout: std::time::Duration::from_secs(15),
            basic_auth: Some(CustomMinreqHttpTransport::basic_auth(
                btc_user.unwrap_or(String::new()),
                btc_password,
            )),
            headers: btc_headers
                .unwrap_or_default()
                .into_iter()
                .filter_map(|s| {
                    let mut parts = s.splitn(2, ',').map(str::trim);
                    let key = parts.next()?;
                    let value = parts.next()?;
                    Some((key.to_string(), value.to_string()))
                })
                .collect(),
        };

        BtcBridgeClient {
            bitcoin_client: bitcoincore_rpc::Client::from_jsonrpc(client.into()),
        }
    }

    pub fn get_block_hash_by_tx_hash(&self, tx_hash: &str) -> BridgeResult<BlockHash> {
        let tx_raw = self
            .bitcoin_client
            .get_raw_transaction_info(
                &bitcoin::Txid::from_str(tx_hash).map_err(|err| {
                    BridgeSdkError::BtcClientError(format!("Incorrect tx_hash: {err}"))
                })?,
                None,
            )
            .map_err(|err| {
                BridgeSdkError::BtcClientError(format!("Error on get raw tx info: {err}"))
            })?;

        tx_raw.blockhash.ok_or(BridgeSdkError::BtcClientError(
            "Tx not finalized yet".to_string(),
        ))
    }

    pub fn extract_btc_proof(&self, tx_hash: &str) -> BridgeResult<TxProof> {
        let block_hash = self.get_block_hash_by_tx_hash(tx_hash)?;
        let block_hex = self
            .bitcoin_client
            .get_block_hex(&block_hash)
            .map_err(|err| BridgeSdkError::BtcClientError(format!("Error on get block: {err}")))?;

        let bytes = Vec::from_hex(&block_hex).expect("Invalid hex");
        let mut cursor = std::io::Cursor::new(bytes);
        let block = zebra_chain::block::Block::zcash_deserialize(&mut cursor)
            .expect("Deserialization failed");

        println!("Zebra Block: {:?}", block);

        let tx_block_blockhash = block.header.hash();

        let transactions = block
            .transactions
            .iter()
            .map(|tx| tx.hash().to_string())
            .collect::<Vec<_>>();

        let tx_index = transactions
            .iter()
            .position(|hash| *hash == tx_hash)
            .ok_or(BridgeSdkError::InvalidArgument(
                "btc tx not found in block".to_string(),
            ))?;

        let merkle_proof = Self::compute_merkle_proof(&block, tx_index);
        let merkle_proof_str = merkle_proof
            .iter()
            .map(std::string::ToString::to_string)
            .collect();

        let mut tx_data = Vec::new();
        &block.transactions[tx_index]
            .zcash_serialize(&mut tx_data)
            .expect("Serialization failed");

        let hex_string = hex::encode(tx_data.clone());
        tracing::info!("Zcash Tx Bytes: {hex_string}");

        Ok(TxProof {
            tx_bytes: tx_data,
            tx_block_blockhash: tx_block_blockhash.to_string(),
            tx_index: tx_index
                .try_into()
                .expect("Error on convert usize into u64"),
            merkle_proof: merkle_proof_str,
        })
    }

    pub fn get_fee_rate(&self) -> BridgeResult<u64> {
        return Ok(1000);
        /*let fee_rate = self
            .bitcoin_client
            .estimate_smart_fee(2, None)
            .map_err(|err| {
                BridgeSdkError::BtcClientError(format!("Error on estimate smart fee: {err}"))
            })?
            .fee_rate
            .ok_or(BridgeSdkError::BtcClientError(
                "Error on estimate fee_rate".to_string(),
            ))?;

        Ok(fee_rate.to_sat())*/
    }

    pub fn send_tx(&self, tx_bytes: &[u8]) -> BridgeResult<String> {
        let tx: ZCashTransaction =
            deserialize(tx_bytes).expect("Failed to deserialize transaction");

        let mut cursor = std::io::Cursor::new(tx_bytes);
        let _ =
            zcash_primitives::transaction::Transaction::read(&mut cursor, BranchId::Nu6_1).unwrap();

        let tx_hash = self
            .bitcoin_client
            .send_raw_transaction(tx)
            .map_err(|err| {
                BridgeSdkError::BtcClientError(format!("Error on sending BTC transaction: {err}"))
            })?;
        Ok(tx_hash.to_string())
    }

    #[must_use]
    #[allow(dead_code)]
    pub fn compute_merkle_proof(
        block: &zebra_chain::block::Block,
        transaction_position: usize,
    ) -> Vec<merkle_tools::H256> {
        let transactions = block
            .transactions
            .iter()
            .map(|tx| tx.hash().0.into())
            .collect();

        merkle_tools::merkle_proof_calculator(transactions, transaction_position)
    }
}

#[derive(Debug, PartialEq, Clone)]
pub struct ZCashTransaction {
    pub hex_str: String,
}

impl Decodable for ZCashTransaction {
    fn consensus_decode<R: Read + ?Sized>(reader: &mut R) -> Result<Self, Error> {
        let mut data = vec![];
        reader.read_to_limit(&mut data, 100000);
        Ok(Self {
            hex_str: hex::encode(data),
        })
    }
}

impl RawTx for ZCashTransaction {
    fn raw_hex(self) -> String {
        self.hex_str
    }
}
