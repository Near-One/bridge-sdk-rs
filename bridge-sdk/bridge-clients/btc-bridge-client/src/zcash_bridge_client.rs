use bridge_connector_common::result::Result;
use reqwest::Client;

use crate::UTXOBridgeClient;
use crate::btc_bridge_client::TxProof;

pub struct ZcashBridgeClient {
    endpoint_url: String,
    http_client: Client,
}

impl UTXOBridgeClient for ZcashBridgeClient {
    fn new(rpc_endpoint: String, api_key: Option<&str>) -> Self {
        ZcashBridgeClient { 
            endpoint_url: rpc_endpoint,
            http_client: Self::build_client(api_key)
        }
    }

    fn http_post(&self) -> reqwest::RequestBuilder {
        self.http_client.post(&self.endpoint_url)
            .header("Content-Type", "application/json")
    }

    async fn extract_btc_proof(&self, tx_hash: &str) -> Result<TxProof> {
        unimplemented!()
    }

    async fn get_fee_rate(&self) -> Result<u64> {
        Ok(1000)
    }
}
