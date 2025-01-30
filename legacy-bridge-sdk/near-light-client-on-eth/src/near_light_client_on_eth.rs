use ethereum_types::Address;
use ethers::{
    contract::abigen,
    providers::{Http, Provider},
};
use std::sync::Arc;

use crate::error::NearLightClientOnEthError;

abigen!(
    NearLightClient,
    r#"[
        function bridgeState() public view returns (uint,uint,uint,uint)
        function blockHashes(uint64) public view returns (bytes32)
    ]"#
);

pub struct NearOnEthClient {
    eth_endpoint: String,
    near_on_eth_client_address: Address,
}

impl NearOnEthClient {
    #[must_use]
    pub fn new(near_one_eth_client_address: Address, eth_rpc_endpoint: String) -> Self {
        Self {
            eth_endpoint: eth_rpc_endpoint,
            near_on_eth_client_address: near_one_eth_client_address,
        }
    }

    /// Get the current sync height of the Near Light Client on Ethereum
    ///
    /// # Errors
    /// Returns an error if the Ethereum RPC client fails to connect
    pub async fn get_sync_height(&self) -> Result<u64, NearLightClientOnEthError> {
        let eth_provider = self.eth_provider()?;
        let client = Arc::new(eth_provider);
        let contract = NearLightClient::new(self.near_on_eth_client_address, client);

        let state = contract.bridge_state().call().await?;

        Ok(state.0.as_u64())
    }

    /// Get the block hash for a specific block number
    ///
    /// # Errors
    /// Returns an error if the Ethereum RPC client fails to connect
    pub async fn get_block_hash(
        &self,
        block_number: u64,
    ) -> Result<[u8; 32], NearLightClientOnEthError> {
        let eth_provider = self.eth_provider()?;
        let client = Arc::new(eth_provider);
        let contract = NearLightClient::new(self.near_on_eth_client_address, client);

        let state = contract.block_hashes(block_number).call().await?;

        Ok(state)
    }

    fn eth_provider(&self) -> Result<Provider<Http>, NearLightClientOnEthError> {
        Provider::<Http>::try_from(self.eth_endpoint.clone()).map_err(|_| {
            NearLightClientOnEthError::ConfigError("Ethereum endpoint url is invalid".to_string())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn get_config() -> (String, Address) {
        let near_on_eth_address = "0x202cdf10bfa45a3d2190901373edd864f071d707"
            .parse()
            .unwrap();
        let eth_rpc_endpoint = "https://ethereum-sepolia-rpc.publicnode.com".to_string();

        (eth_rpc_endpoint, near_on_eth_address)
    }

    #[tokio::test]
    async fn test_sync_height() {
        let (eth_rpc_endpoint, near_on_eth_client_address) = get_config();
        let client = NearOnEthClient::new(near_on_eth_client_address, eth_rpc_endpoint);

        let sync_height = client.get_sync_height().await.unwrap();
        assert!(sync_height > 165_638_532);
    }

    #[tokio::test]
    async fn test_block_hashes() {
        let (eth_rpc_endpoint, near_on_eth_client_address) = get_config();
        let client = NearOnEthClient::new(near_on_eth_client_address, eth_rpc_endpoint);

        let block_hash = client.get_block_hash(164_243_835).await.unwrap();
        assert_eq!(
            block_hash,
            [
                2, 14, 107, 125, 167, 203, 210, 235, 202, 31, 82, 98, 26, 4, 231, 202, 13, 30, 158,
                149, 12, 235, 67, 66, 19, 33, 247, 240, 20, 162, 161, 67
            ]
        );
    }
}
