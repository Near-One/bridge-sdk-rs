use ethers::{
    contract::ContractError,
    providers::{Http, Provider},
};

#[derive(thiserror::Error, Debug)]
pub enum NearLightClientOnEthError {
    #[error("Configuration error: {0}")]
    ConfigError(String),
    #[error("Error communicating with Ethereum: {0}")]
    EthRpcError(#[from] ContractError<Provider<Http>>),
}
