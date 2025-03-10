use ethers::{
    contract::ContractError,
    middleware::SignerMiddleware,
    providers::{Http, Provider, ProviderError},
    signers::LocalWallet,
};
use legacy_eth_proof::{EthClientError, EthProofError};
use legacy_near_light_client_on_eth::NearLightClientOnEthError;
use legacy_near_rpc_client::NearRpcError;
use std::result;

pub type Result<T> = result::Result<T, BridgeSdkError>;

#[derive(thiserror::Error, Debug)]
pub enum BridgeSdkError {
    #[error("Configuration error: {0}")]
    ConfigError(String),
    #[error("Error communicating with Ethereum RPC: {0}")]
    EthRpcError(#[source] EthRpcError),
    #[error("Error communicating with Near RPC: {0}")]
    NearRpcError(#[from] NearRpcError),
    #[error("Error creating Ethereum proof: {0}")]
    EthProofError(String),
    #[error("Error estimating gas on EVM: {0}")]
    EvmGasEstimateError(String),
    #[error("Error creating Near proof: {0}")]
    NearProofError(String),
    #[error("Error deserializing RPC response: {0}")]
    DeserializationError(#[from] serde_json::Error),
    #[error("Error working with Solana: {0}")]
    SolanaOtherError(String),
    #[error("Wormhole client error: {0}")]
    WormholeClientError(String),
    #[error("Invalid argument provided: {0}")]
    InvalidArgument(String),
    #[error("Unexpected error occured: {0}")]
    UnknownError(String),
}

#[derive(thiserror::Error, Debug)]
#[error("{0}")]
pub enum EthRpcError {
    SignerContractError(#[source] ContractError<SignerMiddleware<Provider<Http>, LocalWallet>>),
    ProviderContractError(#[source] ContractError<Provider<Http>>),
    EthClientError(#[source] EthClientError),
    ProviderError(#[source] ProviderError),
}

impl From<EthProofError> for BridgeSdkError {
    fn from(error: EthProofError) -> Self {
        match error {
            EthProofError::TrieError(e) => Self::EthProofError(e.to_string()),
            EthProofError::EthClientError(e) => Self::EthRpcError(EthRpcError::EthClientError(e)),
            EthProofError::Other(e) => Self::EthProofError(e),
        }
    }
}

impl From<NearLightClientOnEthError> for BridgeSdkError {
    fn from(error: NearLightClientOnEthError) -> Self {
        match error {
            NearLightClientOnEthError::ConfigError(e) => Self::ConfigError(e),
            NearLightClientOnEthError::EthRpcError(e) => {
                Self::EthRpcError(EthRpcError::ProviderContractError(e))
            }
        }
    }
}

impl From<ContractError<SignerMiddleware<Provider<Http>, LocalWallet>>> for BridgeSdkError {
    fn from(error: ContractError<SignerMiddleware<Provider<Http>, LocalWallet>>) -> Self {
        Self::EthRpcError(EthRpcError::SignerContractError(error))
    }
}
