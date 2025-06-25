use eth_proof::{EthClientError, EthProofError};
use ethers::{
    contract::ContractError,
    middleware::SignerMiddleware,
    providers::{Http, Provider, ProviderError},
    signers::LocalWallet,
};
use near_light_client_on_eth::NearLightClientOnEthError;
use near_rpc_client::NearRpcError;
use solana_bridge_client::error::SolanaBridgeClientError;
use solana_client::client_error::ClientError;
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
    #[error("Error communicating with Solana RPC: {0}")]
    SolanaRpcError(#[from] ClientError),
    #[error("Error working with Solana: {0}")]
    SolanaOtherError(String),
    #[error("Wormhole client error: {0}")]
    WormholeClientError(String),
    #[error("BTC Client Error: {0}")]
    BtcClientError(String),
    #[error("Invalid argument provided: {0}")]
    InvalidArgument(String),
    #[error("Unexpected error occured: {0}")]
    UnknownError(String),
}

impl From<SolanaBridgeClientError> for BridgeSdkError {
    fn from(error: SolanaBridgeClientError) -> Self {
        match error {
            SolanaBridgeClientError::RpcError(e) => Self::SolanaRpcError(*e),
            SolanaBridgeClientError::ConfigError(e) => Self::ConfigError(e),
            SolanaBridgeClientError::InvalidAccountData(e) => Self::SolanaOtherError(e),
            SolanaBridgeClientError::InvalidEvent => {
                Self::SolanaOtherError("Invalid event".to_string())
            }
            SolanaBridgeClientError::InvalidArgument(e) => Self::InvalidArgument(e),
        }
    }
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

impl From<ProviderError> for BridgeSdkError {
    fn from(error: ProviderError) -> Self {
        Self::EthRpcError(EthRpcError::ProviderError(error))
    }
}
