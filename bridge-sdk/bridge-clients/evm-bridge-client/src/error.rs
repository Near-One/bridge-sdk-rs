use alloy::{
    contract::Error as ContractError,
    providers::PendingTransactionError,
    transports::{RpcError, TransportErrorKind},
};

pub(crate) type Result<T> = std::result::Result<T, EvmBridgeClientError>;

#[derive(thiserror::Error, Debug)]
pub enum EvmBridgeClientError {
    #[error("RPC error: {0}")]
    RpcError(#[from] RpcError<TransportErrorKind>),
    #[error("Blockchain data error: {0}")]
    BlockchainDataError(String),
    #[error("Contract error: {0}")]
    ContractError(String),
    #[error("Pending transaction error: {0}")]
    PendingTransactionError(#[from] PendingTransactionError),
    #[error("Configuration error: {0}")]
    ConfigError(String),
    #[error("{0}")]
    EthProofError(#[from] eth_proof::EthProofError),
    #[error("Invalid argument: {0}")]
    InvalidArgument(String),
}

impl From<ContractError> for EvmBridgeClientError {
    fn from(err: ContractError) -> Self {
        match err {
            ContractError::TransportError(e) => EvmBridgeClientError::RpcError(e),
            ContractError::PendingTransactionError(e) => {
                EvmBridgeClientError::PendingTransactionError(e)
            }
            other => EvmBridgeClientError::ContractError(other.to_string()),
        }
    }
}
