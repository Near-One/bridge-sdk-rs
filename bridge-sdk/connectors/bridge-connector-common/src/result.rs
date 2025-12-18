use alloy::{
    providers::PendingTransactionError,
    transports::{RpcError, TransportErrorKind},
};
use eth_proof::{EthClientError, EthProofError};
use evm_bridge_client::error::EvmBridgeClientError;
use near_rpc_client::NearRpcError;
use solana_bridge_client::error::SolanaBridgeClientError;
use solana_client::client_error::ClientError;
use std::result;
use utxo_bridge_client::{self, error::UtxoClientError};

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
    #[error("Utxo Client Error: {0}")]
    UtxoClientError(String),
    #[error("Error communicating with Utxo chain RPC: {0}")]
    UtxoRpcError(String),
    #[error("Insufficient UTXO chain Gas Fee: {0}")]
    InsufficientUTXOGasFee(String),
    #[error("Insufficient UTXO balance to cover amount and fees")]
    InsufficientUTXOBalance,
    #[error("Insufficient balance for transaction: {0}")]
    InsufficientBalance(String),
    #[error("Invalid argument provided: {0}")]
    InvalidArgument(String),
    #[error("Light client not synced, current height {0}")]
    LightClientNotSynced(u64),
    #[error("Invalid log found. {0}")]
    InvalidLog(String),
    #[error("Invalid contract configuration. {0}")]
    ContractConfigurationError(String),
    #[error("Utxo management error: {0}")]
    UtxoManagementError(String),
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
    RpcError(#[source] RpcError<TransportErrorKind>),
    PendingTransactionError(#[source] PendingTransactionError),
    ContractError(String),
    BlockchainDataError(String),
}

impl From<EthProofError> for BridgeSdkError {
    fn from(error: EthProofError) -> Self {
        match error {
            EthProofError::TrieError(e) => Self::EthProofError(e.to_string()),
            EthProofError::EthClientError(EthClientError::ParseError(e)) => {
                Self::EthRpcError(EthRpcError::RpcError(RpcError::DeserError {
                    err: e,
                    text: String::new(),
                }))
            }
            EthProofError::EthClientError(EthClientError::TransportError(e)) => Self::EthRpcError(
                EthRpcError::RpcError(RpcError::Transport(TransportErrorKind::Custom(Box::new(e)))),
            ),
            EthProofError::Other(e) => Self::EthProofError(e),
        }
    }
}

impl From<UtxoClientError> for BridgeSdkError {
    fn from(error: UtxoClientError) -> Self {
        match error {
            UtxoClientError::RpcError(e) => Self::UtxoRpcError(e),
            UtxoClientError::Other(e) => Self::UtxoClientError(e),
        }
    }
}

impl From<EvmBridgeClientError> for BridgeSdkError {
    fn from(error: EvmBridgeClientError) -> Self {
        match error {
            EvmBridgeClientError::RpcError(e) => Self::EthRpcError(EthRpcError::RpcError(e)),
            EvmBridgeClientError::PendingTransactionError(e) => {
                Self::EthRpcError(EthRpcError::PendingTransactionError(e))
            }
            EvmBridgeClientError::ContractError(e) => {
                Self::EthRpcError(EthRpcError::ContractError(e))
            }
            EvmBridgeClientError::BlockchainDataError(e) => {
                Self::EthRpcError(EthRpcError::BlockchainDataError(e))
            }
            EvmBridgeClientError::EthProofError(e) => Self::EthProofError(e.to_string()),
            EvmBridgeClientError::InvalidArgument(e) => Self::InvalidArgument(e),
            EvmBridgeClientError::ConfigError(e) => Self::ConfigError(e),
        }
    }
}
