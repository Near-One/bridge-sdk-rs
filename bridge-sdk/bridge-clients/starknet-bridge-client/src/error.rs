pub(crate) type Result<T> = std::result::Result<T, StarknetBridgeClientError>;

#[derive(thiserror::Error, Debug)]
pub enum StarknetBridgeClientError {
    #[error("Starknet provider error: {0}")]
    ProviderError(String),
    #[error("Starknet account error: {0}")]
    AccountError(String),
    #[error("Blockchain data error: {0}")]
    BlockchainDataError(String),
    #[error("Configuration error: {0}")]
    ConfigError(String),
    #[error("Invalid argument: {0}")]
    InvalidArgument(String),
    #[error("Transaction error: {0}")]
    TransactionError(String),
}
