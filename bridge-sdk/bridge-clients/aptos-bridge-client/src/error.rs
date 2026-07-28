pub(crate) type Result<T> = std::result::Result<T, AptosBridgeClientError>;

#[derive(thiserror::Error, Debug)]
pub enum AptosBridgeClientError {
    #[error("Aptos REST error: {0}")]
    RestError(String),
    #[error("Aptos transaction error: {0}")]
    TransactionError(String),
    #[error("Blockchain data error: {0}")]
    BlockchainDataError(String),
    #[error("Configuration error: {0}")]
    ConfigError(String),
    #[error("Invalid argument: {0}")]
    InvalidArgument(String),
    #[error("Transaction has not reached the required MPC finality")]
    MpcFinalityNotReached,
}
