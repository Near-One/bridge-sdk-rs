pub(crate) type Result<T> = std::result::Result<T, SuiBridgeClientError>;

#[derive(thiserror::Error, Debug)]
pub enum SuiBridgeClientError {
    #[error("Sui RPC error: {0}")]
    RpcError(String),
    #[error("Sui transaction error: {0}")]
    TransactionError(String),
    #[error("Blockchain data error: {0}")]
    BlockchainDataError(String),
    #[error("Configuration error: {0}")]
    ConfigError(String),
    #[error("Invalid argument: {0}")]
    InvalidArgument(String),
    #[error("Token template bytecode error: {0}")]
    BytecodeError(String),
    #[error("Transaction has not reached the required MPC finality")]
    MpcFinalityNotReached,
}
