use solana_client::client_error::ClientError;

#[derive(thiserror::Error, Debug)]
pub enum SolanaClientError {
    #[error("Solana RPC error: {0}")]
    RpcError(#[from] ClientError),
    #[error("Configuration error: {0}")]
    ConfigError(String),
    #[error("Invalid account data")]
    InvalidAccountData(String),
    #[error("Invalid event")]
    InvalidEvent,
}
