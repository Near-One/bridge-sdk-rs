#[cfg(feature = "client")]
use solana_rpc_client_api::client_error::Error as ClientError;

#[derive(thiserror::Error, Debug)]
pub enum SolanaBridgeClientError {
    #[cfg(feature = "client")]
    #[error("Solana RPC error: {0}")]
    RpcError(Box<ClientError>),
    #[error("Configuration error: {0}")]
    ConfigError(String),
    #[error("Invalid account data")]
    InvalidAccountData(String),
    #[error("Invalid argument: {0}")]
    InvalidArgument(String),
    #[error("Invalid event")]
    InvalidEvent,
    #[error("Serialization error: {0}")]
    SerializationError(String),
}

#[cfg(feature = "client")]
impl From<ClientError> for SolanaBridgeClientError {
    fn from(err: ClientError) -> Self {
        SolanaBridgeClientError::RpcError(Box::new(err))
    }
}
