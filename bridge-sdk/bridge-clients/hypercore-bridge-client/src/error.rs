pub(crate) type Result<T> = std::result::Result<T, HyperCoreBridgeClientError>;

#[derive(thiserror::Error, Debug)]
pub enum HyperCoreBridgeClientError {
    #[error("Configuration error: {0}")]
    ConfigError(String),
    #[error("Invalid argument: {0}")]
    InvalidArgument(String),
    #[error("Invalid signatureChainId: {0}")]
    InvalidSignatureChainId(String),
    #[error("Encoding error: {0}")]
    Encoding(String),
    #[error("Signing error: {0}")]
    Signing(String),
    #[error("HTTP error: {0}")]
    Http(String),
    #[error("Hyperliquid /exchange rejected the action: {0}")]
    ExchangeRejected(String),
    #[error("HyperEVM RPC error: {0}")]
    Rpc(String),
    #[error("Timed out waiting for CoreReceived log on HyperEVM")]
    PollTimeout,
}
