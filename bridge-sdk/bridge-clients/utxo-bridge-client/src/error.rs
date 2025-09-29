#[derive(thiserror::Error, Debug)]
pub enum UtxoClientError {
    #[error("RPC error: {0}")]
    RpcError(String),
    #[error("{0}")]
    Other(String),
}
