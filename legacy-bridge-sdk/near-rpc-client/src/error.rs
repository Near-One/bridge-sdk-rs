use near_jsonrpc_client::{
    errors::JsonRpcError,
    methods::{
        block::RpcBlockError, broadcast_tx_async::RpcBroadcastTxAsyncError, query::RpcQueryError,
        tx::RpcTransactionError,
    },
};
use near_jsonrpc_primitives::types::light_client::RpcLightClientProofError;

#[allow(clippy::module_name_repetitions)]
#[derive(thiserror::Error, Debug)]
#[error("Near RPC error: {0}")]
pub enum NearRpcError {
    RpcQueryError(#[from] JsonRpcError<RpcQueryError>),
    RpcBroadcastTxAsyncError(#[from] JsonRpcError<RpcBroadcastTxAsyncError>),
    RpcLightClientProofError(#[from] JsonRpcError<RpcLightClientProofError>),
    RpcBlockError(#[from] JsonRpcError<RpcBlockError>),
    RpcTransactionError(#[from] JsonRpcError<RpcTransactionError>),
    #[error("Unexpected RPC response")]
    ResultError,
    #[error("Could not retrieve nonce for account")]
    NonceError,
    #[error("Could not confirm that transaction was finalized")]
    FinalizationError,
}
