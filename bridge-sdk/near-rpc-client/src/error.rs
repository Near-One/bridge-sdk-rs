use near_jsonrpc_client::{
    errors::{JsonRpcError, JsonRpcServerError},
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
    #[error("Could not serialize transaction")]
    SerializationError,
    #[error("Public key {public_key} is not an access key on account {account_id}")]
    UnknownAccessKey {
        account_id: String,
        public_key: String,
    },
}

impl NearRpcError {
    /// `true` when a call failed because the contract does not export the
    /// requested method, as opposed to a transport failure or a panic inside
    /// an existing method.
    #[must_use]
    pub fn is_method_not_found(&self) -> bool {
        matches!(
            self,
            Self::RpcQueryError(JsonRpcError::ServerError(JsonRpcServerError::HandlerError(
                RpcQueryError::ContractExecutionError { vm_error, .. },
            ))) if vm_error.contains("MethodNotFound")
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn contract_execution_error(vm_error: &str) -> NearRpcError {
        NearRpcError::RpcQueryError(JsonRpcError::ServerError(JsonRpcServerError::HandlerError(
            RpcQueryError::ContractExecutionError {
                vm_error: vm_error.to_string(),
                block_height: 0,
                block_hash: near_primitives::hash::CryptoHash::default(),
            },
        )))
    }

    #[test]
    fn method_not_found_is_detected() {
        let err = contract_execution_error(
            "wasm execution failed with error: MethodResolveError(MethodNotFound)",
        );
        assert!(err.is_method_not_found());
    }

    #[test]
    fn contract_panic_is_not_method_not_found() {
        let err = contract_execution_error(
            "wasm execution failed with error: HostError(GuestPanic { panic_msg: \"Not enough confirmations for the block-cumulative bridge amount\" })",
        );
        assert!(!err.is_method_not_found());
    }

    #[test]
    fn non_handler_server_error_is_not_method_not_found() {
        let err = NearRpcError::RpcQueryError(JsonRpcError::ServerError(
            JsonRpcServerError::InternalError {
                info: Some("MethodNotFound".to_string()),
            },
        ));
        assert!(!err.is_method_not_found());
    }

    #[test]
    fn unrelated_error_is_not_method_not_found() {
        assert!(!NearRpcError::ResultError.is_method_not_found());
    }
}
