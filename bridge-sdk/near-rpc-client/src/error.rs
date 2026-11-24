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

    /// `(tx_nonce, ak_nonce)` when the node rejected a transaction because its
    /// nonce was not greater than the access-key nonce. That signed transaction
    /// can no longer be included. It can already be on chain if the same request
    /// was sent twice, so check its status before you re-sign it with a new nonce.
    #[must_use]
    pub fn invalid_nonce(&self) -> Option<(u64, u64)> {
        match self {
            Self::RpcTransactionError(err) => crate::near_rpc_client::invalid_nonce(err),
            _ => None,
        }
    }

    /// `true` when the error was produced by executing code on the contract,
    /// as opposed to a transport/RPC failure. Includes the method-not-found
    /// case — check [`Self::is_method_not_found`] first when that matters.
    #[must_use]
    pub fn is_contract_execution_error(&self) -> bool {
        matches!(
            self,
            Self::RpcQueryError(JsonRpcError::ServerError(JsonRpcServerError::HandlerError(
                RpcQueryError::ContractExecutionError { .. },
            )))
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

    #[test]
    fn prohibited_in_view_is_contract_execution_error() {
        let err = contract_execution_error(
            "wasm execution failed with error: HostError(ProhibitedInView { method_name: \"attached_deposit\" })",
        );
        assert!(err.is_contract_execution_error());
        assert!(!err.is_method_not_found());
    }

    #[test]
    fn non_handler_server_error_is_not_contract_execution_error() {
        let err = NearRpcError::RpcQueryError(JsonRpcError::ServerError(
            JsonRpcServerError::InternalError { info: None },
        ));
        assert!(!err.is_contract_execution_error());
    }

    #[test]
    fn unrelated_error_is_not_contract_execution_error() {
        assert!(!NearRpcError::ResultError.is_contract_execution_error());
    }

    fn transaction_error(context: near_primitives::errors::InvalidTxError) -> NearRpcError {
        NearRpcError::RpcTransactionError(JsonRpcError::ServerError(
            JsonRpcServerError::HandlerError(RpcTransactionError::InvalidTransaction { context }),
        ))
    }

    #[test]
    fn invalid_nonce_is_detected() {
        let err = transaction_error(near_primitives::errors::InvalidTxError::InvalidNonce {
            tx_nonce: 10,
            ak_nonce: 13,
        });
        assert_eq!(err.invalid_nonce(), Some((10, 13)));
    }

    #[test]
    fn invalid_nonce_from_rpc_response_is_detected() {
        // Shape of a real `send_tx` rejection. The client parses it from `data`
        // because `cause.info` has no `context`.
        let response = serde_json::json!({
            "jsonrpc": "2.0",
            "id": "dontcare",
            "error": {
                "name": "HANDLER_ERROR",
                "cause": { "name": "INVALID_TRANSACTION", "info": {} },
                "code": -32000,
                "message": "Server error",
                "data": { "TxExecutionError": { "InvalidTxError": {
                    "InvalidNonce": { "tx_nonce": 129, "ak_nonce": 131 }
                } } }
            }
        });
        let rpc_error: near_jsonrpc_primitives::errors::RpcError =
            serde_json::from_value(response["error"].clone()).unwrap();
        let err = NearRpcError::RpcTransactionError(JsonRpcError::from(rpc_error));
        assert_eq!(err.invalid_nonce(), Some((129, 131)));
    }

    #[test]
    fn other_invalid_tx_is_not_invalid_nonce() {
        let err = transaction_error(near_primitives::errors::InvalidTxError::NonceTooLarge {
            tx_nonce: 10,
            upper_bound: 5,
        });
        assert_eq!(err.invalid_nonce(), None);
    }

    #[test]
    fn timeout_is_not_invalid_nonce() {
        let err = NearRpcError::RpcTransactionError(JsonRpcError::ServerError(
            JsonRpcServerError::HandlerError(RpcTransactionError::TimeoutError),
        ));
        assert_eq!(err.invalid_nonce(), None);
        assert_eq!(NearRpcError::ResultError.invalid_nonce(), None);
    }
}
