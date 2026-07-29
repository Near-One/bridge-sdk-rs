//! Thin wrappers over the `sui-rpc` gRPC client.

use sui_rpc::field::{FieldMask, FieldMaskUtil};
use sui_rpc::proto::sui::rpc::v2::{
    ExecutedTransaction, GetObjectRequest, GetTransactionRequest, Object,
};
use sui_rpc::Client;

use crate::error::{Result, SuiBridgeClientError};

pub(crate) fn rpc_error(status: &tonic::Status) -> SuiBridgeClientError {
    SuiBridgeClientError::RpcError(format!("{}: {}", status.code(), status.message()))
}

/// Fetch a transaction by base58 digest; `Ok(None)` if the node doesn't know
/// it (yet).
pub(crate) async fn get_transaction_opt(
    client: &mut Client,
    digest: &str,
    paths: &[&str],
) -> Result<Option<ExecutedTransaction>> {
    let request = GetTransactionRequest::default()
        .with_digest(digest)
        .with_read_mask(FieldMask::from_paths(paths));
    match client.ledger_client().get_transaction(request).await {
        Ok(response) => Ok(response.into_inner().transaction),
        Err(status) if status.code() == tonic::Code::NotFound => Ok(None),
        Err(status) => Err(rpc_error(&status)),
    }
}

pub(crate) async fn get_transaction(
    client: &mut Client,
    digest: &str,
    paths: &[&str],
) -> Result<ExecutedTransaction> {
    get_transaction_opt(client, digest, paths)
        .await?
        .ok_or_else(|| {
            SuiBridgeClientError::BlockchainDataError(format!("transaction {digest} not found"))
        })
}

pub(crate) async fn get_object(
    client: &mut Client,
    object_id: &str,
    paths: &[&str],
) -> Result<Object> {
    let request = GetObjectRequest::default()
        .with_object_id(object_id)
        .with_read_mask(FieldMask::from_paths(paths));
    let response = client
        .ledger_client()
        .get_object(request)
        .await
        .map_err(|status| rpc_error(&status))?;
    response.into_inner().object.ok_or_else(|| {
        SuiBridgeClientError::BlockchainDataError(format!("object {object_id} not found"))
    })
}
