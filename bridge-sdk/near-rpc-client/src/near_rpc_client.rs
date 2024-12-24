use crate::error::NearRpcError;
use crate::light_client_proof::LightClientExecutionProof;
use lazy_static::lazy_static;
use near_jsonrpc_client::{methods, JsonRpcClient, JsonRpcClientConnector};
use near_jsonrpc_primitives::types::query::QueryResponseKind;
use near_jsonrpc_primitives::types::transactions::TransactionInfo;
use near_primitives::hash::CryptoHash;
use near_primitives::transaction::{Action, FunctionCallAction, Transaction};
use near_primitives::types::{AccountId, BlockReference, Finality, FunctionArgs};
use near_primitives::views::{FinalExecutionOutcomeView, QueryRequest};
use reqwest::header::{HeaderMap, HeaderValue, CONTENT_TYPE};
use tokio::time;

pub const DEFAULT_WAIT_FINAL_OUTCOME_TIMEOUT_SEC: u64 = 500;

lazy_static! {
    static ref DEFAULT_CONNECTOR: JsonRpcClientConnector = JsonRpcClient::with(
        new_near_rpc_client(Some(std::time::Duration::from_secs(30)))
    );
}

#[derive(Clone)]
pub struct ViewRequest {
    pub contract_account_id: AccountId,
    pub method_name: String,
    pub args: serde_json::Value,
}

#[derive(Clone)]
pub struct ChangeRequest {
    pub signer: near_crypto::InMemorySigner,
    pub receiver_id: String,
    pub method_name: String,
    pub args: Vec<u8>,
    pub gas: u64,
    pub deposit: u128,
}

fn new_near_rpc_client(timeout: Option<std::time::Duration>) -> reqwest::Client {
    let mut headers = HeaderMap::with_capacity(2);
    headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));

    let mut builder = reqwest::Client::builder().default_headers(headers);
    if let Some(timeout) = timeout {
        builder = builder.timeout(timeout).connect_timeout(timeout);
    }
    builder.build().unwrap()
}

pub async fn view(server_addr: &str, view_request: ViewRequest) -> Result<Vec<u8>, NearRpcError> {
    let client = DEFAULT_CONNECTOR.connect(server_addr);
    let request = methods::query::RpcQueryRequest {
        block_reference: BlockReference::Finality(Finality::Final),
        request: QueryRequest::CallFunction {
            account_id: view_request.contract_account_id,
            method_name: view_request.method_name,
            args: FunctionArgs::from(view_request.args.to_string().into_bytes()),
        },
    };

    let response = client.call(request).await?;
    if let QueryResponseKind::CallResult(result) = response.kind {
        Ok(result.result)
    } else {
        Err(NearRpcError::ResultError)
    }
}

pub async fn get_light_client_proof(
    server_addr: &str,
    id: near_primitives::types::TransactionOrReceiptId,
    light_client_head: CryptoHash,
) -> Result<LightClientExecutionProof, NearRpcError> {
    let client = DEFAULT_CONNECTOR.connect(server_addr);

    let request =
        near_jsonrpc_client::methods::light_client_proof::RpcLightClientExecutionProofRequest {
            id,
            light_client_head,
        };

    Ok(client.call(request).await?.into())
}

pub async fn get_final_block_timestamp(server_addr: &str) -> Result<u64, NearRpcError> {
    let client = DEFAULT_CONNECTOR.connect(server_addr);
    let request = methods::block::RpcBlockRequest {
        block_reference: BlockReference::Finality(Finality::Final),
    };

    let block_info = client.call(request).await?;
    Ok(block_info.header.timestamp)
}

pub async fn get_last_near_block_height(server_addr: &str) -> Result<u64, NearRpcError> {
    let client = DEFAULT_CONNECTOR.connect(server_addr);
    let request = methods::block::RpcBlockRequest {
        block_reference: BlockReference::latest(),
    };

    let block_info = client.call(request).await?;
    Ok(block_info.header.height)
}

pub async fn get_block(
    server_addr: &str,
    block_reference: BlockReference,
) -> Result<near_primitives::views::BlockView, NearRpcError> {
    let client = DEFAULT_CONNECTOR.connect(server_addr);
    let request = methods::block::RpcBlockRequest { block_reference };
    let block_info = client.call(request).await?;
    Ok(block_info)
}

pub async fn change(
    server_addr: &str,
    change_request: ChangeRequest,
) -> Result<CryptoHash, NearRpcError> {
    let client = DEFAULT_CONNECTOR.connect(server_addr);
    let rpc_request = methods::query::RpcQueryRequest {
        block_reference: BlockReference::latest(),
        request: near_primitives::views::QueryRequest::ViewAccessKey {
            account_id: change_request.signer.account_id.clone(),
            public_key: change_request.signer.public_key.clone(),
        },
    };
    let access_key_query_response = client.call(rpc_request).await?;

    let current_nonce = match access_key_query_response.kind {
        QueryResponseKind::AccessKey(access_key) => access_key.nonce,
        _ => Err(NearRpcError::NonceError)?,
    };
    let transaction = Transaction {
        signer_id: change_request.signer.account_id.clone(),
        public_key: change_request.signer.public_key.clone(),
        nonce: current_nonce + 1,
        receiver_id: change_request.receiver_id.parse().unwrap(),
        block_hash: access_key_query_response.block_hash,
        actions: vec![Action::FunctionCall(Box::new(FunctionCallAction {
            method_name: change_request.method_name,
            args: change_request.args,
            gas: change_request.gas,
            deposit: change_request.deposit,
        }))],
    };
    let request = methods::broadcast_tx_async::RpcBroadcastTxAsyncRequest {
        signed_transaction: transaction.sign(&change_request.signer),
    };

    Ok(client.call(request).await?)
}

pub async fn change_and_wait(
    server_addr: &str,
    change_request: ChangeRequest,
    wait_until: near_primitives::views::TxExecutionStatus,
) -> Result<CryptoHash, NearRpcError> {
    let tx_hash = change(server_addr, change_request.clone()).await?;

    wait_for_tx(
        server_addr,
        tx_hash,
        change_request.signer.account_id,
        wait_until,
        DEFAULT_WAIT_FINAL_OUTCOME_TIMEOUT_SEC,
    )
    .await
}

pub async fn wait_for_tx(
    server_addr: &str,
    hash: CryptoHash,
    account_id: AccountId,
    wait_until: near_primitives::views::TxExecutionStatus,
    timeout_sec: u64,
) -> Result<CryptoHash, NearRpcError> {
    let client = DEFAULT_CONNECTOR.connect(server_addr);
    let sent_at = time::Instant::now();
    let tx_info = TransactionInfo::TransactionId {
        tx_hash: hash,
        sender_account_id: account_id,
    };

    loop {
        let response = client
            .call(methods::tx::RpcTransactionStatusRequest {
                transaction_info: tx_info.clone(),
                wait_until: wait_until.clone(),
            })
            .await;

        let delta = (time::Instant::now() - sent_at).as_secs();
        if delta > timeout_sec {
            Err(NearRpcError::FinalizationError)?;
        }

        match response {
            Ok(_) => return Ok(hash),
            Err(err) => match err.handler_error() {
                Some(_err) => {
                    time::sleep(time::Duration::from_secs(2)).await;
                    continue;
                }
                _ => Err(NearRpcError::RpcTransactionError(err))?,
            },
        }
    }
}

pub async fn get_tx_final_outcome(
    server_addr: &str,
    hash: CryptoHash,
    account_id: AccountId,
) -> Result<FinalExecutionOutcomeView, NearRpcError> {
    let client = DEFAULT_CONNECTOR.connect(server_addr);

    let tx_info = TransactionInfo::TransactionId {
        tx_hash: hash,
        sender_account_id: account_id,
    };

    let response = client
        .call(methods::tx::RpcTransactionStatusRequest {
            transaction_info: tx_info.clone(),
            wait_until: near_primitives::views::TxExecutionStatus::Executed,
        })
        .await;

    match response {
        Ok(optional_outcome) => {
            if let Some(outcome) = optional_outcome.final_execution_outcome {
                Ok(outcome.into_outcome())
            } else {
                Err(NearRpcError::FinalizationError)
            }
        }
        Err(err) => match err.handler_error() {
            Some(_err) => Err(NearRpcError::FinalizationError),
            _ => Err(NearRpcError::RpcTransactionError(err)),
        },
    }
}
