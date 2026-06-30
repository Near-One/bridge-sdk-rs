use std::sync::LazyLock;

use crate::error::NearRpcError;
use crate::light_client_proof::LightClientExecutionProof;
use base64::Engine;
use near_jsonrpc_client::errors::{
    JsonRpcError, JsonRpcServerError, JsonRpcServerResponseStatusError,
};
use near_jsonrpc_client::{methods, JsonRpcClient, JsonRpcClientConnector};
use near_jsonrpc_primitives::types::query::QueryResponseKind;
use near_jsonrpc_primitives::types::transactions::TransactionInfo;
use near_primitives::hash::CryptoHash;
use near_primitives::transaction::{Action, FunctionCallAction, Transaction, TransactionV0};
use near_primitives::types::{AccountId, BlockReference, Finality, FunctionArgs};
use near_primitives::views::{FinalExecutionOutcomeView, QueryRequest};
use near_token::NearToken;
use reqwest::header::{HeaderMap, HeaderValue, CONTENT_TYPE};
use tokio::time;

pub const DEFAULT_WAIT_FINAL_OUTCOME_TIMEOUT_SEC: u64 = 500;

static DEFAULT_CONNECTOR: LazyLock<JsonRpcClientConnector> = LazyLock::new(|| {
    JsonRpcClient::with(new_near_rpc_client(Some(std::time::Duration::from_secs(
        30,
    ))))
});

#[derive(Clone)]
pub struct ViewRequest {
    pub contract_account_id: AccountId,
    pub method_name: String,
    pub args: serde_json::Value,
}

/// Identity used to build a NEAR transaction.
///
/// `InMemory` holds a secret key: transactions are signed and broadcast as usual.
/// `DryRun` holds only a public identity (account id + public key, e.g. of a
/// hardware wallet). Transactions built with it are printed as an unsigned
/// payload for external signing instead of being signed and broadcast.
#[derive(Clone)]
pub enum TxSigner {
    InMemory(near_crypto::InMemorySigner),
    DryRun {
        account_id: AccountId,
        public_key: near_crypto::PublicKey,
    },
}

impl TxSigner {
    #[must_use]
    pub fn account_id(&self) -> AccountId {
        match self {
            Self::InMemory(signer) => signer.account_id.clone(),
            Self::DryRun { account_id, .. } => account_id.clone(),
        }
    }

    #[must_use]
    pub fn public_key(&self) -> near_crypto::PublicKey {
        match self {
            Self::InMemory(signer) => signer.public_key.clone(),
            Self::DryRun { public_key, .. } => public_key.clone(),
        }
    }

    #[must_use]
    pub fn is_dry_run(&self) -> bool {
        matches!(self, Self::DryRun { .. })
    }
}

#[derive(Clone)]
pub struct ChangeRequest {
    pub signer: TxSigner,
    pub nonce: Option<u64>,
    pub receiver_id: AccountId,
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

/// Returns the result of the view call
///
/// # Errors
/// Returns an error if the view call fails
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

/// Returns the light client proof
///
/// # Errors
/// Returns an error if the view call fails
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

/// Returns the final block timestamp
///
/// # Errors
/// Returns an error if the view call fails
pub async fn get_final_block_timestamp(server_addr: &str) -> Result<u64, NearRpcError> {
    let client = DEFAULT_CONNECTOR.connect(server_addr);
    let request = methods::block::RpcBlockRequest {
        block_reference: BlockReference::Finality(Finality::Final),
    };

    let block_info = client.call(request).await?;
    Ok(block_info.header.timestamp)
}

/// Returns the last block height
///
/// # Errors
/// Returns an error if the view call fails
pub async fn get_last_near_block_height(server_addr: &str) -> Result<u64, NearRpcError> {
    let client = DEFAULT_CONNECTOR.connect(server_addr);
    let request = methods::block::RpcBlockRequest {
        block_reference: BlockReference::latest(),
    };

    let block_info = client.call(request).await?;
    Ok(block_info.header.height)
}

/// Returns the block info by reference
///
/// # Errors
/// Returns an error if the view call fails
pub async fn get_block(
    server_addr: &str,
    block_reference: BlockReference,
) -> Result<near_primitives::views::BlockView, NearRpcError> {
    let client = DEFAULT_CONNECTOR.connect(server_addr);
    let request = methods::block::RpcBlockRequest { block_reference };
    let block_info = client.call(request).await?;
    Ok(block_info)
}

/// Calls the rpc method that requires change of the state
///
/// # Errors
/// Returns an error if the change call fails
pub async fn change(
    server_addr: &str,
    change_request: ChangeRequest,
) -> Result<CryptoHash, NearRpcError> {
    let client = DEFAULT_CONNECTOR.connect(server_addr);

    let signer_account_id = change_request.signer.account_id();
    let signer_public_key = change_request.signer.public_key();

    let rpc_request = methods::query::RpcQueryRequest {
        block_reference: BlockReference::latest(),
        request: QueryRequest::ViewAccessKey {
            account_id: signer_account_id.clone(),
            public_key: signer_public_key.clone(),
        },
    };

    let access_key_query_response = client.call(rpc_request).await.map_err(|err| {
        if let Some(near_jsonrpc_client::methods::query::RpcQueryError::UnknownAccessKey {
            ..
        }) = err.handler_error()
        {
            NearRpcError::UnknownAccessKey {
                account_id: signer_account_id.to_string(),
                public_key: signer_public_key.to_string(),
            }
        } else {
            NearRpcError::from(err)
        }
    })?;

    let nonce = if let Some(nonce) = change_request.nonce {
        nonce
    } else {
        let current_nonce = match access_key_query_response.kind {
            QueryResponseKind::AccessKey(access_key) => access_key.nonce,
            _ => Err(NearRpcError::NonceError)?,
        };

        current_nonce + 1
    };

    let transaction = Transaction::V0(TransactionV0 {
        signer_id: signer_account_id,
        public_key: signer_public_key,
        nonce,
        receiver_id: change_request.receiver_id,
        block_hash: access_key_query_response.block_hash,
        actions: vec![Action::FunctionCall(Box::new(FunctionCallAction {
            method_name: change_request.method_name,
            args: change_request.args,
            gas: near_primitives::gas::Gas::from_gas(change_request.gas),
            deposit: NearToken::from_yoctonear(change_request.deposit),
        }))],
    });

    match change_request.signer {
        // Dry run: print the unsigned transaction for external signing (e.g. a
        // hardware wallet) instead of signing and broadcasting it.
        TxSigner::DryRun { .. } => print_unsigned_transaction(&transaction),
        TxSigner::InMemory(signer) => {
            let request = methods::broadcast_tx_async::RpcBroadcastTxAsyncRequest {
                signed_transaction: transaction.sign(&near_crypto::Signer::InMemory(signer)),
            };

            Ok(client.call(request).await?)
        }
    }
}

/// Serializes the unsigned transaction (borsh + base64) and prints it together
/// with a human-readable summary, so it can be signed offline. Returns the hash
/// of the unsigned transaction (which equals the signed transaction hash, since
/// the signature is not part of the hashed payload).
fn print_unsigned_transaction(transaction: &Transaction) -> Result<CryptoHash, NearRpcError> {
    let tx_bytes = borsh::to_vec(transaction).map_err(|_| NearRpcError::SerializationError)?;
    let tx_hash = CryptoHash::hash_bytes(&tx_bytes);
    let base64_tx = base64::engine::general_purpose::STANDARD.encode(&tx_bytes);

    let (method_name, args, gas, deposit) = match transaction.actions().first() {
        Some(Action::FunctionCall(action)) => (
            action.method_name.as_str(),
            String::from_utf8_lossy(&action.args).into_owned(),
            action.gas.as_gas(),
            action.deposit.as_yoctonear(),
        ),
        _ => ("<unknown>", String::new(), 0u64, 0u128),
    };

    println!("========================================================================");
    println!("DRY RUN — transaction was NOT signed or broadcast");
    println!("========================================================================");
    println!("signer:      {}", transaction.signer_id());
    println!("public_key:  {}", transaction.public_key());
    println!("nonce:       {}", transaction.nonce());
    println!("receiver:    {}", transaction.receiver_id());
    println!("block_hash:  {}", transaction.block_hash());
    println!("method:      {method_name}");
    println!("gas:         {gas}");
    println!("deposit:     {deposit} yoctoNEAR");
    println!("args:        {args}");
    println!("tx_hash:     {tx_hash}");
    println!();
    println!("unsigned transaction (base64-encoded borsh):");
    println!("{base64_tx}");
    println!("------------------------------------------------------------------------");
    println!("Nothing was broadcast. Sign this payload externally (e.g. hardware");
    println!("wallet) and submit it. Ignore any \"Sent ...\" confirmation logged below.");
    println!("========================================================================");

    Ok(tx_hash)
}

/// Returns the result of the view call and waits for the desired outcome
///
/// # Errors
/// Returns an error if the view call fails
pub async fn change_and_wait(
    server_addr: &str,
    change_request: ChangeRequest,
    wait_until: near_primitives::views::TxExecutionStatus,
    wait_final_outcome_timeout_sec: Option<u64>,
) -> Result<CryptoHash, NearRpcError> {
    let is_dry_run = change_request.signer.is_dry_run();
    let signer_account_id = change_request.signer.account_id();

    let tx_hash = change(server_addr, change_request).await?;

    if is_dry_run {
        return Ok(tx_hash);
    }

    wait_for_tx(
        server_addr,
        tx_hash,
        signer_account_id,
        wait_until,
        wait_final_outcome_timeout_sec.unwrap_or(DEFAULT_WAIT_FINAL_OUTCOME_TIMEOUT_SEC),
    )
    .await
}

/// Returns the result of the view call and waits for the desired outcome
///
/// # Errors
/// Returns an error if the view call fails
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
            Err(err) => match err {
                JsonRpcError::ServerError(JsonRpcServerError::HandlerError(_))
                | near_jsonrpc_client::errors::JsonRpcError::ServerError(
                    JsonRpcServerError::ResponseStatusError(
                        JsonRpcServerResponseStatusError::TimeoutError,
                    ),
                ) => {
                    time::sleep(time::Duration::from_secs(2)).await;
                }
                _ => return Err(NearRpcError::RpcTransactionError(err)),
            },
        }
    }
}

/// Returns the final outcome of the transaction
///
/// # Errors
/// Returns an error if the view call fails
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
