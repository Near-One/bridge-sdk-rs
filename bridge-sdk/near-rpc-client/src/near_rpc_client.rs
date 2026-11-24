use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, LazyLock};

use crate::error::NearRpcError;
use crate::light_client_proof::LightClientExecutionProof;
use base64::Engine;
use near_jsonrpc_client::errors::{
    JsonRpcError, JsonRpcServerError, JsonRpcServerResponseStatusError,
};
use near_jsonrpc_client::methods::send_tx::RpcTransactionError;
use near_jsonrpc_client::{methods, JsonRpcClient, JsonRpcClientConnector};
use near_jsonrpc_primitives::types::query::QueryResponseKind;
use near_jsonrpc_primitives::types::transactions::TransactionInfo;
use near_primitives::hash::CryptoHash;
use near_primitives::transaction::{Action, FunctionCallAction, Transaction, TransactionV0};
use near_primitives::types::{AccountId, BlockReference, Finality, FunctionArgs};
use near_primitives::views::{
    ExecutionStatusView, FinalExecutionOutcomeView, FinalExecutionOutcomeViewEnum,
    FinalExecutionStatus, QueryRequest,
};
use near_token::NearToken;
use reqwest::header::{HeaderMap, HeaderValue, CONTENT_TYPE};
use tokio::time;

pub const DEFAULT_WAIT_FINAL_OUTCOME_TIMEOUT_SEC: u64 = 500;

/// How many times [`change`] re-signs a transaction after an `InvalidNonce`
/// rejection before it returns the error.
pub const MAX_INVALID_NONCE_RETRIES: usize = 3;

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

/// Hands out nonces for transactions that one process signs with one access key.
///
/// Use it when many tasks send transactions with the same key at the same time.
/// [`change`] calls [`NonceSource::reserve_nonce`] only after all slow I/O of the
/// caller is done, right before it signs. A transaction that waits for a proof
/// therefore holds no nonce, and faster transactions cannot make it stale.
pub trait NonceSource: Send + Sync {
    /// Returns the nonce for a transaction that is about to be signed.
    ///
    /// `access_key_nonce` is the newest on-chain nonce of the access key that the
    /// SDK knows: from the access-key query, or from the `ak_nonce` of an
    /// `InvalidNonce` rejection. The result must be greater than
    /// `access_key_nonce`, and no two calls may return the same value.
    fn reserve_nonce(&self, access_key_nonce: u64) -> u64;
}

/// Thread-safe in-process [`NonceSource`]. Each call returns
/// `max(previous + 1, access_key_nonce + 1)`, so the counter resyncs with the
/// chain whenever the chain is ahead.
#[derive(Debug, Default)]
pub struct NonceCounter {
    last: AtomicU64,
}

impl NonceCounter {
    /// Creates a counter whose first nonce is at least `last_used + 1`.
    #[must_use]
    pub const fn new(last_used: u64) -> Self {
        Self {
            last: AtomicU64::new(last_used),
        }
    }

    /// Last nonce this counter returned (or the start value).
    #[must_use]
    pub fn last_used(&self) -> u64 {
        self.last.load(Ordering::SeqCst)
    }
}

impl NonceSource for NonceCounter {
    fn reserve_nonce(&self, access_key_nonce: u64) -> u64 {
        let next = |last: u64| last.max(access_key_nonce).saturating_add(1);
        // `fetch_update` returns the previous value; the closure never returns `None`.
        let previous = self
            .last
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |last| Some(next(last)))
            .unwrap_or_else(|last| last);
        next(previous)
    }
}

/// How [`change`] picks the nonce of a transaction.
#[derive(Clone, Default)]
pub enum NonceStrategy {
    /// Access-key nonce + 1, from the access-key query that [`change`] sends.
    /// On `InvalidNonce`, may re-sign with the `ak_nonce` from the error + 1
    /// (see [`change`]).
    #[default]
    AccessKey,
    /// Exactly this nonce. Never retried: the caller owns the nonce.
    Fixed(u64),
    /// Reserved from the source right before signing. On `InvalidNonce`, may
    /// reserve a new nonce from the source and re-sign (see [`change`]).
    Source(Arc<dyn NonceSource>),
}

impl NonceStrategy {
    /// The nonce for [`NonceStrategy::Fixed`], `None` for the other strategies.
    #[must_use]
    pub const fn fixed(&self) -> Option<u64> {
        match self {
            Self::Fixed(nonce) => Some(*nonce),
            Self::AccessKey | Self::Source(_) => None,
        }
    }

    fn nonce(&self, access_key_nonce: u64) -> u64 {
        match self {
            Self::AccessKey => access_key_nonce.saturating_add(1),
            Self::Fixed(nonce) => *nonce,
            Self::Source(source) => source.reserve_nonce(access_key_nonce),
        }
    }

    const fn retries_invalid_nonce(&self) -> bool {
        match self {
            Self::AccessKey | Self::Source(_) => true,
            Self::Fixed(_) => false,
        }
    }
}

impl std::fmt::Debug for NonceStrategy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AccessKey => f.write_str("AccessKey"),
            Self::Fixed(nonce) => f.debug_tuple("Fixed").field(nonce).finish(),
            Self::Source(_) => f.write_str("Source(..)"),
        }
    }
}

impl From<u64> for NonceStrategy {
    fn from(nonce: u64) -> Self {
        Self::Fixed(nonce)
    }
}

impl From<Option<u64>> for NonceStrategy {
    fn from(nonce: Option<u64>) -> Self {
        nonce.map_or(Self::AccessKey, Self::Fixed)
    }
}

impl From<Arc<dyn NonceSource>> for NonceStrategy {
    fn from(source: Arc<dyn NonceSource>) -> Self {
        Self::Source(source)
    }
}

#[derive(Clone)]
pub struct ChangeRequest {
    pub signer: TxSigner,
    pub nonce: NonceStrategy,
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
        // Connecting should still fail fast even when the overall timeout is long.
        let connect_timeout = std::cmp::min(timeout, std::time::Duration::from_secs(10));
        builder = builder.timeout(timeout).connect_timeout(connect_timeout);
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
/// With [`NonceStrategy::AccessKey`] or [`NonceStrategy::Source`], an
/// `InvalidNonce` rejection is handled as follows. If the rejected transaction
/// is already on chain (a duplicate send), its hash is returned. Otherwise the
/// same actions are re-signed with a new nonce, up to
/// [`MAX_INVALID_NONCE_RETRIES`] times. The error is returned instead when the
/// status check fails or when `tx_nonce == ak_nonce`, because then a
/// transaction with exactly this nonce landed, most likely this one.
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

    let QueryResponseKind::AccessKey(access_key) = access_key_query_response.kind else {
        return Err(NearRpcError::NonceError);
    };
    let block_hash = access_key_query_response.block_hash;
    let actions = vec![Action::FunctionCall(Box::new(FunctionCallAction {
        method_name: change_request.method_name,
        args: change_request.args,
        gas: near_primitives::gas::Gas::from_gas(change_request.gas),
        deposit: NearToken::from_yoctonear(change_request.deposit),
    }))];

    let mut access_key_nonce = access_key.nonce;
    let mut retries = 0;
    loop {
        // Reserve the nonce only now: all slow I/O of the caller is done.
        let nonce = change_request.nonce.nonce(access_key_nonce);

        let transaction = Transaction::V0(TransactionV0 {
            signer_id: signer_account_id.clone(),
            public_key: signer_public_key.clone(),
            nonce,
            receiver_id: change_request.receiver_id.clone(),
            block_hash,
            actions: actions.clone(),
        });

        let signer = match &change_request.signer {
            // Dry run: print the unsigned transaction for external signing (e.g. a
            // hardware wallet) instead of signing and broadcasting it.
            TxSigner::DryRun { .. } => return print_unsigned_transaction(&transaction),
            TxSigner::InMemory(signer) => signer,
        };

        let signed_transaction = transaction.sign(&near_crypto::Signer::InMemory(signer.clone()));
        let tx_hash = signed_transaction.get_hash();

        tracing::debug!(
            tx_hash = tx_hash.to_string(),
            nonce,
            "Broadcasting NEAR transaction"
        );

        // Unlike `broadcast_tx_async`, `send_tx` reports transaction-pool
        // rejections to the caller instead of silently dropping the transaction.
        let result = client
            .call(methods::send_tx::RpcSendTransactionRequest {
                signed_transaction,
                wait_until: near_primitives::views::TxExecutionStatus::Included,
            })
            .await;

        let err = match result {
            Ok(_) => return Ok(tx_hash),
            Err(err) => err,
        };

        // `InvalidNonce` means the access-key nonce already reached `tx_nonce`,
        // so this signed transaction can never be included from now on. It may
        // still be what moved the nonce: a proxy may re-send a request whose
        // first copy was accepted, and the duplicate then fails with
        // `InvalidNonce`. So check its status first, on every attempt. Timeouts
        // and transport errors are never retried: the transaction may still land.
        let Some((tx_nonce, ak_nonce)) = invalid_nonce(&err) else {
            return Err(err.into());
        };
        if !change_request.nonce.retries_invalid_nonce() {
            return Err(err.into());
        }

        match transaction_exists(&client, tx_hash, signer_account_id.clone()).await {
            Ok(true) => {
                tracing::info!(
                    tx_hash = tx_hash.to_string(),
                    tx_nonce,
                    ak_nonce,
                    "NEAR transaction reported InvalidNonce but is already on chain"
                );
                return Ok(tx_hash);
            }
            Ok(false) => {}
            Err(status_err) => {
                tracing::warn!(
                    tx_hash = tx_hash.to_string(),
                    error = %status_err,
                    "Could not check NEAR transaction after InvalidNonce, not re-signing"
                );
                return Err(err.into());
            }
        }

        // A load-balanced RPC can answer the status query from a node that has
        // not seen the transaction yet. `tx_nonce == ak_nonce` means a
        // transaction with exactly this nonce landed, most likely this one, so
        // do not re-sign a copy that could execute the actions twice. The
        // caller can retry later, when the status is visible.
        if tx_nonce == ak_nonce {
            tracing::warn!(
                tx_hash = tx_hash.to_string(),
                tx_nonce,
                ak_nonce,
                "NEAR transaction rejected with InvalidNonce for its own nonce, not re-signing: it may be a duplicate that is not visible yet"
            );
            return Err(err.into());
        }

        if retries == MAX_INVALID_NONCE_RETRIES {
            return Err(err.into());
        }
        retries += 1;
        tracing::info!(
            tx_hash = tx_hash.to_string(),
            tx_nonce,
            ak_nonce,
            retry = retries,
            "NEAR transaction rejected with InvalidNonce, re-signing with a new nonce"
        );
        access_key_nonce = access_key_nonce.max(ak_nonce);
    }
}

/// Whether the transaction `tx_hash` is on chain. Returns an error when the node
/// cannot tell.
async fn transaction_exists(
    client: &JsonRpcClient,
    tx_hash: CryptoHash,
    sender_account_id: AccountId,
) -> Result<bool, NearRpcError> {
    let response = client
        .call(methods::tx::RpcTransactionStatusRequest {
            transaction_info: TransactionInfo::TransactionId {
                tx_hash,
                sender_account_id,
            },
            wait_until: near_primitives::views::TxExecutionStatus::None,
        })
        .await;

    match response {
        // `NONE` does not confirm inclusion: a node that does not track the
        // signer's shard only forwards the query and replies `NONE`.
        Ok(response)
            if matches!(
                response.final_execution_status,
                near_primitives::views::TxExecutionStatus::None
            ) =>
        {
            tracing::debug!(
                tx_hash = tx_hash.to_string(),
                "NEAR transaction status is NONE, inclusion not confirmed"
            );
            Err(NearRpcError::ResultError)
        }
        Ok(_) => Ok(true),
        Err(err)
            if matches!(
                err.handler_error(),
                Some(RpcTransactionError::UnknownTransaction { .. })
            ) =>
        {
            Ok(false)
        }
        Err(err) => Err(err.into()),
    }
}

/// `(tx_nonce, ak_nonce)` when the node rejected the transaction because its
/// nonce is not greater than the access-key nonce.
pub(crate) fn invalid_nonce(
    err: &near_jsonrpc_client::errors::JsonRpcError<RpcTransactionError>,
) -> Option<(u64, u64)> {
    match err.handler_error()? {
        RpcTransactionError::InvalidTransaction {
            context: near_primitives::errors::InvalidTxError::InvalidNonce { tx_nonce, ak_nonce },
        } => Some((*tx_nonce, *ak_nonce)),
        _ => None,
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
            Ok(outcome) => {
                warn_on_failed_receipts(hash, outcome.final_execution_outcome);
                return Ok(hash);
            }
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

/// A callback panic leaves the transaction status as success while an inner
/// receipt fails. Warns rather than errors: some flows fail a receipt on purpose
/// and handle it in a callback.
fn warn_on_failed_receipts(hash: CryptoHash, outcome: Option<FinalExecutionOutcomeViewEnum>) {
    let Some(outcome) = outcome else {
        return;
    };
    let outcome = outcome.into_outcome();

    if let FinalExecutionStatus::Failure(err) = &outcome.status {
        tracing::warn!(tx_hash = %hash, error = ?err, "NEAR transaction failed");
        return;
    }

    for receipt in &outcome.receipts_outcome {
        if let ExecutionStatusView::Failure(err) = &receipt.outcome.status {
            tracing::warn!(
                tx_hash = %hash,
                receipt_id = %receipt.id,
                executor = %receipt.outcome.executor_id,
                error = ?err,
                "NEAR receipt failed while the transaction reports success"
            );
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn access_key_strategy_uses_next_nonce() {
        assert_eq!(NonceStrategy::AccessKey.nonce(41), 42);
        assert!(NonceStrategy::AccessKey.retries_invalid_nonce());
    }

    #[test]
    fn fixed_strategy_ignores_access_key_and_is_not_retried() {
        let strategy = NonceStrategy::from(Some(7));
        assert_eq!(strategy.nonce(100), 7);
        assert_eq!(strategy.fixed(), Some(7));
        assert!(!strategy.retries_invalid_nonce());
        assert!(matches!(
            NonceStrategy::from(None),
            NonceStrategy::AccessKey
        ));
    }

    #[test]
    fn counter_hands_out_unique_increasing_nonces() {
        let counter = NonceCounter::new(10);
        assert_eq!(counter.reserve_nonce(0), 11);
        assert_eq!(counter.reserve_nonce(0), 12);
        assert_eq!(counter.last_used(), 12);
    }

    #[test]
    fn counter_resyncs_when_chain_is_ahead() {
        let counter = NonceCounter::new(10);
        assert_eq!(counter.reserve_nonce(35), 36);
        // Stale access-key nonce must not move the counter back.
        assert_eq!(counter.reserve_nonce(20), 37);
    }

    #[test]
    fn source_strategy_reserves_from_source_and_is_retried() {
        let counter: Arc<dyn NonceSource> = Arc::new(NonceCounter::new(5));
        let strategy = NonceStrategy::from(counter);
        assert_eq!(strategy.nonce(0), 6);
        assert_eq!(strategy.nonce(9), 10);
        assert_eq!(strategy.fixed(), None);
        assert!(strategy.retries_invalid_nonce());
        assert_eq!(format!("{strategy:?}"), "Source(..)");
    }

    mod mock_rpc {
        use super::super::*;
        use near_crypto::{InMemorySigner, KeyType, Signer};
        use serde_json::{json, Value};
        use std::sync::Mutex;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        const ACCESS_KEY_NONCE: u64 = 100;

        pub fn invalid_nonce(tx_nonce: u64, ak_nonce: u64) -> Value {
            json!({ "error": {
                "name": "HANDLER_ERROR",
                "cause": { "name": "INVALID_TRANSACTION", "info": {} },
                "code": -32000,
                "message": "Server error",
                "data": { "TxExecutionError": { "InvalidTxError": {
                    "InvalidNonce": { "tx_nonce": tx_nonce, "ak_nonce": ak_nonce }
                } } }
            } })
        }

        pub fn timeout() -> Value {
            json!({ "error": {
                "name": "HANDLER_ERROR",
                "cause": { "name": "TIMEOUT_ERROR" },
                "code": -32000,
                "message": "Server error",
                "data": "Timeout"
            } })
        }

        pub fn included() -> Value {
            json!({ "result": { "final_execution_status": "INCLUDED" } })
        }

        /// Minimal NEAR JSON-RPC: answers `query` with an access key and
        /// `send_tx` with the scripted replies (the last one repeats).
        pub struct MockRpc {
            send_tx_replies: Vec<Value>,
            sent: Mutex<Vec<(u64, CryptoHash)>>,
            /// Replies to successive `tx` status queries (the last one repeats);
            /// `None` or an empty list means "unknown transaction".
            tx_status_replies: Vec<Option<Value>>,
            tx_status_queries: Mutex<Vec<CryptoHash>>,
        }

        impl MockRpc {
            pub async fn start(send_tx_replies: Vec<Value>) -> (Arc<Self>, String) {
                Self::start_with_tx_status(send_tx_replies, Vec::new()).await
            }

            pub async fn start_with_tx_status(
                send_tx_replies: Vec<Value>,
                tx_status_replies: Vec<Option<Value>>,
            ) -> (Arc<Self>, String) {
                let mock = Arc::new(Self {
                    send_tx_replies,
                    sent: Mutex::new(Vec::new()),
                    tx_status_replies,
                    tx_status_queries: Mutex::new(Vec::new()),
                });
                let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
                let addr = format!("http://{}", listener.local_addr().unwrap());
                let server = Arc::clone(&mock);
                tokio::spawn(async move {
                    loop {
                        let (socket, _) = listener.accept().await.unwrap();
                        tokio::spawn(Arc::clone(&server).serve(socket));
                    }
                });
                (mock, addr)
            }

            pub fn sent_nonces(&self) -> Vec<u64> {
                self.sent.lock().unwrap().iter().map(|(n, _)| *n).collect()
            }

            pub fn sent_hashes(&self) -> Vec<CryptoHash> {
                self.sent.lock().unwrap().iter().map(|(_, h)| *h).collect()
            }

            pub fn tx_status_queries(&self) -> Vec<CryptoHash> {
                self.tx_status_queries.lock().unwrap().clone()
            }

            fn reply(&self, request: &Value) -> Value {
                let mut reply = match request["method"].as_str() {
                    Some("query") => json!({ "result": {
                        "nonce": ACCESS_KEY_NONCE,
                        "permission": "FullAccess",
                        "block_height": 1,
                        "block_hash": CryptoHash::default().to_string(),
                    } }),
                    Some("send_tx") => {
                        let request: methods::send_tx::RpcSendTransactionRequest =
                            serde_json::from_value(request["params"].clone()).unwrap();
                        let tx = request.signed_transaction;
                        let mut sent = self.sent.lock().unwrap();
                        sent.push((tx.transaction.nonce(), tx.get_hash()));
                        let index = (sent.len() - 1).min(self.send_tx_replies.len() - 1);
                        self.send_tx_replies[index].clone()
                    }
                    Some("tx") => {
                        let tx_hash: CryptoHash =
                            serde_json::from_value(request["params"]["tx_hash"].clone()).unwrap();
                        let mut queries = self.tx_status_queries.lock().unwrap();
                        queries.push(tx_hash);
                        let reply = match self.tx_status_replies.len() {
                            0 => None,
                            len => self.tx_status_replies[(queries.len() - 1).min(len - 1)].clone(),
                        };
                        reply.unwrap_or_else(|| {
                            json!({ "error": {
                                "name": "HANDLER_ERROR",
                                "cause": {
                                    "name": "UNKNOWN_TRANSACTION",
                                    "info": { "requested_transaction_hash": tx_hash.to_string() }
                                },
                                "code": -32000,
                                "message": "Server error",
                                "data": format!("Transaction {tx_hash} doesn't exist")
                            } })
                        })
                    }
                    other => panic!("unexpected method {other:?}"),
                };
                reply["jsonrpc"] = json!("2.0");
                reply["id"] = request["id"].clone();
                reply
            }

            async fn serve(self: Arc<Self>, mut socket: tokio::net::TcpStream) {
                let mut buf = Vec::new();
                loop {
                    let header_end = loop {
                        if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                            break pos + 4;
                        }
                        if socket.read_buf(&mut buf).await.unwrap_or(0) == 0 {
                            return;
                        }
                    };
                    let headers = String::from_utf8_lossy(&buf[..header_end]).to_lowercase();
                    let body_len: usize = headers
                        .lines()
                        .find_map(|line| line.strip_prefix("content-length:"))
                        .map_or(0, |len| len.trim().parse().unwrap());
                    while buf.len() < header_end + body_len {
                        if socket.read_buf(&mut buf).await.unwrap_or(0) == 0 {
                            return;
                        }
                    }
                    let request: Value =
                        serde_json::from_slice(&buf[header_end..header_end + body_len]).unwrap();
                    buf.drain(..header_end + body_len);

                    let body = self.reply(&request).to_string();
                    let response = format!(
                        "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n{body}",
                        body.len()
                    );
                    if socket.write_all(response.as_bytes()).await.is_err() {
                        return;
                    }
                }
            }
        }

        pub fn change_request(nonce: NonceStrategy) -> ChangeRequest {
            let account_id: AccountId = "relayer.near".parse().unwrap();
            let Signer::InMemory(signer) =
                InMemorySigner::from_seed(account_id, KeyType::ED25519, "relayer")
            else {
                unreachable!()
            };
            ChangeRequest {
                signer: TxSigner::InMemory(signer),
                nonce,
                receiver_id: "bridge.near".parse().unwrap(),
                method_name: "fin_transfer".to_string(),
                args: b"{}".to_vec(),
                gas: 1,
                deposit: 0,
            }
        }
    }

    #[tokio::test]
    async fn source_strategy_reserves_after_access_key_query_and_resigns_on_invalid_nonce() {
        use mock_rpc::*;
        let (rpc, addr) = MockRpc::start(vec![invalid_nonce(101, 105), included()]).await;
        let counter = Arc::new(NonceCounter::new(0));

        let tx_hash = change(
            &addr,
            change_request(NonceStrategy::Source(counter.clone())),
        )
        .await
        .unwrap();

        // 101 = access-key nonce 100 + 1; 106 = `ak_nonce` 105 from the error + 1.
        assert_eq!(rpc.sent_nonces(), vec![101, 106]);
        assert_eq!(rpc.sent_hashes().last(), Some(&tx_hash));
        assert_eq!(counter.last_used(), 106);
        // The rejected transaction was checked before re-signing.
        assert_eq!(rpc.tx_status_queries(), vec![rpc.sent_hashes()[0]]);
    }

    #[tokio::test]
    async fn invalid_nonce_for_landed_transaction_is_not_resigned() {
        use mock_rpc::*;
        let landed = serde_json::json!({ "result": { "final_execution_status": "EXECUTED" } });
        let (rpc, addr) = MockRpc::start_with_tx_status(
            vec![invalid_nonce(101, 101), included()],
            vec![Some(landed)],
        )
        .await;
        let counter: Arc<dyn NonceSource> = Arc::new(NonceCounter::new(0));

        let tx_hash = change(&addr, change_request(NonceStrategy::Source(counter)))
            .await
            .unwrap();

        assert_eq!(rpc.sent_nonces(), vec![101]);
        assert_eq!(rpc.sent_hashes(), vec![tx_hash]);
    }

    #[tokio::test]
    async fn source_strategy_does_not_resign_when_its_own_nonce_landed() {
        use mock_rpc::*;
        // Status query says "unknown", but `ak_nonce == tx_nonce`: the transaction
        // is probably on chain and not yet visible to the queried node.
        let (rpc, addr) = MockRpc::start(vec![invalid_nonce(101, 101), included()]).await;
        let counter: Arc<dyn NonceSource> = Arc::new(NonceCounter::new(0));

        let err = change(&addr, change_request(NonceStrategy::Source(counter)))
            .await
            .unwrap_err();

        assert_eq!(err.invalid_nonce(), Some((101, 101)));
        assert_eq!(rpc.sent_nonces(), vec![101]);
        assert_eq!(rpc.tx_status_queries().len(), 1);
    }

    #[tokio::test]
    async fn access_key_strategy_does_not_resign_when_nonce_equals_access_key_nonce() {
        use mock_rpc::*;
        // Same as for `Source`: the landed transaction is most likely this one.
        let (rpc, addr) = MockRpc::start(vec![invalid_nonce(101, 101), included()]).await;

        let err = change(&addr, change_request(NonceStrategy::AccessKey))
            .await
            .unwrap_err();

        assert_eq!(err.invalid_nonce(), Some((101, 101)));
        assert_eq!(rpc.sent_nonces(), vec![101]);
    }

    #[tokio::test]
    async fn invalid_nonce_is_not_resigned_when_status_check_fails() {
        use mock_rpc::*;
        let (rpc, addr) = MockRpc::start_with_tx_status(
            vec![invalid_nonce(101, 105), included()],
            vec![Some(timeout())],
        )
        .await;
        let counter: Arc<dyn NonceSource> = Arc::new(NonceCounter::new(0));

        let err = change(&addr, change_request(NonceStrategy::Source(counter)))
            .await
            .unwrap_err();

        assert_eq!(err.invalid_nonce(), Some((101, 105)));
        assert_eq!(rpc.sent_nonces(), vec![101]);
    }

    #[tokio::test]
    async fn status_none_is_not_treated_as_on_chain() {
        use mock_rpc::*;
        // A node that does not track the shard answers `NONE` for any hash.
        let not_tracked = serde_json::json!({ "result": { "final_execution_status": "NONE" } });
        let (rpc, addr) = MockRpc::start_with_tx_status(
            vec![invalid_nonce(101, 105), included()],
            vec![Some(not_tracked)],
        )
        .await;
        let counter: Arc<dyn NonceSource> = Arc::new(NonceCounter::new(0));

        let err = change(&addr, change_request(NonceStrategy::Source(counter)))
            .await
            .unwrap_err();

        assert_eq!(err.invalid_nonce(), Some((101, 105)));
        assert_eq!(rpc.sent_nonces(), vec![101]);
    }

    #[tokio::test]
    async fn access_key_strategy_resigns_on_invalid_nonce() {
        use mock_rpc::*;
        let (rpc, addr) = MockRpc::start(vec![invalid_nonce(101, 103), included()]).await;

        change(&addr, change_request(NonceStrategy::AccessKey))
            .await
            .unwrap();

        assert_eq!(rpc.sent_nonces(), vec![101, 104]);
    }

    #[tokio::test]
    async fn fixed_strategy_is_not_retried() {
        use mock_rpc::*;
        let (rpc, addr) = MockRpc::start(vec![invalid_nonce(7, 100), included()]).await;

        let err = change(&addr, change_request(NonceStrategy::Fixed(7)))
            .await
            .unwrap_err();

        assert_eq!(err.invalid_nonce(), Some((7, 100)));
        assert_eq!(rpc.sent_nonces(), vec![7]);
        assert!(rpc.tx_status_queries().is_empty());
    }

    #[tokio::test]
    async fn invalid_nonce_retries_are_capped() {
        use mock_rpc::*;
        let (rpc, addr) = MockRpc::start(vec![invalid_nonce(0, 200)]).await;
        let counter: Arc<dyn NonceSource> = Arc::new(NonceCounter::new(0));

        let err = change(&addr, change_request(NonceStrategy::Source(counter)))
            .await
            .unwrap_err();

        assert!(err.invalid_nonce().is_some());
        assert_eq!(rpc.sent_nonces().len(), 1 + MAX_INVALID_NONCE_RETRIES);
        // The last rejected copy is checked too.
        assert_eq!(rpc.tx_status_queries().len(), 1 + MAX_INVALID_NONCE_RETRIES);
    }

    #[tokio::test]
    async fn landed_transaction_is_detected_on_the_last_attempt() {
        use mock_rpc::*;
        let landed = serde_json::json!({ "result": { "final_execution_status": "EXECUTED" } });
        let mut tx_status = vec![None; MAX_INVALID_NONCE_RETRIES];
        tx_status.push(Some(landed));
        let (rpc, addr) =
            MockRpc::start_with_tx_status(vec![invalid_nonce(0, 200)], tx_status).await;
        let counter: Arc<dyn NonceSource> = Arc::new(NonceCounter::new(0));

        let tx_hash = change(&addr, change_request(NonceStrategy::Source(counter)))
            .await
            .unwrap();

        assert_eq!(rpc.sent_nonces().len(), 1 + MAX_INVALID_NONCE_RETRIES);
        assert_eq!(rpc.sent_hashes().last(), Some(&tx_hash));
    }

    #[tokio::test]
    async fn timeout_is_not_retried() {
        use mock_rpc::*;
        let (rpc, addr) = MockRpc::start(vec![timeout(), included()]).await;
        let counter: Arc<dyn NonceSource> = Arc::new(NonceCounter::new(0));

        let err = change(&addr, change_request(NonceStrategy::Source(counter)))
            .await
            .unwrap_err();

        assert!(err.invalid_nonce().is_none());
        assert_eq!(rpc.sent_nonces(), vec![101]);
    }

    #[test]
    fn counter_is_unique_across_threads() {
        let counter = Arc::new(NonceCounter::new(0));
        let handles: Vec<_> = (0..8)
            .map(|_| {
                let counter = Arc::clone(&counter);
                std::thread::spawn(move || {
                    (0..1000)
                        .map(|_| counter.reserve_nonce(0))
                        .collect::<Vec<_>>()
                })
            })
            .collect();
        let mut nonces: Vec<u64> = handles
            .into_iter()
            .flat_map(|handle| handle.join().unwrap())
            .collect();
        nonces.sort_unstable();
        nonces.dedup();
        assert_eq!(nonces.len(), 8000);
        assert_eq!(nonces.first(), Some(&1));
        assert_eq!(nonces.last(), Some(&8000));
    }
}
