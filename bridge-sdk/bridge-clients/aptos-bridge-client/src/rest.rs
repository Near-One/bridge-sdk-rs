//! Thin wrappers over the Aptos fullnode REST API (v1). The `base_url` is
//! expected to already include the `/v1` version segment.

use serde::Deserialize;

use crate::error::{AptosBridgeClientError, Result};

/// `GET /v1` — node ledger info. Used for the network chain id.
#[derive(Debug, Deserialize)]
pub struct LedgerInfo {
    pub chain_id: u8,
}

/// `GET /v1/accounts/{address}` — the bits we need to build a transaction.
#[derive(Debug, Deserialize)]
pub struct AccountInfo {
    pub sequence_number: String,
}

/// `GET /v1/estimate_gas_price`.
#[derive(Debug, Deserialize)]
pub struct GasEstimate {
    pub gas_estimate: u64,
}

/// `POST /v1/transactions` (pending tx) response — we only need the hash.
#[derive(Debug, Deserialize)]
pub struct PendingTransaction {
    pub hash: String,
}

/// `GET /v1/transactions/by_hash/{hash}`. Modelled leniently: `success` is
/// `Some` only once the transaction is committed (a pending tx omits it).
#[derive(Debug, Deserialize)]
pub struct CommittedTransaction {
    pub hash: String,
    #[serde(default)]
    pub success: Option<bool>,
    #[serde(default)]
    pub vm_status: Option<String>,
    #[serde(default)]
    pub events: Vec<TransactionEvent>,
}

#[derive(Debug, Deserialize)]
pub struct TransactionEvent {
    pub guid: EventGuid,
    pub sequence_number: String,
    #[serde(rename = "type")]
    pub event_type: String,
    pub data: serde_json::Value,
}

#[derive(Debug, Deserialize)]
pub struct EventGuid {
    pub account_address: String,
}

fn trim_base(base_url: &str) -> &str {
    base_url.trim_end_matches('/')
}

async fn error_body(response: reqwest::Response) -> AptosBridgeClientError {
    let status = response.status();
    let body = response.text().await.unwrap_or_default();
    AptosBridgeClientError::RestError(format!("HTTP {status}: {body}"))
}

pub async fn get_ledger_info(client: &reqwest::Client, base_url: &str) -> Result<LedgerInfo> {
    let response = client
        .get(trim_base(base_url))
        .send()
        .await
        .map_err(|e| AptosBridgeClientError::RestError(format!("ledger info request: {e}")))?;
    if !response.status().is_success() {
        return Err(error_body(response).await);
    }
    response
        .json()
        .await
        .map_err(|e| AptosBridgeClientError::RestError(format!("ledger info decode: {e}")))
}

pub async fn get_account_sequence_number(
    client: &reqwest::Client,
    base_url: &str,
    address_hex: &str,
) -> Result<u64> {
    let url = format!("{}/accounts/{address_hex}", trim_base(base_url));
    let response = client
        .get(&url)
        .send()
        .await
        .map_err(|e| AptosBridgeClientError::RestError(format!("account request: {e}")))?;
    if !response.status().is_success() {
        return Err(error_body(response).await);
    }
    let info: AccountInfo = response
        .json()
        .await
        .map_err(|e| AptosBridgeClientError::RestError(format!("account decode: {e}")))?;
    info.sequence_number.parse().map_err(|e| {
        AptosBridgeClientError::BlockchainDataError(format!(
            "invalid account sequence_number {:?}: {e}",
            info.sequence_number
        ))
    })
}

pub async fn estimate_gas_price(client: &reqwest::Client, base_url: &str) -> Result<u64> {
    let url = format!("{}/estimate_gas_price", trim_base(base_url));
    let response = client
        .get(&url)
        .send()
        .await
        .map_err(|e| AptosBridgeClientError::RestError(format!("gas price request: {e}")))?;
    if !response.status().is_success() {
        return Err(error_body(response).await);
    }
    let estimate: GasEstimate = response
        .json()
        .await
        .map_err(|e| AptosBridgeClientError::RestError(format!("gas price decode: {e}")))?;
    Ok(estimate.gas_estimate)
}

/// Submit a BCS-serialized `SignedTransaction`; returns the transaction hash.
pub async fn submit_bcs_transaction(
    client: &reqwest::Client,
    base_url: &str,
    signed_txn_bcs: Vec<u8>,
) -> Result<String> {
    let url = format!("{}/transactions", trim_base(base_url));
    let response = client
        .post(&url)
        .header(
            reqwest::header::CONTENT_TYPE,
            "application/x.aptos.signed_transaction+bcs",
        )
        .body(signed_txn_bcs)
        .send()
        .await
        .map_err(|e| AptosBridgeClientError::RestError(format!("submit request: {e}")))?;
    if !response.status().is_success() {
        return Err(error_body(response).await);
    }
    let pending: PendingTransaction = response
        .json()
        .await
        .map_err(|e| AptosBridgeClientError::RestError(format!("submit decode: {e}")))?;
    Ok(pending.hash)
}

/// `GET /v1/transactions/by_hash/{hash}`. Returns `Ok(None)` on 404 (not yet
/// indexed / pending), `Err` on other failures.
pub async fn get_transaction_by_hash(
    client: &reqwest::Client,
    base_url: &str,
    tx_hash: &str,
) -> Result<Option<CommittedTransaction>> {
    let url = format!("{}/transactions/by_hash/{tx_hash}", trim_base(base_url));
    let response = client
        .get(&url)
        .send()
        .await
        .map_err(|e| AptosBridgeClientError::RestError(format!("by_hash request: {e}")))?;
    if response.status() == reqwest::StatusCode::NOT_FOUND {
        return Ok(None);
    }
    if !response.status().is_success() {
        return Err(error_body(response).await);
    }
    let tx = response
        .json()
        .await
        .map_err(|e| AptosBridgeClientError::RestError(format!("by_hash decode: {e}")))?;
    Ok(Some(tx))
}

/// `POST /v1/view` — call a Move view function. Returns the JSON result array.
pub async fn view(
    client: &reqwest::Client,
    base_url: &str,
    function: &str,
    type_arguments: Vec<String>,
    arguments: Vec<serde_json::Value>,
) -> Result<Vec<serde_json::Value>> {
    let url = format!("{}/view", trim_base(base_url));
    let body = serde_json::json!({
        "function": function,
        "type_arguments": type_arguments,
        "arguments": arguments,
    });
    let response = client
        .post(&url)
        .json(&body)
        .send()
        .await
        .map_err(|e| AptosBridgeClientError::RestError(format!("view request: {e}")))?;
    if !response.status().is_success() {
        return Err(error_body(response).await);
    }
    response
        .json()
        .await
        .map_err(|e| AptosBridgeClientError::RestError(format!("view decode: {e}")))
}
