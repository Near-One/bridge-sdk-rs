//! Minimal client for the bridge indexer API: fee quotes and transfer lookup.

use reqwest::Client;
use serde::Deserialize;

use near_sdk::json_types::U128;

#[derive(Debug, Deserialize, Clone)]
pub struct TransferFee {
    pub native_token_fee: U128,
    pub transferred_token_fee: Option<U128>,
    pub gas_fee: Option<U128>,
}

fn http_client() -> Result<Client, String> {
    Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .map_err(|e| format!("Failed to build HTTP client: {e}"))
}

pub async fn fetch_transfer_fee(
    api_url: &str,
    sender: &str,
    recipient: &str,
    token: &str,
    amount: Option<u128>,
) -> Result<TransferFee, String> {
    let mut request = http_client()?
        .get(format!("{api_url}/api/v3/transfer-fee"))
        .query(&[
            ("sender", sender),
            ("recipient", recipient),
            ("token", token),
        ]);

    if let Some(amount) = amount {
        request = request.query(&[("amount", &amount.to_string())]);
    }

    let response = request
        .send()
        .await
        .map_err(|e| format!("Failed to fetch transfer fee: {e}"))?
        .error_for_status()
        .map_err(|e| format!("Transfer fee API returned error: {e}"))?;

    response
        .json()
        .await
        .map_err(|e| format!("Failed to parse transfer fee response: {e}"))
}

/// A transaction that advanced a transfer, as reported by the indexer.
#[derive(Debug, Deserialize, Clone)]
pub struct TransactionRef {
    pub transaction_hash: String,
    pub chain: String,
}

/// Subset of the indexer's v4 transfer object that the CLI displays. Absent
/// optional fields are omitted (not null) by the API, hence `serde(default)`.
#[derive(Debug, Deserialize, Clone)]
pub struct Transfer {
    pub status: String,
    #[serde(default)]
    pub origin_chain: Option<String>,
    #[serde(default)]
    pub destination_chain: Option<String>,
    #[serde(default)]
    pub sender: Option<String>,
    #[serde(default)]
    pub recipient: Option<String>,
    #[serde(default)]
    pub token_id: Option<String>,
    #[serde(default)]
    pub amount: Option<String>,
    #[serde(default)]
    pub fee: Option<String>,
    #[serde(default)]
    pub native_fee: Option<String>,
    #[serde(default)]
    pub destination_nonce: Option<u64>,
    #[serde(default)]
    pub initialised: Option<TransactionRef>,
    #[serde(default)]
    pub signed: Vec<TransactionRef>,
    #[serde(default)]
    pub fast_finalised_on_near: Option<TransactionRef>,
    #[serde(default)]
    pub finalised_on_near: Option<TransactionRef>,
    #[serde(default)]
    pub fast_finalised: Option<TransactionRef>,
    #[serde(default)]
    pub finalised: Option<TransactionRef>,
    #[serde(default)]
    pub claimed: Option<TransactionRef>,
}

#[derive(Debug, Deserialize)]
struct TransfersResponse {
    transfers: Vec<Transfer>,
}

/// Look up transfers by any transaction hash that touched them.
pub async fn fetch_transfers_by_tx(api_url: &str, tx_hash: &str) -> Result<Vec<Transfer>, String> {
    let response = http_client()?
        .get(format!("{api_url}/api/v4/transfers/transfer"))
        .query(&[("transaction_hash", tx_hash)])
        .send()
        .await
        .map_err(|e| format!("Failed to fetch transfer: {e}"))?;

    if response.status() == reqwest::StatusCode::NOT_FOUND {
        return Ok(Vec::new());
    }

    let response = response
        .error_for_status()
        .map_err(|e| format!("Transfer API returned error: {e}"))?;

    let transfers: TransfersResponse = response
        .json()
        .await
        .map_err(|e| format!("Failed to parse transfer response: {e}"))?;

    Ok(transfers.transfers)
}
