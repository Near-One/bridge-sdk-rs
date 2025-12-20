use reqwest::Client;
use serde::Deserialize;

use near_sdk::json_types::U128;

#[derive(Debug, Deserialize)]
pub struct TransferFeeDto {
    pub native_token_fee: U128,
    pub transferred_token_fee: Option<U128>,
    // pub gas_fee: Option<U128>,
    // pub usd_fee: Option<f64>,
}

#[derive(Debug)]
pub struct FeeQuote {
    pub native_fee: u128,
    pub transferred_fee: u128,
}

pub async fn fetch_transfer_fee(
    api_url: &str,
    sender: &str,
    recipient: &str,
    token: &str,
    amount: Option<u128>,
) -> Result<FeeQuote, String> {
    let client = Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .map_err(|e| format!("Failed to build HTTP client: {e}"))?;

    let mut request = client
        .get(format!("{}/api/v3/transfer-fee", api_url))
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

    let dto: TransferFeeDto = response
        .json()
        .await
        .map_err(|e| format!("Failed to parse transfer fee response: {e}"))?;

    let native_fee = dto.native_token_fee.0;
    let transferred_fee = dto
        .transferred_token_fee
        .ok_or("Missing transferred_token_fee in response")?
        .0;

    Ok(FeeQuote {
        native_fee,
        transferred_fee,
    })
}
