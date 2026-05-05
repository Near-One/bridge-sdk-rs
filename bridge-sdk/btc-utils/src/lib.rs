use bitcoin::{Address, Amount, TxOut};
use bridge_connector_common::result::{BridgeSdkError, Result};
use serde_with::{serde_as, DisplayFromStr};
use std::str::FromStr;

pub mod coin_selection;
pub mod coin_selection_random;
pub use coin_selection::{choose_utxos, SelectionLimits};
pub use coin_selection_random::{choose_utxos_random, UtxoSelection, WithdrawSelectionParams};

#[serde_as]
#[derive(Clone, serde::Serialize, serde::Deserialize, Debug)]
pub struct UTXO {
    pub path: String,
    pub tx_bytes: Vec<u8>,
    pub vout: u32,
    #[serde_as(as = "DisplayFromStr")]
    pub balance: u64,
}

pub fn get_gas_fee(num_input: u64, num_output: u64, fee_rate: u64) -> u64 {
    let tx_size = 12 + num_input * 68 + num_output * 31;
    (fee_rate * tx_size / 1024) + 141
}

pub fn get_tx_outs(
    target_btc_address: &str,
    amount: u64,
    change_address: &str,
    change_amount: u64,
) -> Result<Vec<TxOut>> {
    let btc_recipient_address = Address::from_str(target_btc_address).map_err(|e| {
        BridgeSdkError::UtxoClientError(format!(
            "Invalid target Bitcoin address '{target_btc_address}': {e}"
        ))
    })?;
    let btc_recipient_address = btc_recipient_address.assume_checked();
    let btc_recipient_script_pubkey = btc_recipient_address.script_pubkey();

    let mut res = vec![TxOut {
        value: Amount::from_sat(amount),
        script_pubkey: btc_recipient_script_pubkey,
    }];

    if change_amount > 0 {
        let change_address = Address::from_str(change_address).map_err(|e| {
            BridgeSdkError::UtxoClientError(format!(
                "Invalid change Bitcoin address '{change_address}': {e}"
            ))
        })?;
        let change_address = change_address.assume_checked();
        let change_script_pubkey = change_address.script_pubkey();
        res.push(TxOut {
            value: Amount::from_sat(change_amount),
            script_pubkey: change_script_pubkey,
        });
    }

    Ok(res)
}
