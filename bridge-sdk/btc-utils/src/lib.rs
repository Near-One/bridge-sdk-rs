use bitcoin::{Address, Amount, OutPoint, TxOut};
use bridge_connector_common::result::{BridgeSdkError, Result};
use serde_with::{serde_as, DisplayFromStr};
use std::collections::HashMap;
use std::str::FromStr;

#[serde_as]
#[derive(Clone, serde::Serialize, serde::Deserialize, Debug)]
pub struct UTXO {
    pub path: String,
    pub tx_bytes: Vec<u8>,
    pub vout: u32,
    #[serde_as(as = "DisplayFromStr")]
    pub balance: u64,
}

fn utxo_to_out_points(utxos: Vec<(String, UTXO)>) -> Result<Vec<OutPoint>> {
    utxos
        .into_iter()
        .map(|(txid, utxo)| {
            let txid_str = txid.split('@').next().ok_or_else(|| {
                BridgeSdkError::BtcClientError(format!("Invalid txid format: {txid}"))
            })?;

            let parsed_txid = txid_str.parse().map_err(|e| {
                BridgeSdkError::BtcClientError(format!(
                    "Failed to parse txid '{txid_str}' into bitcoin::Txid: {e}"
                ))
            })?;

            Ok(OutPoint::new(parsed_txid, utxo.vout))
        })
        .collect()
}

pub fn get_gas_fee(num_input: u64, num_output: u64, fee_rate: u64) -> u64 {
    let tx_size = 12 + num_input * 68 + num_output * 31;
    (fee_rate * tx_size / 1024) + 50
}

#[allow(clippy::implicit_hasher)]
pub fn choose_utxos(
    amount: u128,
    utxos: HashMap<String, UTXO>,
    fee_rate: u64,
) -> Result<(Vec<OutPoint>, u128, u128)> {
    let mut utxo_list: Vec<(String, UTXO)> = utxos.into_iter().collect();
    utxo_list.sort_by(|a, b| a.1.balance.cmp(&b.1.balance));

    let mut selected = Vec::new();
    let mut utxos_balance = 0;
    let mut gas_fee: u128 = 0;

    for utxo in utxo_list {
        gas_fee = get_gas_fee(
            selected
                .len()
                .try_into()
                .expect("Error on convert usize into u64"),
            2,
            fee_rate,
        )
        .into();

        if utxos_balance >= gas_fee + amount {
            break;
        }
        utxos_balance += u128::from(utxo.1.balance);
        selected.push(utxo);
    }

    println!("{:?}", selected);
    println!("{:?}, {:?}", utxos_balance, utxos_balance - gas_fee - amount);

    let out_points = utxo_to_out_points(selected)?;
    Ok((out_points, utxos_balance, gas_fee))
}

pub fn get_tx_outs(
    target_btc_address: &str,
    amount: u64,
    change_address: &str,
    change_amount: u64,
) -> Vec<TxOut> {
    let btc_recipient_address =
        Address::from_str(target_btc_address).expect("Invalid Bitcoin address");
    let btc_recipient_address = btc_recipient_address.assume_checked();
    let btc_recipient_script_pubkey = btc_recipient_address.script_pubkey();

    let change_address = Address::from_str(change_address).expect("Invalid Bitcoin Change address");
    let change_address = change_address.assume_checked();
    let change_script_pubkey = change_address.script_pubkey();
    vec![
        TxOut {
            value: Amount::from_sat(amount),
            script_pubkey: btc_recipient_script_pubkey,
        },
        TxOut {
            value: Amount::from_sat(change_amount),
            script_pubkey: change_script_pubkey,
        },
    ]
}
