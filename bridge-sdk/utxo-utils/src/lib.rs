pub mod address;

use crate::address::UTXOAddress;
use address::Network;
use bitcoin::consensus::deserialize;
use bitcoin::{Amount, OutPoint, ScriptBuf, Transaction as BtcTransaction, TxOut};
use k256::elliptic_curve::subtle::CtOption;
use omni_types::ChainKind;
use serde_with::{serde_as, DisplayFromStr};
use std::collections::HashMap;
use zcash_address::unified;
use zcash_address::unified::Container;
use zcash_address::unified::Encoding;

#[serde_as]
#[derive(Clone, serde::Serialize, serde::Deserialize, Debug)]
pub struct UTXO {
    pub path: String,
    pub tx_bytes: Vec<u8>,
    pub vout: u32,
    #[serde_as(as = "DisplayFromStr")]
    pub balance: u64,
}

#[serde_as]
#[derive(Clone, serde::Serialize, serde::Deserialize, Debug)]
pub struct InputPoint {
    pub utxo: UTXO,
    pub out_point: OutPoint,
}

pub fn utxo_to_out_points(utxos: Vec<(String, UTXO)>) -> Result<Vec<OutPoint>, String> {
    utxos
        .into_iter()
        .map(|(txid, utxo)| {
            let txid_str = txid
                .split('@')
                .next()
                .ok_or_else(|| format!("Invalid txid format: {txid}"))?;

            let parsed_txid = txid_str.parse().map_err(|e| {
                format!("Failed to parse txid '{txid_str}' into bitcoin::Txid: {e}")
            })?;

            Ok(OutPoint::new(parsed_txid, utxo.vout))
        })
        .collect()
}

pub fn utxo_to_input_points(utxos: Vec<(String, UTXO)>) -> Result<Vec<InputPoint>, String> {
    let outputs = utxo_to_out_points(utxos.clone())?;
    Ok(utxos
        .into_iter()
        .zip(outputs)
        .map(|((_, utxo), out_point)| InputPoint { utxo, out_point })
        .collect())
}

pub fn get_gas_fee(
    chain: ChainKind,
    num_input: u64,
    num_output: u64,
    fee_rate: u64,
    orchard: bool,
) -> u64 {
    if chain == ChainKind::Zcash {
        5000 * std::cmp::max(num_input, num_output) + 5000 * (orchard as u64)
    } else {
        let tx_size = 12 + num_input * 68 + num_output * 31;
        (fee_rate * tx_size / 1024) + 141
    }
}

#[allow(clippy::implicit_hasher)]
pub fn choose_utxos(
    amount: u128,
    utxos: HashMap<String, UTXO>,
) -> Result<(Vec<(String, UTXO)>, u128), String> {
    let mut utxo_list: Vec<(String, UTXO)> = utxos.into_iter().collect();
    utxo_list.sort_by(|a, b| b.1.balance.cmp(&a.1.balance));

    let mut selected = Vec::new();
    let mut utxos_balance = 0;

    for utxo in utxo_list {
        utxos_balance += u128::from(utxo.1.balance);
        selected.push(utxo);

        if utxos_balance >= amount {
            break;
        }
    }

    Ok((selected, utxos_balance))
}

#[allow(clippy::implicit_hasher)]
#[allow(clippy::too_many_arguments)]
pub fn choose_utxos_for_active_management(
    utxos: HashMap<String, UTXO>,
    fee_rate: u64,
    change_address: &str,
    active_management_limit: (usize, usize),
    max_active_utxo_management_input_number: usize,
    max_active_utxo_management_output_number: usize,
    min_deposit_amount: usize,
    chain: ChainKind,
    network: Network,
) -> Result<(Vec<OutPoint>, Vec<TxOut>), String> {
    let mut utxo_list: Vec<(String, UTXO)> = utxos.into_iter().collect();
    utxo_list.sort_by(|a, b| a.1.balance.cmp(&b.1.balance));

    let mut selected = Vec::new();
    let mut utxos_balance: u64 = 0;

    if utxo_list.len() < active_management_limit.0 {
        let utxo_amount = 1;
        for i in 0..utxo_amount {
            utxos_balance += utxo_list[utxo_list.len() - 1 - i].1.balance;
            selected.push(utxo_list[i].clone());
        }

        let output_amount = std::cmp::min(
            active_management_limit.0 - utxo_list.len(),
            std::cmp::min(
                usize::try_from(utxos_balance)
                    .map_err(|e| format!("Error on convert u64 into usize: {e}"))?
                    / min_deposit_amount
                    - 1,
                max_active_utxo_management_output_number,
            ),
        );

        let output_amount = output_amount
            .try_into()
            .map_err(|e| format!("Error on convert usize into u64: {e}"))?;

        let gas_fee: u64 = get_gas_fee(chain, 1, output_amount, fee_rate, false);
        let out_points = utxo_to_out_points(selected)?;

        let tx_outs = get_tx_outs_utxo_management(
            change_address,
            output_amount,
            utxos_balance - gas_fee,
            chain,
            network,
        )?;

        Ok((out_points, tx_outs))
    } else if utxo_list.len() > active_management_limit.1 {
        let utxo_amount = std::cmp::min(
            utxo_list.len() - active_management_limit.1,
            max_active_utxo_management_input_number,
        );
        for utxo_item in utxo_list.iter().take(utxo_amount) {
            utxos_balance += utxo_item.1.balance;
            selected.push(utxo_item.clone());
        }
        let gas_fee: u64 = get_gas_fee(
            chain,
            selected
                .len()
                .try_into()
                .map_err(|e| format!("Error on convert usize into u64: {e}"))?,
            1,
            fee_rate,
            false,
        );
        let out_points = utxo_to_out_points(selected)?;

        let tx_outs = get_tx_outs(
            change_address,
            utxos_balance - gas_fee,
            change_address,
            0,
            chain,
            network,
        )?;

        Ok((out_points, tx_outs))
    } else {
        Err("Incorrect number of UTXOs for active management".to_string())
    }
}

pub fn get_tx_outs(
    target_btc_address: &str,
    amount: u64,
    change_address: &str,
    change_amount: u64,
    chain: ChainKind,
    network: Network,
) -> Result<Vec<TxOut>, String> {
    let btc_recipient_address = UTXOAddress::parse(target_btc_address, chain, network)
        .map_err(|e| format!("Invalid target UTXO address '{target_btc_address}': {e}"))?;
    let btc_recipient_script_pubkey = btc_recipient_address.script_pubkey().map_err(|e| {
        format!("Failed to get script_pubkey for target UTXO address '{target_btc_address}': {e}")
    })?;

    let mut res = vec![TxOut {
        value: Amount::from_sat(amount),
        script_pubkey: btc_recipient_script_pubkey,
    }];

    if change_amount > 0 {
        let change_address = UTXOAddress::parse(change_address, chain, network)
            .map_err(|e| format!("Invalid change UTXO address '{change_address}': {e}"))?;
        let change_script_pubkey = change_address.script_pubkey().map_err(|e| {
            format!("Failed to get script_pubkey for change UTXO address '{change_address}': {e}")
        })?;
        res.push(TxOut {
            value: Amount::from_sat(change_amount),
            script_pubkey: change_script_pubkey,
        });
    }

    Ok(res)
}

pub fn get_tx_outs_script_pubkey(
    btc_recipient_script_pubkey: ScriptBuf,
    amount: u64,
    change_script_pubkey: ScriptBuf,
    change_amount: u64,
) -> Vec<TxOut> {
    let mut res = vec![TxOut {
        value: Amount::from_sat(amount),
        script_pubkey: btc_recipient_script_pubkey,
    }];

    if change_amount > 0 {
        res.push(TxOut {
            value: Amount::from_sat(change_amount),
            script_pubkey: change_script_pubkey,
        });
    }

    res
}
pub fn bytes_to_btc_transaction(tx_bytes: &[u8]) -> BtcTransaction {
    deserialize(tx_bytes).expect("Deserialization tx_bytes failed")
}

pub fn get_tx_outs_utxo_management(
    change_address: &str,
    output_amount: u64,
    amount: u64,
    chain: ChainKind,
    network: Network,
) -> Result<Vec<TxOut>, String> {
    let change_address = UTXOAddress::parse(change_address, chain, network)
        .map_err(|e| format!("Invalid change UTXO address '{change_address}': {e}"))?;
    let change_script_pubkey = change_address.script_pubkey().map_err(|e| {
        format!("Failed to get script_pubkey for change UTXO address '{change_address}': {e}")
    })?;

    let one_amount = amount / output_amount;
    let mut res = vec![TxOut {
        value: Amount::from_sat(amount - one_amount * (output_amount - 1)),
        script_pubkey: change_script_pubkey.clone(),
    }];

    for _ in 0..output_amount - 1 {
        res.push(TxOut {
            value: Amount::from_sat(one_amount),
            script_pubkey: change_script_pubkey.clone(),
        });
    }

    Ok(res)
}

pub fn extract_orchard_address(uaddress: String) -> Result<CtOption<orchard::Address>, String> {
    let (_, ua) = unified::Address::decode(&uaddress)
        .map_err(|err| format!("Invalid unified address {err}"))?;
    let mut parsed_address = None;
    for receiver in ua.items() {
        if let unified::Receiver::Orchard(orchard_receiver) = receiver {
            parsed_address = Some(orchard_receiver);
        }
    }
    Ok(orchard::Address::from_raw_address_bytes(
        &parsed_address.ok_or_else(|| "No orchard address found in unified address".to_string())?,
    ))
}
