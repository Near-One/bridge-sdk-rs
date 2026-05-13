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
        let mut fee = 5000 * std::cmp::max(num_input, num_output);
        if orchard {
            fee += 5000;
        }
        fee
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

/// Greedy largest-first to determine the minimum number of inputs needed
/// to cover `target = net_amount + min_change_amount`.
fn determine_optimal_n(
    target: u128,
    utxos: &HashMap<String, UTXO>,
    max_input_num: usize,
) -> Result<usize, String> {
    let mut sorted_desc: Vec<&UTXO> = utxos.values().collect();
    sorted_desc.sort_by(|a, b| b.balance.cmp(&a.balance));

    let mut sum: u128 = 0;
    let mut n: usize = 0;
    for u in sorted_desc {
        sum = sum.saturating_add(u128::from(u.balance));
        n += 1;
        if sum >= target {
            if n > max_input_num {
                return Err(format!(
                    "Need {n} inputs to cover target, exceeds max_input_num {max_input_num}"
                ));
            }
            return Ok(n);
        }
    }
    Err("UTXO pool cannot cover target".to_string())
}

/// Randomized iterative selection.
/// At each step picks a random UTXO from those whose balance satisfies
/// `balance * n_remaining >= remaining`
/// (equivalent to `balance >= remaining / n_remaining` but avoids integer-division loss).
fn choose_random_iterative<R: rand::Rng>(
    initial_target: u128,
    n_inputs: usize,
    utxos: HashMap<String, UTXO>,
    rng: &mut R,
) -> Result<Vec<(String, UTXO)>, String> {
    let mut pool: Vec<(String, UTXO)> = utxos.into_iter().collect();
    let mut selected: Vec<(String, UTXO)> = Vec::with_capacity(n_inputs);
    let mut remaining: u128 = initial_target;
    let mut n_remaining: usize = n_inputs;

    while remaining > 0 && n_remaining > 0 {
        let n_u128 = n_remaining as u128;
        let candidate_indices: Vec<usize> = pool
            .iter()
            .enumerate()
            .filter(|(_, (_, u))| u128::from(u.balance).saturating_mul(n_u128) >= remaining)
            .map(|(i, _)| i)
            .collect();

        if candidate_indices.is_empty() {
            return Err("No UTXO satisfies the per-step threshold".to_string());
        }

        let pick_idx = candidate_indices[rng.gen_range(0..candidate_indices.len())];
        let picked = pool.swap_remove(pick_idx);
        let picked_balance = u128::from(picked.1.balance);
        selected.push(picked);

        remaining = remaining.saturating_sub(picked_balance);
        n_remaining -= 1;
    }

    if remaining > 0 {
        return Err("Could not cover target within determined N inputs".to_string());
    }

    Ok(selected)
}

/// Result of UTXO selection. The caller constructs the PSBT outputs as:
/// - target_btc_address: `net_amount - gas_fee - user_payment`
/// - change_address: one TxOut per element of `change_amounts`
///
/// The protocol mining fee is implicitly `gas_fee` (i.e. `inputs - outputs == gas_fee`).
#[derive(Clone, Debug)]
pub struct UtxoSelection {
    pub selected: Vec<(String, UTXO)>,
    /// Extra amount the user pays beyond `gas_fee`. Non-zero only when dust-padding
    /// was applied: equals `min_change_amount - new_change`. The user receives less
    /// by this amount; the difference lands in the change-output (back to the pool).
    pub user_payment: u128,
    /// Sizes of change outputs. Possible cases:
    /// - empty: absorption (no change output, sum_inputs == net_amount exactly)
    /// - single: standard or padded change
    /// - multiple: split change (size constraint or passive management LOW zone)
    pub change_amounts: Vec<u128>,
}

/// Contract parameters relevant to withdraw UTXO selection. Mirrors a subset of
/// `Config` from the satoshi-bridge contract.
#[derive(Clone, Debug)]
pub struct WithdrawSelectionParams {
    pub min_change_amount: u128,
    pub max_change_amount: u128,
    pub max_withdrawal_input_number: usize,
    pub max_change_number: usize,
    pub passive_management_lower_limit: u32,
    pub passive_management_upper_limit: u32,
}

/// Splits `change` into `n` outputs each strictly less than `max_per_piece`
/// and at least `min_change_amount`. Returns Err if no valid split exists
/// within `max_change_number`.
fn split_change(
    change: u128,
    min_change_amount: u128,
    max_per_piece: u128,
    max_change_number: usize,
) -> Result<Vec<u128>, String> {
    if max_per_piece == 0 {
        return Err("Cannot split change: max_per_piece is zero".to_string());
    }
    let num_pieces_u128 = change.div_ceil(max_per_piece);
    let num_pieces: usize = num_pieces_u128
        .try_into()
        .map_err(|_| "num_pieces overflow".to_string())?;
    if num_pieces > max_change_number {
        return Err(format!(
            "Change {change} requires {num_pieces} pieces, exceeds max_change_number {max_change_number}"
        ));
    }
    let avg = change / num_pieces_u128;
    if avg < min_change_amount {
        return Err(format!(
            "Cannot split change {change} into {num_pieces} pieces of at least {min_change_amount} (avg {avg})"
        ));
    }
    let remainder: usize = (change % num_pieces_u128)
        .try_into()
        .expect("remainder fits in usize when num_pieces fits");
    let mut amounts = vec![avg; num_pieces];
    for amount in amounts.iter_mut().take(remainder) {
        *amount += 1;
    }
    Ok(amounts)
}

/// Validates the random selection against contract rules and applies repair if needed.
///
/// Iteratively drops the smallest selected UTXO while `change >= min_input`. After
/// each drop, evaluates the result:
/// - `change == 0` → absorption (no change output).
/// - `0 < change < min_change_amount` → pad change up to `min_change_amount`,
///   user pays the gap.
/// - `min_change_amount <= change < min_input` → standard. Single change output if
///   it fits under `max_change_amount` (or input_num == 1 where the contract doesn't
///   enforce that bound); otherwise split change into multiple outputs.
/// - `change >= min_input` → drop again.
///
/// Returns `Err` if dropping reduces sum below `net_amount`, selection becomes
/// empty, or change cannot be split within `max_change_number`.
fn validate_and_repair(
    mut selected: Vec<(String, UTXO)>,
    net_amount: u128,
    min_change_amount: u128,
    max_change_amount: u128,
    max_change_number: usize,
) -> Result<UtxoSelection, String> {
    loop {
        if selected.is_empty() {
            return Err("Selection became empty during repair".to_string());
        }

        let sum: u128 = selected.iter().map(|(_, u)| u128::from(u.balance)).sum();

        let change = sum
            .checked_sub(net_amount)
            .ok_or_else(|| "Selection no longer covers net_amount after dropping".to_string())?;

        // Absorption: sum equals net_amount exactly, no change output.
        if change == 0 {
            return Ok(UtxoSelection {
                selected,
                user_payment: 0,
                change_amounts: vec![],
            });
        }

        let min_input: u128 = selected
            .iter()
            .map(|(_, u)| u128::from(u.balance))
            .min()
            .expect("non-empty");

        // Dust zone: pad change up to min_change_amount; user covers the gap.
        // Only valid if `min_change_amount < min_input` (contract requires
        // each change-output to be strictly less than every input).
        if change < min_change_amount {
            if min_change_amount < min_input {
                let user_payment = min_change_amount - change;
                return Ok(UtxoSelection {
                    selected,
                    user_payment,
                    change_amounts: vec![min_change_amount],
                });
            }
            // Padding would create a change-output >= min_input. Drop and retry.
            let min_idx = selected
                .iter()
                .enumerate()
                .min_by_key(|(_, (_, u))| u.balance)
                .map(|(i, _)| i)
                .expect("non-empty");
            selected.swap_remove(min_idx);
            continue;
        }

        // change >= min_change_amount. Standard valid if change < min_input.
        if change < min_input {
            // Decide whether to split. The contract's `change < max_change_amount`
            // rule applies only when `input_num > change_num`. With single input,
            // a single change output always sidesteps it.
            let num_inputs = selected.len();
            let need_split = num_inputs > 1 && change >= max_change_amount;

            let change_amounts = if need_split {
                let max_per_piece = std::cmp::min(max_change_amount, min_input).saturating_sub(1);
                split_change(change, min_change_amount, max_per_piece, max_change_number)?
            } else {
                vec![change]
            };

            return Ok(UtxoSelection {
                selected,
                user_payment: 0,
                change_amounts,
            });
        }

        // change >= min_input → drop the smallest UTXO and retry.
        let min_idx = selected
            .iter()
            .enumerate()
            .min_by_key(|(_, (_, u))| u.balance)
            .map(|(i, _)| i)
            .expect("non-empty");
        selected.swap_remove(min_idx);
    }
}

/// Enforces passive management constraints based on `pool_size`:
/// - LOW zone (`pool_size < passive_lower`): require `input_num < change_num`.
///   If currently `input_num >= change_num`, attempts to split single change into
///   `input_num + 1` pieces.
/// - HIGH zone (`pool_size > passive_upper`): require `input_num > change_num`.
///   No automatic adjustment — returns `Err` if violated.
/// - Healthy zone: no-op.
fn enforce_passive_management(
    selection: UtxoSelection,
    pool_size: u32,
    params: &WithdrawSelectionParams,
) -> Result<UtxoSelection, String> {
    let input_num = selection.selected.len();
    let change_num = selection.change_amounts.len();

    if pool_size < params.passive_management_lower_limit {
        // LOW zone: need input_num < change_num.
        if change_num > input_num {
            return Ok(selection);
        }
        if change_num == 0 {
            return Err(
                "Passive management LOW zone violation: selection produced no change output \
                 (absorption case); cannot split nothing"
                    .to_string(),
            );
        }
        let target_change_num = input_num + 1;
        if target_change_num > params.max_change_number {
            return Err(format!(
                "Passive management LOW zone needs {target_change_num} change outputs, \
                 exceeds max_change_number {}",
                params.max_change_number
            ));
        }
        let total_change: u128 = selection.change_amounts.iter().sum();
        let min_input: u128 = selection
            .selected
            .iter()
            .map(|(_, u)| u128::from(u.balance))
            .min()
            .expect("non-empty");
        // In LOW zone, `input < change` so the contract's `change < max_change_amount`
        // check (gated on `input > change`) does NOT apply. Only need `change < min_input`.
        let max_per_piece = min_input.saturating_sub(1);
        let amounts = split_into_n_pieces(
            total_change,
            params.min_change_amount,
            max_per_piece,
            target_change_num,
        )?;
        return Ok(UtxoSelection {
            change_amounts: amounts,
            ..selection
        });
    }

    if pool_size > params.passive_management_upper_limit {
        // HIGH zone: need input_num > change_num.
        if input_num > change_num {
            return Ok(selection);
        }
        return Err(format!(
            "Passive management HIGH zone violation: input_num ({input_num}) <= \
             change_num ({change_num}); pool needs to be consolidated via active management first"
        ));
    }

    // Healthy zone — no constraint.
    Ok(selection)
}

/// Splits `total` into exactly `num_pieces` pieces, each in `[min_per_piece, max_per_piece]`.
fn split_into_n_pieces(
    total: u128,
    min_per_piece: u128,
    max_per_piece: u128,
    num_pieces: usize,
) -> Result<Vec<u128>, String> {
    if num_pieces == 0 {
        return Err("num_pieces must be positive".to_string());
    }
    if max_per_piece == 0 {
        return Err("max_per_piece is zero".to_string());
    }
    let n_u128 = num_pieces as u128;
    let avg = total / n_u128;
    let remainder_u128 = total % n_u128;
    let remainder: usize = remainder_u128
        .try_into()
        .expect("remainder < num_pieces fits in usize");
    let max_piece = if remainder > 0 { avg + 1 } else { avg };

    if avg < min_per_piece {
        return Err(format!(
            "Cannot split {total} into {num_pieces} pieces of at least {min_per_piece} (avg = {avg})"
        ));
    }
    if max_piece > max_per_piece {
        return Err(format!(
            "Cannot split {total} into {num_pieces} pieces of at most {max_per_piece} (max piece = {max_piece})"
        ));
    }
    let mut amounts = vec![avg; num_pieces];
    for amount in amounts.iter_mut().take(remainder) {
        *amount += 1;
    }
    Ok(amounts)
}

/// Picks UTXOs to cover `net_amount` such that the resulting change is at least
/// `min_change_amount` (avoiding the dust-zone where change ∈ (0, min_change_amount)).
///
/// Algorithm:
/// 0. If `pool_size > passive_management_upper_limit` (HIGH zone), filter out UTXOs
///    with `balance > net_amount`. This forces multi-input or 1-input absorption,
///    both of which trivially satisfy `input_num > change_num` (the HIGH zone rule).
///    Single-input + 1-change is impossible after this filter.
/// 1. Greedy largest-first determines the minimum number of inputs N
///    needed to cover `net_amount + min_change_amount`.
/// 2. Randomized iterative pick: at each step, the candidate pool is UTXOs
///    with `balance >= remaining / n_remaining` (compared via multiplication
///    to avoid integer-division loss). One candidate is picked uniformly at random.
/// 3. Validation and repair: while `change >= min_input`, drop the smallest selected
///    UTXO and re-evaluate. Terminates with absorption / padding / standard / split
///    change output, or `Err` if no valid configuration is reachable
///    (see `validate_and_repair`).
/// 4. Passive management enforcement based on `pool_size`. In LOW zone, splits
///    change into more pieces; in HIGH zone, fails if `input_num <= change_num`.
#[allow(clippy::implicit_hasher)]
pub fn choose_utxos_random<R: rand::Rng>(
    net_amount: u128,
    utxos: HashMap<String, UTXO>,
    pool_size: u32,
    params: &WithdrawSelectionParams,
    rng: &mut R,
) -> Result<UtxoSelection, String> {
    let target = net_amount
        .checked_add(params.min_change_amount)
        .ok_or_else(|| "target overflow".to_string())?;

    // HIGH zone: drop UTXOs that alone would push us into single-input territory.
    // We keep UTXOs with balance <= net_amount (absorption-friendly threshold).
    let utxos = if pool_size > params.passive_management_upper_limit {
        utxos
            .into_iter()
            .filter(|(_, u)| u128::from(u.balance) <= net_amount)
            .collect()
    } else {
        utxos
    };

    let n = determine_optimal_n(target, &utxos, params.max_withdrawal_input_number)?;
    let selected = choose_random_iterative(target, n, utxos, rng)?;
    let selection = validate_and_repair(
        selected,
        net_amount,
        params.min_change_amount,
        params.max_change_amount,
        params.max_change_number,
    )?;
    enforce_passive_management(selection, pool_size, params)
}

/// Maximum number of `choose_utxos_random` attempts inside
/// [`choose_utxos_random_no_payment`] before giving up.
pub const MAX_NO_PAYMENT_RETRIES: usize = 10;

/// Wrapper around [`choose_utxos_random`] that rejects selections where the user has to
/// pay anything beyond the gas fee (i.e. `user_payment > 0`, dust-zone padding). Retries
/// up to [`MAX_NO_PAYMENT_RETRIES`] times with fresh random rolls; returns the first
/// selection with `user_payment == 0`. If every attempt landed in the dust zone, returns
/// `Err`.
#[allow(clippy::implicit_hasher)]
pub fn choose_utxos_random_no_payment<R: rand::Rng>(
    net_amount: u128,
    utxos: HashMap<String, UTXO>,
    pool_size: u32,
    params: &WithdrawSelectionParams,
    rng: &mut R,
) -> Result<UtxoSelection, String> {
    let mut last_user_payment: u128 = 0;
    for _ in 0..MAX_NO_PAYMENT_RETRIES {
        let selection = choose_utxos_random(net_amount, utxos.clone(), pool_size, params, rng)?;
        if selection.user_payment == 0 {
            return Ok(selection);
        }
        last_user_payment = selection.user_payment;
    }
    Err(format!(
        "Failed to find UTXO selection without user_payment after {MAX_NO_PAYMENT_RETRIES} \
         attempts (last attempt required user_payment={last_user_payment})"
    ))
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
    merge_largest: bool,
    max_change_amount: u128,
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
        if merge_largest {
            let half_cap = max_change_amount / 2;
            for utxo_item in utxo_list.iter().rev() {
                if selected.len() >= utxo_amount {
                    break;
                }
                let next_balance = u128::from(utxo_item.1.balance);
                // Skip UTXOs that can't usefully pair with any other big UTXO
                // without pushing the change output past max_change_amount.
                if next_balance > half_cap {
                    continue;
                }
                if u128::from(utxos_balance) + next_balance >= max_change_amount {
                    break;
                }
                utxos_balance += utxo_item.1.balance;
                selected.push(utxo_item.clone());
            }
            if selected.is_empty() {
                return Err(format!(
                    "merge-largest: no UTXOs <= max_change_amount/2 ({half_cap}); nothing to merge"
                ));
            }
        } else {
            for utxo_item in utxo_list.iter().take(utxo_amount) {
                utxos_balance += utxo_item.1.balance;
                selected.push(utxo_item.clone());
            }
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

pub fn get_tx_outs_multi(
    target_btc_address: &str,
    target_amount: u64,
    change_address: &str,
    change_amounts: &[u64],
    chain: ChainKind,
    network: Network,
) -> Result<Vec<TxOut>, String> {
    let btc_recipient_address = UTXOAddress::parse(target_btc_address, chain, network)
        .map_err(|e| format!("Invalid target UTXO address '{target_btc_address}': {e}"))?;
    let btc_recipient_script_pubkey = btc_recipient_address.script_pubkey().map_err(|e| {
        format!("Failed to get script_pubkey for target UTXO address '{target_btc_address}': {e}")
    })?;

    let mut res = vec![TxOut {
        value: Amount::from_sat(target_amount),
        script_pubkey: btc_recipient_script_pubkey,
    }];

    if !change_amounts.is_empty() {
        let change_address_parsed = UTXOAddress::parse(change_address, chain, network)
            .map_err(|e| format!("Invalid change UTXO address '{change_address}': {e}"))?;
        let change_script_pubkey = change_address_parsed.script_pubkey().map_err(|e| {
            format!("Failed to get script_pubkey for change UTXO address '{change_address}': {e}")
        })?;
        for &amt in change_amounts {
            res.push(TxOut {
                value: Amount::from_sat(amt),
                script_pubkey: change_script_pubkey.clone(),
            });
        }
    }

    Ok(res)
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

pub fn extract_orchard_address(uaddress: &str) -> Result<CtOption<orchard::Address>, String> {
    let (_, ua) = unified::Address::decode(uaddress)
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

pub fn contains_orchard_address(uaddress: &str) -> Result<bool, String> {
    let (_, ua) = unified::Address::decode(uaddress)
        .map_err(|err| format!("Invalid unified address {err}"))?;
    for receiver in ua.items() {
        if let unified::Receiver::Orchard(_) = receiver {
            return Ok(true);
        }
    }

    Ok(false)
}

pub fn contains_transparent_address(uaddress: &str) -> Result<bool, String> {
    let (_, ua) = unified::Address::decode(uaddress)
        .map_err(|err| format!("Invalid unified address {err}"))?;
    for receiver in ua.items() {
        if let unified::Receiver::P2pkh(_) = receiver {
            return Ok(true);
        }

        if let unified::Receiver::P2sh(_) = receiver {
            return Ok(true);
        }
    }

    Ok(false)
}
