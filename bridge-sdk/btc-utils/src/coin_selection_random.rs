//! Randomized coin selection ported from
//! [Near-One/bridge-sdk-rs#272](https://github.com/Near-One/bridge-sdk-rs/pull/272)
//! ("Random UTXO choose"), translated for `btc-utils`'s [`crate::UTXO`] type.
//! Kept close to the PR source so the diff stays small and traceable.
//!
//! Algorithm:
//! 1. `determine_optimal_n` — greedy largest-first to find the minimum input
//!    count `N` that covers `target = net_amount + min_change_amount`.
//! 2. `choose_random_iterative` — at each step the candidate pool is UTXOs
//!    whose `balance * n_remaining >= remaining` (exact, no integer-division
//!    loss). Pick one uniformly at random; loop until `remaining` reaches 0.
//! 3. `validate_and_repair` — drop the smallest selected UTXO while
//!    `change >= min_input`. Terminate with absorption / dust-padding /
//!    standard-change / split-change.
//! 4. `enforce_passive_management` — split change in the LOW zone; fail in
//!    the HIGH zone if `input_num <= change_num`.
//! 5. HIGH-zone preprocessing filters out UTXOs with `balance > net_amount`
//!    so single-input + 1-change is structurally impossible.
//!
//! Returned via [`UtxoSelection`]:
//! - `selected` — the chosen UTXOs.
//! - `user_payment` — non-zero only when dust-padding was applied (the user
//!   pays this gap so the change output reaches `min_change_amount`).
//! - `change_amounts` — empty (absorption), single (standard / padded), or
//!   multiple (split).

use crate::UTXO;
use std::collections::HashMap;

/// Result of the randomized UTXO selection.
#[derive(Clone, Debug)]
pub struct UtxoSelection {
    pub selected: Vec<(String, UTXO)>,
    /// Extra amount the user pays beyond `gas_fee`. Non-zero only when
    /// dust-padding was applied (`min_change_amount - new_change`).
    pub user_payment: u128,
    /// Sizes of change outputs:
    /// - empty: absorption (no change output, sum_inputs == net_amount exactly)
    /// - single: standard or padded change
    /// - multiple: split (size constraint or LOW-zone passive management)
    pub change_amounts: Vec<u128>,
}

/// Subset of contract config relevant to withdraw UTXO selection.
#[derive(Clone, Debug)]
pub struct WithdrawSelectionParams {
    pub min_change_amount: u128,
    pub max_change_amount: u128,
    pub max_withdrawal_input_number: usize,
    pub max_change_number: usize,
    pub passive_management_lower_limit: u32,
    pub passive_management_upper_limit: u32,
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

/// Randomized iterative selection. Picks a random UTXO at each step from
/// those whose `balance * n_remaining >= remaining`.
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

/// Splits `change` into `n` outputs each strictly less than `max_per_piece`
/// and at least `min_change_amount`.
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

/// Validates the random selection and applies repair if needed.
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

        if change < min_change_amount {
            if min_change_amount < min_input {
                let user_payment = min_change_amount - change;
                return Ok(UtxoSelection {
                    selected,
                    user_payment,
                    change_amounts: vec![min_change_amount],
                });
            }
            let min_idx = selected
                .iter()
                .enumerate()
                .min_by_key(|(_, (_, u))| u.balance)
                .map(|(i, _)| i)
                .expect("non-empty");
            selected.swap_remove(min_idx);
            continue;
        }

        if change < min_input {
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

/// Splits `total` into exactly `num_pieces` pieces in `[min, max]`.
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

/// Enforces passive management constraints based on `pool_size`.
fn enforce_passive_management(
    selection: UtxoSelection,
    pool_size: u32,
    params: &WithdrawSelectionParams,
) -> Result<UtxoSelection, String> {
    let input_num = selection.selected.len();
    let change_num = selection.change_amounts.len();

    if pool_size < params.passive_management_lower_limit {
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
        if input_num > change_num {
            return Ok(selection);
        }
        return Err(format!(
            "Passive management HIGH zone violation: input_num ({input_num}) <= \
             change_num ({change_num}); pool needs to be consolidated via active management first"
        ));
    }

    Ok(selection)
}

/// Picks UTXOs to cover `net_amount` such that the resulting change is at
/// least `min_change_amount` (or absorbed if dust). See module-level docs.
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

    // HIGH zone: drop UTXOs that alone would force single-input territory.
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

/// Wrapper around [`choose_utxos_random`] that rejects selections where the
/// user has to pay anything beyond the gas fee (i.e. `user_payment > 0`,
/// dust-zone padding). Retries up to [`MAX_NO_PAYMENT_RETRIES`] times with
/// fresh random rolls; returns the first selection with `user_payment == 0`.
/// If every attempt landed in the dust zone, returns `Err`.
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
        let selection =
            choose_utxos_random(net_amount, utxos.clone(), pool_size, params, rng)?;
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
