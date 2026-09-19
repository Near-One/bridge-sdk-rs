pub mod address;
pub mod anchor_fill;

pub use anchor_fill::choose_utxos_anchor_fill;

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
    utxo_list.sort_by_key(|b| std::cmp::Reverse(b.1.balance));

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
    sorted_desc.sort_by_key(|b| std::cmp::Reverse(b.balance));

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
    pub active_management_upper_limit: u32,
}

/// Locally configured replacements for the pool-size thresholds that steer
/// withdraw UTXO selection. Every field is optional: `None` keeps the value
/// the connector contract reports, so an operator only states what they want
/// to deviate on.
///
/// Note the asymmetry in what is safe to change. `algorithm_switch_threshold`
/// is SDK-only — the contract never validates against it — so it can move in
/// either direction. The two passive-management bounds are mirrored by the
/// contract's own PSBT validation, so only tightening is safe: lowering
/// `merge_above` or raising `split_below` makes the SDK stricter than the
/// contract and the resulting PSBT still passes. Loosening them produces
/// transactions the contract rejects.
#[derive(Clone, Debug, Default)]
pub struct WithdrawSelectionOverrides {
    /// Replaces `active_management_upper_limit`: pool sizes above this switch
    /// the withdraw path from the random selector to the consolidating
    /// anchor-fill selector.
    pub algorithm_switch_threshold: Option<u32>,
    /// Replaces `passive_management_lower_limit`: below this the withdrawal
    /// must split its change into more outputs than it consumes inputs, so the
    /// pool grows.
    pub split_below: Option<u32>,
    /// Replaces `passive_management_upper_limit`: above this the withdrawal
    /// must consume more inputs than it creates change outputs, so the pool
    /// shrinks.
    pub merge_above: Option<u32>,
}

impl WithdrawSelectionOverrides {
    /// Returns true when nothing is overridden.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.algorithm_switch_threshold.is_none()
            && self.split_below.is_none()
            && self.merge_above.is_none()
    }

    /// Overwrites the contract-supplied thresholds with whatever is set here.
    pub fn apply_to(&self, params: &mut WithdrawSelectionParams) {
        if let Some(threshold) = self.algorithm_switch_threshold {
            params.active_management_upper_limit = threshold;
        }
        if let Some(limit) = self.split_below {
            params.passive_management_lower_limit = limit;
        }
        if let Some(limit) = self.merge_above {
            params.passive_management_upper_limit = limit;
        }
    }
}

/// Splits `change` into `n` outputs each strictly less than `max_per_piece`
/// and at least `min_change_amount`. Returns Err if no valid split exists
/// within `max_change_number`.
pub(crate) fn split_change(
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
pub(crate) fn enforce_passive_management(
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

/// Which UTXO a [`ActiveManagementPlan::Split`] consumes.
#[derive(Clone, Debug)]
pub enum SplitInput {
    /// The largest UTXO in the pool — yields the biggest pieces.
    Largest,
    /// The smallest UTXO in the pool.
    Smallest,
    /// A specific UTXO, keyed as `"{txid}@{vout}"`.
    Utxo(String),
}

/// Explicit shape for an active UTXO-management transaction.
///
/// The caller states the direction and the counts outright; the connector
/// contract's `active_management_*` limits and `min_deposit_amount` are not
/// consulted. Whether the pool needs to shrink or grow is the caller's call,
/// which makes the resulting transaction a pure function of these arguments
/// and the current pool.
#[derive(Clone, Debug)]
pub enum ActiveManagementPlan {
    /// `input_number` inputs → one output. Shrinks the pool by
    /// `input_number - 1`.
    Merge {
        /// How many UTXOs to consume; at least 2.
        input_number: usize,
        /// Take from the largest end of the pool instead of the smallest.
        /// Useful ahead of a large withdrawal, which needs a fat UTXO.
        prefer_largest: bool,
        /// Skip any single UTXO above this. `None` ⇒ no per-UTXO cap.
        per_utxo_cap: Option<u128>,
        /// Skip any UTXO that would push the merged total to this or above,
        /// so the single output stays a valid change piece for the contract.
        /// `None` ⇒ no cap.
        max_total: Option<u128>,
    },
    /// One input → `output_number` outputs. Grows the pool by
    /// `output_number - 1`.
    Split {
        /// How many outputs to produce; at least 2.
        output_number: usize,
        /// Which UTXO to spend.
        input: SplitInput,
    },
}

/// Builds the inputs and outputs for an active UTXO-management transaction
/// from an explicit [`ActiveManagementPlan`].
///
/// Returns `Err` when the pool cannot satisfy the plan — too few eligible
/// UTXOs for the requested `input_number`, an unknown UTXO key, or a balance
/// that does not cover the mining fee.
#[allow(clippy::implicit_hasher)]
pub fn plan_active_management(
    utxos: &HashMap<String, UTXO>,
    plan: &ActiveManagementPlan,
    fee_rate: u64,
    change_address: &str,
    chain: ChainKind,
    network: Network,
) -> Result<(Vec<OutPoint>, Vec<TxOut>), String> {
    let mut sorted: Vec<(&String, &UTXO)> = utxos.iter().collect();
    sorted.sort_by_key(|(_, u)| u.balance);

    match *plan {
        ActiveManagementPlan::Merge {
            input_number,
            prefer_largest,
            per_utxo_cap,
            max_total,
        } => merge(
            &sorted,
            input_number,
            prefer_largest,
            per_utxo_cap,
            max_total,
            fee_rate,
            change_address,
            chain,
            network,
        ),
        ActiveManagementPlan::Split {
            output_number,
            ref input,
        } => split(
            &sorted,
            utxos,
            output_number,
            input,
            fee_rate,
            change_address,
            chain,
            network,
        ),
    }
}

#[allow(clippy::too_many_arguments)]
fn merge(
    sorted: &[(&String, &UTXO)],
    input_number: usize,
    prefer_largest: bool,
    per_utxo_cap: Option<u128>,
    max_total: Option<u128>,
    fee_rate: u64,
    change_address: &str,
    chain: ChainKind,
    network: Network,
) -> Result<(Vec<OutPoint>, Vec<TxOut>), String> {
    if input_number < 2 {
        return Err(format!(
            "Merge needs at least 2 inputs to shrink the pool (got input_number={input_number})"
        ));
    }

    // Walk from whichever end the caller asked for, skipping UTXOs the caps
    // exclude. A skipped UTXO doesn't end the walk: a later one may still fit
    // under `max_total`.
    let mut selected: Vec<(String, UTXO)> = Vec::with_capacity(input_number);
    let mut total: u64 = 0;
    let mut skipped_by_cap = 0usize;

    let walk: Box<dyn Iterator<Item = &(&String, &UTXO)>> = if prefer_largest {
        Box::new(sorted.iter().rev())
    } else {
        Box::new(sorted.iter())
    };

    for (key, utxo) in walk {
        if selected.len() == input_number {
            break;
        }
        let balance = u128::from(utxo.balance);
        if per_utxo_cap.is_some_and(|cap| balance > cap) {
            skipped_by_cap += 1;
            continue;
        }
        let next_total = u128::from(total)
            .checked_add(balance)
            .ok_or_else(|| "Merged total overflows u128".to_string())?;
        if max_total.is_some_and(|cap| next_total >= cap) {
            skipped_by_cap += 1;
            continue;
        }
        total = total
            .checked_add(utxo.balance)
            .ok_or_else(|| "Merged total overflows u64".to_string())?;
        selected.push(((*key).clone(), (*utxo).clone()));
    }

    if selected.len() < input_number {
        return Err(format!(
            "Merge asked for {input_number} inputs but only {} of the {} pool UTXOs are eligible \
             ({skipped_by_cap} excluded by per_utxo_cap/max_total)",
            selected.len(),
            sorted.len()
        ));
    }

    let num_inputs = u64::try_from(selected.len())
        .map_err(|e| format!("Error on convert usize into u64: {e}"))?;
    let gas_fee = get_gas_fee(chain, num_inputs, 1, fee_rate, false);
    let amount = total
        .checked_sub(gas_fee)
        .ok_or_else(|| format!("Merged total {total} does not cover the mining fee {gas_fee}"))?;
    if amount == 0 {
        return Err(format!(
            "Merged total {total} leaves nothing after the mining fee {gas_fee}"
        ));
    }

    let out_points = utxo_to_out_points(selected)?;
    let tx_outs = get_tx_outs_utxo_management(change_address, 1, amount, chain, network)?;

    Ok((out_points, tx_outs))
}

#[allow(clippy::too_many_arguments)]
fn split(
    sorted: &[(&String, &UTXO)],
    utxos: &HashMap<String, UTXO>,
    output_number: usize,
    input: &SplitInput,
    fee_rate: u64,
    change_address: &str,
    chain: ChainKind,
    network: Network,
) -> Result<(Vec<OutPoint>, Vec<TxOut>), String> {
    if output_number < 2 {
        return Err(format!(
            "Split needs at least 2 outputs to grow the pool (got output_number={output_number})"
        ));
    }

    let (key, utxo) = match input {
        SplitInput::Largest => sorted
            .last()
            .map(|(k, u)| ((*k).clone(), (*u).clone()))
            .ok_or_else(|| "UTXO pool is empty".to_string())?,
        SplitInput::Smallest => sorted
            .first()
            .map(|(k, u)| ((*k).clone(), (*u).clone()))
            .ok_or_else(|| "UTXO pool is empty".to_string())?,
        SplitInput::Utxo(key) => utxos
            .get(key)
            .map(|u| (key.clone(), u.clone()))
            .ok_or_else(|| format!("UTXO '{key}' is not in the pool"))?,
    };

    let outputs = u64::try_from(output_number)
        .map_err(|e| format!("Error on convert usize into u64: {e}"))?;
    let gas_fee = get_gas_fee(chain, 1, outputs, fee_rate, false);
    let amount = utxo.balance.checked_sub(gas_fee).ok_or_else(|| {
        format!(
            "UTXO '{key}' holds {} which does not cover the mining fee {gas_fee}",
            utxo.balance
        )
    })?;
    // `get_tx_outs_utxo_management` hands the remainder to the first output and
    // `amount / outputs` to the rest, so a zero quotient would emit dust outputs.
    if amount / outputs == 0 {
        return Err(format!(
            "UTXO '{key}' leaves {amount} after the mining fee {gas_fee}, too little to split \
             into {output_number} outputs"
        ));
    }

    let out_points = utxo_to_out_points(vec![(key, utxo)])?;
    let tx_outs = get_tx_outs_utxo_management(change_address, outputs, amount, chain, network)?;

    Ok((out_points, tx_outs))
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

/// Builds `tx_outs` for an Orchard-shielded Zcash recipient. The recipient
/// receives funds via the Orchard bundle (carried in `chain_specific_data`),
/// not via a transparent output, so `tx_outs[0]` is only an amount sentinel
/// for downstream code and its `script_pubkey` is intentionally empty.
/// Change uses the transparent `change_address`.
///
/// The Orchard tx builder accepts a single optional transparent change
/// (`get_orchard_raw`'s `tx_out_change: Option<&TxOut>`), and the orchard
/// fee model assumes one transparent output. UTXO selection may legitimately
/// produce multiple change pieces (passive management LOW zone splits change
/// into `input_num + 1` pieces); they are aggregated into one output here
/// rather than silently dropped or hard-failed.
pub fn get_tx_outs_orchard(
    target_amount: u64,
    change_address: &str,
    change_amounts: &[u64],
    chain: ChainKind,
    network: Network,
) -> Result<Vec<TxOut>, String> {
    let total_change: u64 = change_amounts
        .iter()
        .try_fold(0u64, |acc, &x| acc.checked_add(x))
        .ok_or_else(|| "Orchard change amount sum overflows u64".to_string())?;

    let mut res = vec![TxOut {
        value: Amount::from_sat(target_amount),
        script_pubkey: ScriptBuf::new(),
    }];

    if total_change > 0 {
        let change_address_parsed = UTXOAddress::parse(change_address, chain, network)
            .map_err(|e| format!("Invalid change UTXO address '{change_address}': {e}"))?;
        let change_script_pubkey = change_address_parsed.script_pubkey().map_err(|e| {
            format!("Failed to get script_pubkey for change UTXO address '{change_address}': {e}")
        })?;
        // The Orchard tx builder (`get_builder_with_transparent` in zcash.rs)
        // hard-codes `TransparentAddress::PublicKeyHash` and extracts the hash
        // from a P2PKH script layout (`script[3..23]`). A non-P2PKH change
        // script would yield a malformed transparent output and lose the
        // change. Reject here so the failure is loud and local.
        if !change_script_pubkey.is_p2pkh() {
            return Err(format!(
                "Orchard mode requires a P2PKH transparent change address; \
                 '{change_address}' produced a non-P2PKH script"
            ));
        }
        res.push(TxOut {
            value: Amount::from_sat(total_change),
            script_pubkey: change_script_pubkey,
        });
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

pub fn contains_orchard_address(address: &str) -> Result<bool, String> {
    Ok(zcash_address_receivers(address)?.has_orchard)
}

pub fn contains_transparent_address(address: &str) -> Result<bool, String> {
    Ok(zcash_address_receivers(address)?.has_transparent)
}

struct ZcashAddressReceivers {
    has_orchard: bool,
    has_transparent: bool,
}

impl zcash_address::TryFromAddress for ZcashAddressReceivers {
    type Error = &'static str;

    fn try_from_transparent_p2pkh(
        _net: zcash_protocol::consensus::NetworkType,
        _data: [u8; 20],
    ) -> Result<Self, zcash_address::ConversionError<Self::Error>> {
        Ok(Self {
            has_orchard: false,
            has_transparent: true,
        })
    }

    fn try_from_transparent_p2sh(
        _net: zcash_protocol::consensus::NetworkType,
        _data: [u8; 20],
    ) -> Result<Self, zcash_address::ConversionError<Self::Error>> {
        Ok(Self {
            has_orchard: false,
            has_transparent: true,
        })
    }

    fn try_from_tex(
        _net: zcash_protocol::consensus::NetworkType,
        _data: [u8; 20],
    ) -> Result<Self, zcash_address::ConversionError<Self::Error>> {
        Ok(Self {
            has_orchard: false,
            has_transparent: true,
        })
    }

    fn try_from_unified(
        _net: zcash_protocol::consensus::NetworkType,
        data: unified::Address,
    ) -> Result<Self, zcash_address::ConversionError<Self::Error>> {
        let mut has_orchard = false;
        let mut has_transparent = false;
        for receiver in data.items() {
            match receiver {
                unified::Receiver::Orchard(_) => has_orchard = true,
                unified::Receiver::P2pkh(_) | unified::Receiver::P2sh(_) => {
                    has_transparent = true;
                }
                _ => {}
            }
        }
        Ok(Self {
            has_orchard,
            has_transparent,
        })
    }
}

fn zcash_address_receivers(address: &str) -> Result<ZcashAddressReceivers, String> {
    let parsed = zcash_address::ZcashAddress::try_from_encoded(address)
        .map_err(|err| format!("Invalid Zcash address: {err}"))?;
    parsed
        .convert::<ZcashAddressReceivers>()
        .map_err(|err| format!("Unsupported Zcash address: {err}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::base58;

    // Transparent P2PKH (`t1...`) mainnet address from the reported bug.
    const TRANSPARENT_P2PKH_MAINNET: &str = "t1Yuiss7kdrddAkaAQjtHctsZPG3uKj4f2o";

    // Encodes a fresh Zcash mainnet P2SH (`t3...`) address from a 20-byte
    // script hash so the test does not depend on a specific live address.
    fn synthetic_t3_mainnet(script_hash: [u8; 20]) -> String {
        let mut prefixed = Vec::with_capacity(22);
        prefixed.extend_from_slice(&[0x1C, 0xBD]);
        prefixed.extend_from_slice(&script_hash);
        base58::encode_check(&prefixed)
    }

    // Orchard-only unified mainnet address from the reported bug. It contains
    // no transparent receiver, so `UTXOAddress::script_pubkey()` cannot derive
    // a transparent script for it.
    const ORCHARD_ONLY_UNIFIED_MAINNET: &str = "u15a97e324mckwx89t0ucxytpd7v3pfzey7daldrk4mwu3u55ej39f6v7myqjxw0e098hnhyp0tvfgfnxj8swt22rl4f77a8wrg9zjynh9dwj20lf232h7yzfr0v53l2s824l22l63xwlxyypnxkx9qq7dd249pj565q7490fey5czu2pm";

    #[test]
    fn transparent_p2pkh_address_has_no_orchard() {
        assert_eq!(
            contains_orchard_address(TRANSPARENT_P2PKH_MAINNET),
            Ok(false)
        );
    }

    #[test]
    fn transparent_p2pkh_address_is_transparent() {
        assert_eq!(
            contains_transparent_address(TRANSPARENT_P2PKH_MAINNET),
            Ok(true)
        );
    }

    #[test]
    fn invalid_address_returns_error() {
        assert!(contains_orchard_address("not-a-zcash-address").is_err());
        assert!(contains_transparent_address("not-a-zcash-address").is_err());
    }

    fn tex_mainnet_from_t1(t1: &str) -> String {
        use zcash_address::ToAddress;
        let data = base58::decode_check(t1).unwrap();
        let hash: [u8; 20] = data[2..].try_into().unwrap();
        zcash_address::ZcashAddress::from_tex(zcash_protocol::consensus::NetworkType::Main, hash)
            .encode()
    }

    #[test]
    fn tex_address_is_transparent_without_orchard() {
        let tex = tex_mainnet_from_t1(TRANSPARENT_P2PKH_MAINNET);
        assert_eq!(contains_transparent_address(&tex), Ok(true));
        assert_eq!(contains_orchard_address(&tex), Ok(false));
    }

    #[test]
    fn orchard_only_unified_address_classification() {
        assert_eq!(
            contains_orchard_address(ORCHARD_ONLY_UNIFIED_MAINNET),
            Ok(true)
        );
        assert_eq!(
            contains_transparent_address(ORCHARD_ONLY_UNIFIED_MAINNET),
            Ok(false)
        );
    }

    #[test]
    fn get_tx_outs_orchard_uses_empty_script_for_recipient() {
        let change_address = "t1Yuiss7kdrddAkaAQjtHctsZPG3uKj4f2o";
        let outs = get_tx_outs_orchard(
            100_000,
            change_address,
            &[50_000],
            ChainKind::Zcash,
            Network::Mainnet,
        )
        .expect("orchard tx_outs build succeeds for orchard-only recipient");

        assert_eq!(outs.len(), 2);
        assert_eq!(outs[0].value.to_sat(), 100_000);
        assert!(outs[0].script_pubkey.is_empty());
        assert_eq!(outs[1].value.to_sat(), 50_000);
        assert!(!outs[1].script_pubkey.is_empty());
    }

    #[test]
    fn get_tx_outs_orchard_no_change_returns_single_out() {
        let outs = get_tx_outs_orchard(
            100_000,
            "t1Yuiss7kdrddAkaAQjtHctsZPG3uKj4f2o",
            &[],
            ChainKind::Zcash,
            Network::Mainnet,
        )
        .expect("orchard tx_outs build succeeds without change");

        assert_eq!(outs.len(), 1);
        assert_eq!(outs[0].value.to_sat(), 100_000);
        assert!(outs[0].script_pubkey.is_empty());
    }

    #[test]
    fn get_tx_outs_orchard_aggregates_multi_change() {
        let outs = get_tx_outs_orchard(
            100_000,
            "t1Yuiss7kdrddAkaAQjtHctsZPG3uKj4f2o",
            &[20_000, 30_000, 7_000],
            ChainKind::Zcash,
            Network::Mainnet,
        )
        .expect("orchard tx_outs build aggregates multi-change");
        assert_eq!(outs.len(), 2);
        assert_eq!(outs[0].value.to_sat(), 100_000);
        assert!(outs[0].script_pubkey.is_empty());
        assert_eq!(outs[1].value.to_sat(), 57_000);
        assert!(!outs[1].script_pubkey.is_empty());
    }

    #[test]
    fn get_tx_outs_orchard_rejects_change_amount_overflow() {
        let err = get_tx_outs_orchard(
            100_000,
            "t1Yuiss7kdrddAkaAQjtHctsZPG3uKj4f2o",
            &[u64::MAX, 1],
            ChainKind::Zcash,
            Network::Mainnet,
        )
        .expect_err("orchard tx_outs must reject u64 overflow on change sum");
        assert!(err.contains("overflows"), "unexpected error: {err}");
    }

    #[test]
    fn zcash_t3_mainnet_parses_as_p2sh() {
        let script_hash = [0x42u8; 20];
        let t3 = synthetic_t3_mainnet(script_hash);
        let parsed = UTXOAddress::parse(&t3, ChainKind::Zcash, Network::Mainnet)
            .expect("Zcash P2SH (t3) must parse");

        let script = parsed.script_pubkey().expect("t3 must yield a script");
        assert!(script.is_p2sh(), "expected P2SH script, got: {script:?}");
        assert_eq!(&script.as_bytes()[2..22], &script_hash);
        assert_eq!(parsed.to_string(), t3, "t3 address must roundtrip");
    }

    #[test]
    fn zcash_t3_classified_as_transparent() {
        let t3 = synthetic_t3_mainnet([0u8; 20]);
        assert_eq!(contains_orchard_address(&t3), Ok(false));
        assert_eq!(contains_transparent_address(&t3), Ok(true));
    }

    #[test]
    fn get_tx_outs_orchard_rejects_p2sh_change_address() {
        let t3 = synthetic_t3_mainnet([0u8; 20]);
        let err = get_tx_outs_orchard(100_000, &t3, &[50_000], ChainKind::Zcash, Network::Mainnet)
            .expect_err("orchard mode must reject P2SH change addresses");
        assert!(
            err.contains("requires a P2PKH transparent change address"),
            "expected non-P2PKH change rejection, got: {err}"
        );
    }

    #[test]
    fn get_tx_outs_supports_p2sh_recipient() {
        let t3 = synthetic_t3_mainnet([0x42u8; 20]);
        let outs = get_tx_outs(
            &t3,
            100_000,
            "t1Yuiss7kdrddAkaAQjtHctsZPG3uKj4f2o",
            50_000,
            ChainKind::Zcash,
            Network::Mainnet,
        )
        .expect("tx_outs build succeeds for P2SH recipient");

        assert_eq!(outs.len(), 2);
        assert!(outs[0].script_pubkey.is_p2sh());
        assert!(outs[1].script_pubkey.is_p2pkh());
    }

    // --- Active UTXO management: explicit merge / split plans ---
    //
    // All of these run on Zcash, whose fee is `5000 * max(num_input, num_output)`
    // (see `get_gas_fee`), so the expected amounts stay readable.

    const ZCASH_CHANGE_ADDRESS: &str = TRANSPARENT_P2PKH_MAINNET;

    fn mk_utxo(idx: usize, balance: u64) -> (String, UTXO) {
        (
            format!("{idx:064x}@0"),
            UTXO {
                path: format!("m/0/{idx}"),
                tx_bytes: vec![],
                vout: 0,
                balance,
            },
        )
    }

    /// Four UTXOs: 10k, 20k, 30k, 100k.
    fn management_pool() -> HashMap<String, UTXO> {
        [10_000, 20_000, 30_000, 100_000]
            .into_iter()
            .enumerate()
            .map(|(i, balance)| mk_utxo(i, balance))
            .collect()
    }

    fn run_plan(
        pool: &HashMap<String, UTXO>,
        plan: &ActiveManagementPlan,
    ) -> Result<(Vec<OutPoint>, Vec<TxOut>), String> {
        plan_active_management(
            pool,
            plan,
            0,
            ZCASH_CHANGE_ADDRESS,
            ChainKind::Zcash,
            Network::Mainnet,
        )
    }

    fn balances(pool: &HashMap<String, UTXO>, out_points: &[OutPoint]) -> Vec<u64> {
        out_points
            .iter()
            .map(|op| pool[&format!("{}@{}", op.txid, op.vout)].balance)
            .collect()
    }

    fn merge_plan(input_number: usize, prefer_largest: bool) -> ActiveManagementPlan {
        ActiveManagementPlan::Merge {
            input_number,
            prefer_largest,
            per_utxo_cap: None,
            max_total: None,
        }
    }

    #[test]
    fn merge_consumes_smallest_utxos_into_one_output() {
        let pool = management_pool();
        let (out_points, tx_outs) = run_plan(&pool, &merge_plan(3, false)).unwrap();

        assert_eq!(balances(&pool, &out_points), vec![10_000, 20_000, 30_000]);
        assert_eq!(tx_outs.len(), 1);
        // 60_000 in, fee = 5000 * max(3, 1).
        assert_eq!(tx_outs[0].value.to_sat(), 60_000 - 15_000);
    }

    #[test]
    fn merge_prefer_largest_walks_from_the_other_end() {
        let pool = management_pool();
        let (out_points, tx_outs) = run_plan(&pool, &merge_plan(2, true)).unwrap();

        assert_eq!(balances(&pool, &out_points), vec![100_000, 30_000]);
        assert_eq!(tx_outs[0].value.to_sat(), 130_000 - 10_000);
    }

    #[test]
    fn merge_skips_utxos_above_per_utxo_cap() {
        let pool = management_pool();
        let plan = ActiveManagementPlan::Merge {
            input_number: 2,
            prefer_largest: true,
            per_utxo_cap: Some(25_000),
            max_total: None,
        };
        let (out_points, _) = run_plan(&pool, &plan).unwrap();

        // 100k and 30k are over the cap, so the largest-first walk lands on 20k and 10k.
        assert_eq!(balances(&pool, &out_points), vec![20_000, 10_000]);
    }

    #[test]
    fn merge_skips_utxos_that_would_breach_max_total() {
        let pool = management_pool();
        let plan = ActiveManagementPlan::Merge {
            input_number: 2,
            prefer_largest: false,
            per_utxo_cap: None,
            max_total: Some(35_000),
        };
        let (out_points, _) = run_plan(&pool, &plan).unwrap();

        // 10k + 20k = 30k fits; adding 30k or 100k would reach the cap.
        assert_eq!(balances(&pool, &out_points), vec![10_000, 20_000]);
    }

    #[test]
    fn merge_reports_how_many_utxos_were_eligible() {
        let pool = management_pool();
        let plan = ActiveManagementPlan::Merge {
            input_number: 3,
            prefer_largest: false,
            per_utxo_cap: Some(25_000),
            max_total: None,
        };
        let err = run_plan(&pool, &plan).unwrap_err();

        assert!(err.contains("only 2"), "{err}");
        assert!(err.contains("2 excluded"), "{err}");
    }

    #[test]
    fn merge_needs_at_least_two_inputs() {
        let pool = management_pool();
        assert!(run_plan(&pool, &merge_plan(1, false))
            .unwrap_err()
            .contains("at least 2 inputs"));
    }

    #[test]
    fn merge_rejects_a_total_below_the_fee() {
        let pool: HashMap<String, UTXO> = [1, 2]
            .into_iter()
            .enumerate()
            .map(|(i, b)| mk_utxo(i, b))
            .collect();
        // fee = 5000 * max(2, 1) = 10_000 against a 3 sat total.
        assert!(run_plan(&pool, &merge_plan(2, false))
            .unwrap_err()
            .contains("does not cover the mining fee"));
    }

    #[test]
    fn split_breaks_the_largest_utxo_into_even_pieces() {
        let pool = management_pool();
        let plan = ActiveManagementPlan::Split {
            output_number: 4,
            input: SplitInput::Largest,
        };
        let (out_points, tx_outs) = run_plan(&pool, &plan).unwrap();

        assert_eq!(balances(&pool, &out_points), vec![100_000]);
        // fee = 5000 * max(1, 4) = 20_000, so 80_000 across 4 outputs.
        assert_eq!(
            tx_outs.iter().map(|o| o.value.to_sat()).collect::<Vec<_>>(),
            vec![20_000; 4]
        );
    }

    #[test]
    fn split_can_target_the_smallest_or_a_named_utxo() {
        // The default pool's smallest UTXO is exactly the two-output fee, so use
        // a pool where either end survives it.
        let pool: HashMap<String, UTXO> = [30_000, 100_000]
            .into_iter()
            .enumerate()
            .map(|(i, balance)| mk_utxo(i, balance))
            .collect();

        let plan = ActiveManagementPlan::Split {
            output_number: 2,
            input: SplitInput::Smallest,
        };
        let (out_points, tx_outs) = run_plan(&pool, &plan).unwrap();
        assert_eq!(balances(&pool, &out_points), vec![30_000]);
        assert_eq!(
            tx_outs.iter().map(|o| o.value.to_sat()).collect::<Vec<_>>(),
            vec![10_000; 2]
        );

        let plan = ActiveManagementPlan::Split {
            output_number: 2,
            input: SplitInput::Utxo(mk_utxo(1, 0).0),
        };
        let (out_points, _) = run_plan(&pool, &plan).unwrap();
        assert_eq!(balances(&pool, &out_points), vec![100_000]);
    }

    #[test]
    fn split_rejects_an_unknown_utxo_key() {
        let pool = management_pool();
        let plan = ActiveManagementPlan::Split {
            output_number: 2,
            input: SplitInput::Utxo("deadbeef@1".to_owned()),
        };
        assert!(run_plan(&pool, &plan)
            .unwrap_err()
            .contains("is not in the pool"));
    }

    #[test]
    fn split_needs_at_least_two_outputs() {
        let pool = management_pool();
        let plan = ActiveManagementPlan::Split {
            output_number: 1,
            input: SplitInput::Largest,
        };
        assert!(run_plan(&pool, &plan)
            .unwrap_err()
            .contains("at least 2 outputs"));
    }

    #[test]
    fn split_rejects_pieces_that_would_be_dust() {
        let pool: HashMap<String, UTXO> = std::iter::once(mk_utxo(0, 20_001)).collect();
        let plan = ActiveManagementPlan::Split {
            output_number: 4,
            input: SplitInput::Largest,
        };
        // fee = 20_000 leaves 1 sat, which cannot make four outputs.
        assert!(run_plan(&pool, &plan)
            .unwrap_err()
            .contains("too little to split"));
    }

    // --- Withdraw selection overrides ---

    fn contract_params() -> WithdrawSelectionParams {
        WithdrawSelectionParams {
            min_change_amount: 537,
            max_change_amount: 2_500_000_000,
            max_withdrawal_input_number: 23,
            max_change_number: 10,
            passive_management_lower_limit: 10,
            passive_management_upper_limit: 6000,
            active_management_upper_limit: 4000,
        }
    }

    #[test]
    fn empty_overrides_leave_the_contract_values_alone() {
        let overrides = WithdrawSelectionOverrides::default();
        assert!(overrides.is_empty());

        let mut params = contract_params();
        overrides.apply_to(&mut params);

        assert_eq!(params.active_management_upper_limit, 4000);
        assert_eq!(params.passive_management_lower_limit, 10);
        assert_eq!(params.passive_management_upper_limit, 6000);
    }

    #[test]
    fn overrides_replace_only_the_fields_that_are_set() {
        let overrides = WithdrawSelectionOverrides {
            algorithm_switch_threshold: Some(500),
            ..Default::default()
        };
        assert!(!overrides.is_empty());

        let mut params = contract_params();
        overrides.apply_to(&mut params);

        assert_eq!(params.active_management_upper_limit, 500);
        assert_eq!(params.passive_management_lower_limit, 10);
        assert_eq!(params.passive_management_upper_limit, 6000);
        // Fields outside the override set are never touched.
        assert_eq!(params.max_withdrawal_input_number, 23);
        assert_eq!(params.min_change_amount, 537);
    }

    #[test]
    fn overrides_can_replace_every_threshold() {
        let overrides = WithdrawSelectionOverrides {
            algorithm_switch_threshold: Some(500),
            split_below: Some(50),
            merge_above: Some(800),
        };

        let mut params = contract_params();
        overrides.apply_to(&mut params);

        assert_eq!(params.active_management_upper_limit, 500);
        assert_eq!(params.passive_management_lower_limit, 50);
        assert_eq!(params.passive_management_upper_limit, 800);
    }
}
