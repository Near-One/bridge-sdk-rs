//! Anchor-fill UTXO selection.
//!
//! Goal: pick the **maximum** number of UTXOs allowed by a `max_gas_fee`
//! budget while still covering `net_amount` and producing valid change under
//! the contract's `change_i < min_input` and `change_num <= max_change_number`
//! rules. Used to consolidate small UTXOs within a single withdrawal so the
//! pool drifts toward fewer, larger UTXOs over time.
//!
//! ## Algorithm
//!
//! 1. Sort the pool ascending by balance.
//! 2. Compute `K_max = min(max_inputs_by_gas, max_withdrawal_input_number, pool.len())`.
//! 3. For each `K` from `K_max` down to `1`:
//!      - For each `filler_start` in `0..=pool.len() - K`:
//!         - Take `K-1` consecutive UTXOs starting at `filler_start` as
//!           "fillers" (the UTXOs we want to consume).
//!         - Binary-search the remaining tail of the pool for an "anchor"
//!           UTXO whose balance brings the total to either:
//!             - `net_amount` exactly (absorption, no change), or
//!             - `net_amount + change` where
//!               `change ∈ [min_change_amount, max_change_number * min_filler)`.
//!      - Return the first feasible `(K, filler_start, anchor)`.
//!
//! Picking `filler_start = 0` consumes the `K-1` smallest UTXOs — maximum
//! consolidation. Larger `filler_start` widens the change window (bigger
//! `min_filler`) at the cost of consolidating fewer smalls. The outer loop
//! tries `K_max` first so the returned selection uses as much of the gas
//! budget as the pool allows.
//!
//! ## Why "max within budget" not "min fee"
//!
//! Each withdrawal consumes pool UTXOs. If we always pick the minimum number
//! of inputs (`min_fee` strategy) the pool fragments over time because every
//! tx creates one change output. By picking the **maximum** inputs the gas
//! budget allows — each tx folds many small UTXOs into one change — the pool
//! consolidates as a side-effect of normal withdrawals.

use crate::{split_change, UtxoSelection, WithdrawSelectionParams, UTXO};
use omni_types::ChainKind;
use std::collections::HashMap;

/// Choose UTXOs maximizing input count within the `max_gas_fee` budget.
///
/// Returns `Err` if the budget is too tight to admit any inputs, if the pool
/// can't cover `net_amount`, or if no `K`-subset of the pool produces a valid
/// change configuration.
#[allow(clippy::implicit_hasher)]
#[allow(clippy::too_many_arguments)]
pub fn choose_utxos_anchor_fill(
    net_amount: u128,
    utxos: HashMap<String, UTXO>,
    pool_size: u32,
    params: &WithdrawSelectionParams,
    chain: ChainKind,
    fee_rate: u64,
    max_gas_fee: u64,
    orchard: bool,
) -> Result<UtxoSelection, String> {
    let in_high_zone = pool_size > params.passive_management_upper_limit;

    // HIGH zone: drop UTXOs > net_amount so the result satisfies `input_num > change_num`
    // downstream (single-input + 1-change becomes structurally impossible).
    let utxos = if in_high_zone {
        utxos
            .into_iter()
            .filter(|(_, u)| u128::from(u.balance) <= net_amount)
            .collect::<HashMap<_, _>>()
    } else {
        utxos
    };

    let mut sorted: Vec<(String, UTXO)> = utxos.into_iter().collect();
    sorted.sort_by_key(|(_, u)| u.balance);

    // Worst-case num_output makes the fee bound hold regardless of how the
    // change finally splits (1 target + up to max_change_number change outputs).
    let worst_case_num_output = 1u64 + params.max_change_number as u64;
    let k_max_by_gas = max_inputs_by_gas(
        chain,
        fee_rate,
        max_gas_fee,
        worst_case_num_output,
        orchard,
    );

    let k_max = std::cmp::min(
        std::cmp::min(k_max_by_gas, params.max_withdrawal_input_number),
        sorted.len(),
    );

    if k_max == 0 {
        return Err(format!(
            "No inputs admissible within max_gas_fee={max_gas_fee} (k_max_by_gas={k_max_by_gas}, \
             max_withdrawal_input_number={}, pool_size={})",
            params.max_withdrawal_input_number,
            sorted.len()
        ));
    }

    for k in (1..=k_max).rev() {
        if let Some(selection) = try_k_inputs(k, net_amount, &sorted, params, in_high_zone) {
            return Ok(selection);
        }
    }

    Err(format!(
        "No feasible selection for net_amount={net_amount} (k_max={k_max}, pool_size={})",
        sorted.len()
    ))
}

/// Upper bound on the number of inputs allowed by a `max_gas_fee` budget,
/// assuming `num_output` outputs. Inverts the `get_gas_fee` formula in
/// [`crate::get_gas_fee`].
fn max_inputs_by_gas(
    chain: ChainKind,
    fee_rate: u64,
    max_gas_fee: u64,
    num_output: u64,
    orchard: bool,
) -> usize {
    if chain == ChainKind::Zcash {
        // fee = 5000 * max(num_input, num_output) + (orchard ? 5000 : 0)
        let orchard_offset = if orchard { 5000u64 } else { 0 };
        let budget = max_gas_fee.saturating_sub(orchard_offset);
        usize::try_from(budget / 5000).unwrap_or(usize::MAX)
    } else {
        // fee = (fee_rate * (12 + num_input * 68 + num_output * 31)) / 1024 + 141
        if fee_rate == 0 {
            return usize::MAX;
        }
        let budget = max_gas_fee.saturating_sub(141);
        let tx_size_budget = budget.saturating_mul(1024) / fee_rate;
        let inputs_size_budget = tx_size_budget
            .saturating_sub(12)
            .saturating_sub(num_output.saturating_mul(31));
        usize::try_from(inputs_size_budget / 68).unwrap_or(usize::MAX)
    }
}

fn try_k_inputs(
    k: usize,
    net_amount: u128,
    sorted_pool: &[(String, UTXO)],
    params: &WithdrawSelectionParams,
    in_high_zone: bool,
) -> Option<UtxoSelection> {
    if k == 0 || sorted_pool.len() < k {
        return None;
    }

    if k == 1 {
        return try_single_input(net_amount, sorted_pool, params, in_high_zone);
    }

    // K >= 2: anchor + (K-1) consecutive fillers.
    // filler_start = 0 maximizes consolidation; growing it widens the change
    // window (larger min_filler) at the cost of consuming fewer smalls.
    let max_filler_start = sorted_pool.len() - k;
    for filler_start in 0..=max_filler_start {
        let fillers = &sorted_pool[filler_start..filler_start + k - 1];
        let candidates = &sorted_pool[filler_start + k - 1..];

        if let Some(sel) = try_anchor_search(fillers, candidates, net_amount, params, in_high_zone)
        {
            return Some(sel);
        }
    }
    None
}

fn try_single_input(
    net_amount: u128,
    sorted_pool: &[(String, UTXO)],
    params: &WithdrawSelectionParams,
    in_high_zone: bool,
) -> Option<UtxoSelection> {
    // Best-fit single input: smallest balance >= net_amount that yields valid change.
    let lo = sorted_pool.partition_point(|(_, u)| u128::from(u.balance) < net_amount);

    for entry in &sorted_pool[lo..] {
        let bal = u128::from(entry.1.balance);
        let change = bal - net_amount;

        if change == 0 {
            return Some(UtxoSelection {
                selected: vec![entry.clone()],
                user_payment: 0,
                change_amounts: vec![],
            });
        }

        if change < params.min_change_amount {
            if params.min_change_amount < bal {
                // Dust padding: user covers the gap to bring change up to min_change_amount.
                // 1 input + 1 change → HIGH zone (input_num > change_num) is satisfied.
                return Some(UtxoSelection {
                    selected: vec![entry.clone()],
                    user_payment: params.min_change_amount - change,
                    change_amounts: vec![params.min_change_amount],
                });
            }
            continue;
        }

        // change >= min_change_amount && change < bal.
        let change_amounts = if change >= params.max_change_amount {
            let max_per_piece = std::cmp::min(params.max_change_amount, bal).saturating_sub(1);
            if max_per_piece == 0 {
                continue;
            }
            match split_change(
                change,
                params.min_change_amount,
                max_per_piece,
                params.max_change_number,
            ) {
                Ok(amts) => amts,
                Err(_) => continue,
            }
        } else {
            vec![change]
        };

        if in_high_zone && !change_amounts.is_empty() {
            // HIGH zone: input_num=1 > change_num required → change_num must be 0.
            // The HIGH-zone pool filter already drops UTXOs > net_amount, so this
            // path only fires when net_amount equals an existing UTXO balance.
            continue;
        }

        return Some(UtxoSelection {
            selected: vec![entry.clone()],
            user_payment: 0,
            change_amounts,
        });
    }
    None
}

fn try_anchor_search(
    fillers: &[(String, UTXO)],
    candidates: &[(String, UTXO)],
    net_amount: u128,
    params: &WithdrawSelectionParams,
    in_high_zone: bool,
) -> Option<UtxoSelection> {
    if fillers.is_empty() || candidates.is_empty() {
        return None;
    }

    let sum_fillers: u128 = fillers.iter().map(|(_, u)| u128::from(u.balance)).sum();
    let min_filler = u128::from(fillers[0].1.balance);
    let input_count = fillers.len() + 1;

    // Each change piece must be < min_input (= min_filler, since `candidates`
    // are sorted ≥ all fillers) and < max_change_amount, so total change
    // can be at most max_change_number * (min(max_change_amount, min_filler) - 1).
    let max_per_piece = std::cmp::min(params.max_change_amount, min_filler).saturating_sub(1);
    if max_per_piece == 0 {
        return None;
    }
    // Strict upper bound on change (exclusive).
    let valid_change_max = (params.max_change_number as u128).saturating_mul(max_per_piece + 1);

    // 1) Absorption — anchor balance brings sum to exactly net_amount.
    if sum_fillers < net_amount {
        let abs_target = net_amount - sum_fillers;
        if let Some(idx) = find_balance_eq(candidates, abs_target) {
            let mut selected: Vec<(String, UTXO)> = fillers.to_vec();
            selected.push(candidates[idx].clone());
            return Some(UtxoSelection {
                selected,
                user_payment: 0,
                change_amounts: vec![],
            });
        }
    }

    // 2) Standard / splittable change — anchor balance in [lower, upper).
    let lower = net_amount
        .saturating_add(params.min_change_amount)
        .saturating_sub(sum_fillers);
    let upper = net_amount
        .saturating_add(valid_change_max)
        .saturating_sub(sum_fillers);

    if lower >= upper {
        return None;
    }

    let lo_idx = candidates.partition_point(|(_, u)| u128::from(u.balance) < lower);
    for entry in &candidates[lo_idx..] {
        let anchor_bal = u128::from(entry.1.balance);
        if anchor_bal >= upper {
            break;
        }

        let total = sum_fillers + anchor_bal;
        let change = total - net_amount;

        let change_amounts = if change < min_filler && change < params.max_change_amount {
            vec![change]
        } else {
            match split_change(
                change,
                params.min_change_amount,
                max_per_piece,
                params.max_change_number,
            ) {
                Ok(amts) => amts,
                Err(_) => continue,
            }
        };

        // HIGH zone requires input_num > change_num.
        if in_high_zone && input_count <= change_amounts.len() {
            continue;
        }

        let mut selected: Vec<(String, UTXO)> = fillers.to_vec();
        selected.push(entry.clone());
        return Some(UtxoSelection {
            selected,
            user_payment: 0,
            change_amounts,
        });
    }

    None
}

fn find_balance_eq(slice: &[(String, UTXO)], target: u128) -> Option<usize> {
    let lo = slice.partition_point(|(_, u)| u128::from(u.balance) < target);
    if lo < slice.len() && u128::from(slice[lo].1.balance) == target {
        Some(lo)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

    /// 100 UTXOs across three tiers (same as the random-selector test bench).
    fn pool_100_tiered() -> HashMap<String, UTXO> {
        let mut pool = HashMap::new();
        for i in 0..50 {
            let bal = 10_000 + (i as u64) * 800;
            let (k, v) = mk_utxo(i, bal);
            pool.insert(k, v);
        }
        for i in 0..30 {
            let bal = 100_000 + (i as u64) * 13_000;
            let (k, v) = mk_utxo(50 + i, bal);
            pool.insert(k, v);
        }
        for i in 0..20 {
            let bal = 1_000_000 + (i as u64) * 200_000;
            let (k, v) = mk_utxo(80 + i, bal);
            pool.insert(k, v);
        }
        pool
    }

    fn default_params() -> WithdrawSelectionParams {
        WithdrawSelectionParams {
            min_change_amount: 5_000,
            max_change_amount: 2_000_000,
            max_withdrawal_input_number: 50,
            max_change_number: 5,
            passive_management_lower_limit: 10,
            passive_management_upper_limit: 200,
        }
    }

    fn assert_invariants(
        selection: &UtxoSelection,
        net_amount: u128,
        params: &WithdrawSelectionParams,
    ) {
        let mut seen = std::collections::HashSet::new();
        for (k, _) in &selection.selected {
            assert!(seen.insert(k.clone()), "duplicate UTXO {k}");
        }
        assert!(!selection.selected.is_empty(), "empty selection");
        assert!(
            selection.selected.len() <= params.max_withdrawal_input_number,
            "input_num {} > max_withdrawal_input_number {}",
            selection.selected.len(),
            params.max_withdrawal_input_number
        );
        assert!(
            selection.change_amounts.len() <= params.max_change_number,
            "change_num {} > max_change_number {}",
            selection.change_amounts.len(),
            params.max_change_number
        );

        let sum_inputs: u128 = selection
            .selected
            .iter()
            .map(|(_, u)| u128::from(u.balance))
            .sum();
        let sum_change: u128 = selection.change_amounts.iter().sum();
        assert_eq!(
            sum_inputs + selection.user_payment,
            net_amount + sum_change,
            "balance equation broken"
        );

        if !selection.change_amounts.is_empty() {
            let min_input = selection
                .selected
                .iter()
                .map(|(_, u)| u128::from(u.balance))
                .min()
                .unwrap();
            for &c in &selection.change_amounts {
                assert!(
                    c >= params.min_change_amount,
                    "change_piece {c} < min_change_amount"
                );
                assert!(c < min_input, "change_piece {c} not < min_input {min_input}");
            }
        }
    }

    /// Sweep over a range of `max_gas_fee` budgets and print the resulting input
    /// counts. Run with `cargo test -p utxo-utils -- --nocapture` to see the table.
    #[test]
    fn anchor_fill_sweep_input_count_vs_budget() {
        let chain = ChainKind::Btc;
        let fee_rate = 3_000u64;
        let params = default_params();
        let pool = pool_100_tiered();
        let pool_size = pool.len() as u32;
        let net_amount: u128 = 1_500_000;

        let budgets: &[u64] = &[200_000, 100_000, 50_000, 20_000, 10_000, 5_000, 3_000, 2_000, 1_000, 500];

        println!(
            "\n=== anchor_fill | amount={net_amount} sat | fee_rate={fee_rate} | pool=100 tiered ===\n"
        );
        println!(
            "{:>12} | {:>8} | {:>6} | {:>7} | {:>7}",
            "max_gas_fee", "k_max", "inputs", "outputs", "fee"
        );
        println!("{}", "-".repeat(56));

        for &budget in budgets {
            let worst_out = 1u64 + params.max_change_number as u64;
            let k_max_gas = max_inputs_by_gas(chain, fee_rate, budget, worst_out, false);
            let k_max = std::cmp::min(
                std::cmp::min(k_max_gas, params.max_withdrawal_input_number),
                pool.len(),
            );

            match choose_utxos_anchor_fill(
                net_amount,
                pool.clone(),
                pool_size,
                &params,
                chain,
                fee_rate,
                budget,
                false,
            ) {
                Ok(sel) => {
                    let n_in = sel.selected.len();
                    let n_out = 1 + sel.change_amounts.len();
                    let fee =
                        crate::get_gas_fee(chain, n_in as u64, n_out as u64, fee_rate, false);
                    assert_invariants(&sel, net_amount, &params);
                    assert!(
                        n_in <= k_max,
                        "selected {n_in} > k_max {k_max} for budget {budget}"
                    );
                    assert!(
                        fee <= budget,
                        "actual fee {fee} > max_gas_fee {budget} (in={n_in}, out={n_out})"
                    );
                    println!(
                        "{budget:>12} | {k_max:>8} | {n_in:>6} | {n_out:>7} | {fee:>7}"
                    );
                }
                Err(_) => {
                    println!("{budget:>12} | {k_max:>8} | (infeasible)");
                }
            }
        }
    }

    #[test]
    fn anchor_fill_picks_more_inputs_at_larger_budget() {
        let chain = ChainKind::Btc;
        let fee_rate = 10_000u64;
        let params = default_params();
        let pool = pool_100_tiered();
        let pool_size = pool.len() as u32;

        let large = choose_utxos_anchor_fill(
            1_500_000,
            pool.clone(),
            pool_size,
            &params,
            chain,
            fee_rate,
            200_000,
            false,
        )
        .expect("large-budget selection");

        let small = choose_utxos_anchor_fill(
            1_500_000,
            pool.clone(),
            pool_size,
            &params,
            chain,
            fee_rate,
            3_000,
            false,
        )
        .expect("small-budget selection");

        assert_invariants(&large, 1_500_000, &params);
        assert_invariants(&small, 1_500_000, &params);
        assert!(
            large.selected.len() > small.selected.len(),
            "expected larger budget ({}) to pick more inputs than tight budget ({})",
            large.selected.len(),
            small.selected.len()
        );
    }

    #[test]
    fn anchor_fill_errors_when_budget_too_small() {
        let chain = ChainKind::Btc;
        let fee_rate = 10_000u64;
        let params = default_params();
        let pool = pool_100_tiered();
        let pool_size = pool.len() as u32;

        let res = choose_utxos_anchor_fill(
            1_500_000,
            pool,
            pool_size,
            &params,
            chain,
            fee_rate,
            100,
            false,
        );
        assert!(res.is_err(), "expected Err for tiny budget, got {res:?}");
    }
}
