//! Anchor-fill UTXO selection.
//!
//! Goal: pick the **maximum** number of UTXOs allowed by a `max_gas_fee`
//! budget while still covering `net_amount` and producing valid change under
//! the `change_i < max_change_amount` and `change_num <= max_change_number`
//! rules. The contract's `change_i < min_input` constraint is intentionally
//! **not** enforced here — relaxing it lets a single large change piece
//! absorb the surplus from many small fillers instead of forcing a split
//! into many sub-`min_filler` pieces (which fragments the pool with dust).
//! Used to consolidate small UTXOs within a single withdrawal so the pool
//! drifts toward fewer, larger UTXOs over time.
//!
//! ## Algorithm
//!
//! 1. Sort the pool ascending by balance.
//! 2. Compute `K_max = min(max_withdrawal_input_number, pool.len())`.
//! 3. For each `K` from `K_max` down to `1`:
//!      - Skip `K` if the best-case fee (`get_gas_fee(K, 1, …)`, absorption /
//!        orchard with one output) already exceeds `max_gas_fee` — no
//!        selection at this `K` can fit the budget.
//!      - For each `filler_start` in `0..=pool.len() - K`:
//!         - Take `K-1` consecutive UTXOs starting at `filler_start` as
//!           "fillers" (the UTXOs we want to consume).
//!         - Binary-search the remaining tail of the pool for an "anchor"
//!           UTXO whose balance brings the total to either:
//!             - `net_amount` exactly (absorption, no change), or
//!             - `net_amount + change` where
//!               `change ∈ [min_change_amount, max_change_number * max_change_amount)`.
//!      - Compute the actual fee using the *real* output count produced by
//!        the candidate; reject if it exceeds `max_gas_fee`.
//!      - Return the first candidate that passes the fee check and
//!        `enforce_passive_management`.
//!
//! Picking `filler_start = 0` consumes the `K-1` smallest UTXOs — maximum
//! consolidation. With the `< min_input` constraint relaxed the change
//! window no longer depends on `min_filler`, so larger `filler_start` is
//! rarely needed; it remains useful only when no anchor exists for the
//! `filler_start = 0` selection. The outer loop tries `K_max` first so the
//! returned selection uses as much of the gas budget as the pool allows.
//!
//! ## Why "max within budget" not "min fee"
//!
//! Each withdrawal consumes pool UTXOs. If we always pick the minimum number
//! of inputs (`min_fee` strategy) the pool fragments over time because every
//! tx creates one change output. By picking the **maximum** inputs the gas
//! budget allows — each tx folds many small UTXOs into one change — the pool
//! consolidates as a side-effect of normal withdrawals.

use crate::{
    enforce_passive_management, get_gas_fee, split_change, UtxoSelection, WithdrawSelectionParams,
    UTXO,
};
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
    // Match `choose_utxos_random`'s overflow guard on the dust target.
    net_amount
        .checked_add(params.min_change_amount)
        .ok_or_else(|| "net_amount + min_change_amount overflows u128".to_string())?;

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

    // K is bounded only by what the contract and pool permit. The gas budget is
    // enforced per-candidate against the actual output count rather than via a
    // pessimistic upfront `worst_case_num_output` bound, which would refuse
    // budgets that real selections (small num_output) can easily fit.
    let k_max = std::cmp::min(params.max_withdrawal_input_number, sorted.len());

    if k_max == 0 {
        return Err(format!(
            "No inputs available (max_withdrawal_input_number={}, pool_size={})",
            params.max_withdrawal_input_number,
            sorted.len()
        ));
    }

    // For each K, find a candidate, gate it on the gas budget using the actual
    // output count, and run it through `enforce_passive_management` (same
    // LOW/HIGH zone post-check as `choose_utxos_random`). Fall back to smaller
    // K on any rejection.
    let mut last_err: Option<String> = None;
    for k in (1..=k_max).rev() {
        // Skip K when even the best-case fee (absorption / orchard, 1 output)
        // exceeds the budget — no candidate at this K can fit.
        let best_case_fee = get_gas_fee(chain, k as u64, 1, fee_rate, orchard);
        if best_case_fee > max_gas_fee {
            last_err = Some(format!(
                "best-case fee {best_case_fee} > max_gas_fee {max_gas_fee} at K={k}"
            ));
            continue;
        }

        let Some(selection) = try_k_inputs(k, net_amount, &sorted, params, in_high_zone) else {
            continue;
        };

        let actual_num_output = if orchard {
            1
        } else {
            1 + selection.change_amounts.len() as u64
        };
        let actual_fee = get_gas_fee(chain, k as u64, actual_num_output, fee_rate, orchard);
        if actual_fee > max_gas_fee {
            last_err = Some(format!(
                "actual fee {actual_fee} > max_gas_fee {max_gas_fee} at K={k} \
                 with {actual_num_output} outputs"
            ));
            continue;
        }

        match enforce_passive_management(selection, pool_size, params) {
            Ok(adjusted) => return Ok(adjusted),
            Err(e) => last_err = Some(e),
        }
    }

    Err(last_err.unwrap_or_else(|| {
        format!(
            "No feasible selection for net_amount={net_amount} (k_max={k_max}, pool_size={})",
            sorted.len()
        )
    }))
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

        // change >= min_change_amount.
        // Change-piece cap is `max_change_amount` only — `< min_input` is not enforced.
        let change_amounts = if change >= params.max_change_amount {
            let max_per_piece = params.max_change_amount.saturating_sub(1);
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
    let input_count = fillers.len() + 1;

    // Each change piece must be < max_change_amount only — the contract's
    // `change_i < min_input` constraint is intentionally relaxed here so a
    // single large change piece can absorb the surplus instead of fragmenting
    // into many sub-`min_filler` pieces.
    let max_per_piece = params.max_change_amount.saturating_sub(1);
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

        let change_amounts = if change < params.max_change_amount {
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
            min_change_amount: 537,
            max_change_amount: 2_500_000_000,
            max_withdrawal_input_number: 23,
            max_change_number: 10,
            passive_management_lower_limit: 0,
            passive_management_upper_limit: 6000,
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
            // `change_i < min_input` is intentionally not enforced — the algorithm
            // relaxed that contract rule. Each piece still satisfies the looser
            // `min_change_amount <= c < max_change_amount` bounds.
            for &c in &selection.change_amounts {
                assert!(
                    c >= params.min_change_amount,
                    "change_piece {c} < min_change_amount"
                );
                assert!(
                    c < params.max_change_amount,
                    "change_piece {c} not < max_change_amount {}",
                    params.max_change_amount
                );
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

        let budgets: &[u64] = &[
            200_000, 100_000, 50_000, 20_000, 10_000, 5_000, 3_000, 2_000, 1_000, 500,
        ];

        println!(
            "\n=== anchor_fill | amount={net_amount} sat | fee_rate={fee_rate} | pool=100 tiered ===\n"
        );
        println!(
            "{:>12} | {:>10} | {:>6} | {:>7} | {:>7}",
            "max_gas_fee", "k_max_opt", "inputs", "outputs", "fee"
        );
        println!("{}", "-".repeat(58));

        for &budget in budgets {
            // Best-case feasible K (assuming the cheapest possible output count
            // of 1) — the same per-K filter used inside the algorithm. Shown
            // for context only; the algorithm doesn't cap on this upfront.
            let mut k_max_opt = 0;
            for k in 1..=params.max_withdrawal_input_number {
                if crate::get_gas_fee(chain, k as u64, 1, fee_rate, false) <= budget {
                    k_max_opt = k;
                } else {
                    break;
                }
            }

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
                    let fee = crate::get_gas_fee(chain, n_in as u64, n_out as u64, fee_rate, false);
                    assert_invariants(&sel, net_amount, &params);
                    assert!(
                        fee <= budget,
                        "actual fee {fee} > max_gas_fee {budget} (in={n_in}, out={n_out})"
                    );
                    println!("{budget:>12} | {k_max_opt:>10} | {n_in:>6} | {n_out:>7} | {fee:>7}");
                }
                Err(_) => {
                    println!("{budget:>12} | {k_max_opt:>10} | (infeasible)");
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

    /// Regression: the previous algorithm used a pessimistic upfront bound
    /// (`worst_case_num_output = 1 + max_change_number`) that resolved to
    /// `k_max_by_gas = 0` at `fee_rate=10000` / `max_gas_fee=1600` — bailing
    /// before even trying K=1, even though a real K=1 selection produces only
    /// 2 outputs and fits the budget with a 1527 sat fee. The per-candidate
    /// `actual_fee` check fixes this.
    ///
    /// Under the old upfront-bound code:
    ///   - `(1600 - 141) * 1024 / 10000 = 149` (tx-size budget)
    ///   - `149 - 12 - 6 * 31 = -49` → saturates to 0
    ///   - `k_max_by_gas = 0` → `choose_utxos_anchor_fill` returns Err.
    ///
    /// Under the per-candidate fee check:
    ///   - K=1 best-case fee = 1224 ≤ 1600, try it.
    ///   - Actual fee at 1 input + 1 change = 1527 ≤ 1600 ✓.
    #[test]
    fn anchor_fill_accepts_budget_that_pessimistic_bound_would_reject() {
        let chain = ChainKind::Btc;
        let fee_rate = 10_000u64;
        let params = default_params();
        let pool = pool_100_tiered();
        let pool_size = pool.len() as u32;
        let net_amount: u128 = 1_500_000;
        let max_gas_fee = 1_600u64;

        let sel = choose_utxos_anchor_fill(
            net_amount,
            pool,
            pool_size,
            &params,
            chain,
            fee_rate,
            max_gas_fee,
            false,
        )
        .expect("budget=1600 is feasible — real selection has 2 outputs, not the worst-case 6");

        let actual_fee = crate::get_gas_fee(
            chain,
            sel.selected.len() as u64,
            (1 + sel.change_amounts.len()) as u64,
            fee_rate,
            false,
        );
        assert!(
            actual_fee <= max_gas_fee,
            "actual fee {actual_fee} exceeds budget {max_gas_fee}"
        );
        assert_invariants(&sel, net_amount, &params);
    }

    #[test]
    fn anchor_fill_errors_when_budget_too_small() {
        let chain = ChainKind::Btc;
        let fee_rate = 10_000u64;
        let params = default_params();
        let pool = pool_100_tiered();
        let pool_size = pool.len() as u32;

        let res = choose_utxos_anchor_fill(
            1_500_000, pool, pool_size, &params, chain, fee_rate, 100, false,
        );
        assert!(res.is_err(), "expected Err for tiny budget, got {res:?}");
    }

    /// LOW zone (`pool_size < passive_management_lower_limit`) requires
    /// `input_num < change_num`. The selector must run candidates through
    /// `enforce_passive_management` and either re-split the change or fall
    /// back to a smaller K — never return a selection violating the rule.
    #[test]
    fn anchor_fill_enforces_low_zone() {
        let chain = ChainKind::Btc;
        let fee_rate = 10_000u64;
        // Force LOW zone: pool_size=4 < lower_limit=10.
        let params = WithdrawSelectionParams {
            min_change_amount: 5_000,
            max_change_amount: 2_000_000,
            max_withdrawal_input_number: 50,
            max_change_number: 5,
            passive_management_lower_limit: 10,
            passive_management_upper_limit: 200,
        };

        // 4-UTXO pool, all large enough that re-splitting change into multiple
        // pieces is feasible.
        let mut pool = HashMap::new();
        for (i, bal) in [2_000_000u64, 1_500_000, 1_200_000, 1_000_000]
            .iter()
            .enumerate()
        {
            let (k, v) = mk_utxo(i, *bal);
            pool.insert(k, v);
        }
        let pool_size = pool.len() as u32;

        let net_amount: u128 = 1_400_000;
        let selection = choose_utxos_anchor_fill(
            net_amount, pool, pool_size, &params, chain, fee_rate, 200_000, false,
        )
        .expect("LOW-zone selection should succeed");

        assert_invariants(&selection, net_amount, &params);
        assert!(
            selection.change_amounts.len() > selection.selected.len(),
            "LOW zone violation: inputs={} not < change_outputs={}",
            selection.selected.len(),
            selection.change_amounts.len()
        );
    }

    /// LOW zone with a parameter set where the natural anchor-fill output is a
    /// single change piece — the selector must call `enforce_passive_management`
    /// to re-split it, otherwise `change_num=1 <= input_num=3` violates the rule.
    /// Without the enforcement this test fails (1 piece returned instead of ≥4).
    #[test]
    fn anchor_fill_low_zone_resplits_single_change() {
        let chain = ChainKind::Btc;
        let fee_rate = 10_000u64;
        let params = WithdrawSelectionParams {
            min_change_amount: 1_000,
            // Big max_change_amount so single piece is *naturally* preferred.
            max_change_amount: 10_000_000,
            max_withdrawal_input_number: 50,
            max_change_number: 5,
            passive_management_lower_limit: 10,
            passive_management_upper_limit: 200,
        };

        // 3-UTXO pool ⇒ LOW zone. Sizes chosen so K=3 produces a small change
        // (under min_filler), which without enforcement collapses to 1 piece.
        let mut pool = HashMap::new();
        for (i, bal) in [500_000u64, 400_000, 300_000].iter().enumerate() {
            let (k, v) = mk_utxo(i, *bal);
            pool.insert(k, v);
        }
        let pool_size = pool.len() as u32;

        // net_amount = 1,150,000 → with all 3 inputs (sum 1,200,000) change = 50,000.
        // min_filler = 300,000 → 50,000 < 300,000 → naturally 1 change piece (violates LOW).
        // enforce_passive_management must re-split into ≥ K+1 = 4 pieces.
        let net_amount: u128 = 1_150_000;
        let selection = choose_utxos_anchor_fill(
            net_amount, pool, pool_size, &params, chain, fee_rate, 200_000, false,
        )
        .expect("LOW-zone re-split should succeed");

        assert_invariants(&selection, net_amount, &params);
        assert!(
            selection.change_amounts.len() > selection.selected.len(),
            "LOW zone violation: inputs={} not < change_outputs={}",
            selection.selected.len(),
            selection.change_amounts.len()
        );
    }
}
