//! Anchor-fill UTXO selection.
//!
//! Goal: pick the **maximum** number of UTXOs allowed by a `max_gas_fee`
//! budget while still covering `gross_amount` and producing valid change under
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
//!             - `gross_amount` exactly (absorption, no change), or
//!             - `gross_amount + change` where
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

use crate::{get_gas_fee, UtxoSelection, WithdrawSelectionParams, UTXO};
use omni_types::ChainKind;
use std::collections::HashMap;

/// Choose UTXOs maximizing input count within the `max_gas_fee` budget.
///
/// `gross_amount` is the total amount deducted from the pool by the
/// withdrawal — i.e. `recipient_amount + gas_fee`. The recipient ultimately
/// receives `gross_amount - gas_fee`. Every returned selection has
/// `user_payment == 0`; if the algorithm can't produce an exact payout
/// without dust-padding, it errors instead of silently shrinking the
/// recipient's amount.
///
/// Returns `Err` if the budget is too tight to admit any inputs, if the pool
/// can't cover `gross_amount`, or if no `K`-subset of the pool produces a
/// valid change configuration.
#[allow(clippy::implicit_hasher)]
#[allow(clippy::too_many_arguments)]
pub fn choose_utxos_anchor_fill(
    gross_amount: u128,
    utxos: HashMap<String, UTXO>,
    pool_size: u32,
    params: &WithdrawSelectionParams,
    chain: ChainKind,
    fee_rate: u64,
    max_gas_fee: u64,
    orchard: bool,
    // Extra room (sat) to leave in the change output above `min_change_amount`,
    // so a later RBF can bump the fee by up to `change_reserve` without driving
    // the change below the contract's minimum. Pass `0` if RBF headroom isn't
    // needed. When > 0, absorption (no change) is disabled — there's nothing to
    // shrink for an RBF bump.
    change_reserve: u128,
) -> Result<UtxoSelection, String> {
    // Effective minimum change: `min_change_amount` plus RBF headroom.
    let min_change_required = params
        .min_change_amount
        .checked_add(change_reserve)
        .ok_or_else(|| "min_change_amount + change_reserve overflows u128".to_string())?;

    // Overflow guard on the dust target (mirrors `choose_utxos_random`).
    gross_amount
        .checked_add(min_change_required)
        .ok_or_else(|| "gross_amount + min_change_required overflows u128".to_string())?;

    // LOW zone (`pool_size < passive_management_lower_limit`) requires
    // `input_num < change_num`, which is unreachable under the single-change
    // rule. Bail upfront; the caller should run active utxo management
    // instead of relying on a withdrawal to consolidate.
    if pool_size < params.passive_management_lower_limit {
        return Err(format!(
            "LOW zone (pool_size={pool_size} < passive_management_lower_limit={}) is \
             incompatible with the single-change-output rule; run active utxo management \
             instead",
            params.passive_management_lower_limit
        ));
    }

    let in_high_zone = pool_size > params.passive_management_upper_limit;

    // HIGH zone: drop UTXOs > gross_amount so the result satisfies `input_num > change_num`
    // downstream (single-input + 1-change becomes structurally impossible).
    let utxos = if in_high_zone {
        utxos
            .into_iter()
            .filter(|(_, u)| u128::from(u.balance) <= gross_amount)
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

    // For each K, find a candidate and gate it on the gas budget using the
    // actual output count. HIGH-zone (`input_num > change_num`) is enforced
    // inline by `try_single_input` / `try_anchor_search` — the pool filter
    // above plus the single-change rule make K ≥ 2 trivially satisfy it.
    // Fall back to smaller K on any rejection.
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

        let Some(selection) = try_k_inputs(
            k,
            gross_amount,
            &sorted,
            params,
            min_change_required,
            in_high_zone,
        ) else {
            continue;
        };

        let actual_num_output = if orchard {
            1
        } else {
            1 + selection.change_amounts.len() as u64
        };
        debug_assert!(
            actual_num_output <= 2,
            "anchor_fill produced {actual_num_output} outputs; expected ≤ 2"
        );
        let actual_fee = get_gas_fee(chain, k as u64, actual_num_output, fee_rate, orchard);
        if actual_fee > max_gas_fee {
            last_err = Some(format!(
                "actual fee {actual_fee} > max_gas_fee {max_gas_fee} at K={k} \
                 with {actual_num_output} outputs"
            ));
            continue;
        }

        return Ok(selection);
    }

    Err(last_err.unwrap_or_else(|| {
        format!(
            "No feasible selection for gross_amount={gross_amount} (k_max={k_max}, pool_size={})",
            sorted.len()
        )
    }))
}

fn try_k_inputs(
    k: usize,
    gross_amount: u128,
    sorted_pool: &[(String, UTXO)],
    params: &WithdrawSelectionParams,
    min_change_required: u128,
    in_high_zone: bool,
) -> Option<UtxoSelection> {
    if k == 0 || sorted_pool.len() < k {
        return None;
    }

    if k == 1 {
        return try_single_input(
            gross_amount,
            sorted_pool,
            params,
            min_change_required,
            in_high_zone,
        );
    }

    // K >= 2: anchor + (K-1) consecutive fillers.
    // filler_start = 0 maximizes consolidation; growing it widens the change
    // window (larger min_filler) at the cost of consuming fewer smalls.
    let max_filler_start = sorted_pool.len() - k;
    for filler_start in 0..=max_filler_start {
        let fillers = &sorted_pool[filler_start..filler_start + k - 1];
        let candidates = &sorted_pool[filler_start + k - 1..];

        if let Some(sel) = try_anchor_search(
            fillers,
            candidates,
            gross_amount,
            params,
            min_change_required,
        ) {
            return Some(sel);
        }
    }
    None
}

fn try_single_input(
    gross_amount: u128,
    sorted_pool: &[(String, UTXO)],
    params: &WithdrawSelectionParams,
    min_change_required: u128,
    in_high_zone: bool,
) -> Option<UtxoSelection> {
    let reserve_active = min_change_required > params.min_change_amount;
    // Best-fit single input: smallest balance >= gross_amount that yields valid change.
    let lo = sorted_pool.partition_point(|(_, u)| u128::from(u.balance) < gross_amount);

    for entry in &sorted_pool[lo..] {
        let bal = u128::from(entry.1.balance);
        let change = bal - gross_amount;

        if change == 0 {
            // Absorption leaves no change to shrink for an RBF bump, so skip
            // when a reserve is required.
            if reserve_active {
                continue;
            }
            return Some(UtxoSelection {
                selected: vec![entry.clone()],
                user_payment: 0,
                change_amounts: vec![],
            });
        }

        if change < min_change_required {
            // Dust zone: change is positive but too small to be a valid output.
            // We don't dust-pad (which would silently shrink the recipient's
            // payout) — skip this candidate and try the next bigger one. If
            // none satisfies, the outer loop falls back to lower K.
            continue;
        }

        // change ∈ [min_change_required, ?]. The single-change-output rule
        // requires `change < max_change_amount`; if not, skip this candidate
        // and try the next bigger one. We never split a K=1 change into
        // multiple pieces.
        if change >= params.max_change_amount {
            continue;
        }

        if in_high_zone {
            // HIGH zone: input_num=1 > change_num required → change_num must be 0.
            // The HIGH-zone pool filter already drops UTXOs > gross_amount, so
            // this path only fires when gross_amount equals an existing UTXO
            // balance (handled by the `change == 0` absorption arm above).
            continue;
        }

        return Some(UtxoSelection {
            selected: vec![entry.clone()],
            user_payment: 0,
            change_amounts: vec![change],
        });
    }
    None
}

fn try_anchor_search(
    fillers: &[(String, UTXO)],
    candidates: &[(String, UTXO)],
    gross_amount: u128,
    params: &WithdrawSelectionParams,
    min_change_required: u128,
) -> Option<UtxoSelection> {
    if fillers.is_empty() || candidates.is_empty() {
        return None;
    }

    let sum_fillers: u128 = fillers.iter().map(|(_, u)| u128::from(u.balance)).sum();
    let reserve_active = min_change_required > params.min_change_amount;

    // The bridge withdrawal shape is 1 target + 0-or-1 change. We never split
    // into multiple change outputs, so the change must fit a single piece in
    // `[min_change_amount, max_change_amount)`. The contract's
    // `change_i < min_input` constraint is intentionally **not** enforced here
    // — relaxing it lets a single large change piece absorb the surplus from
    // many small fillers instead of fragmenting into sub-`min_filler` pieces.
    let valid_change_max = params.max_change_amount;
    if valid_change_max == 0 {
        return None;
    }

    // 1) Absorption — anchor balance brings sum to exactly gross_amount.
    //    Skipped when an RBF reserve is required: absorption leaves no change
    //    output to shrink, so a later RBF bump has no headroom.
    if !reserve_active && sum_fillers < gross_amount {
        let abs_target = gross_amount - sum_fillers;
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
    //    `min_change_required = min_change_amount + change_reserve` ensures the
    //    total change leaves room for an RBF fee bump of up to `change_reserve`.
    let lower = gross_amount
        .saturating_add(min_change_required)
        .saturating_sub(sum_fillers);
    let upper = gross_amount
        .saturating_add(valid_change_max)
        .saturating_sub(sum_fillers);

    if lower >= upper {
        return None;
    }

    // The smallest candidate with balance ≥ lower is the only one we need:
    // candidates are sorted ascending, so if its balance is also < upper it's
    // a valid anchor (change is guaranteed to be a single piece in
    // `[min_change_required, max_change_amount)`). HIGH-zone rule
    // `input_num > change_num` is `K ≥ 2 > 1`, trivially satisfied here.
    let lo_idx = candidates.partition_point(|(_, u)| u128::from(u.balance) < lower);
    let entry = candidates.get(lo_idx)?;
    let anchor_bal = u128::from(entry.1.balance);
    if anchor_bal >= upper {
        return None;
    }

    let total = sum_fillers + anchor_bal;
    let change = total - gross_amount;

    let mut selected: Vec<(String, UTXO)> = fillers.to_vec();
    selected.push(entry.clone());
    Some(UtxoSelection {
        selected,
        user_payment: 0,
        change_amounts: vec![change],
    })
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
        gross_amount: u128,
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
        // anchor_fill never splits change — every successful selection has at
        // most one change output.
        assert!(
            selection.change_amounts.len() <= 1,
            "change_num {} > 1 — anchor_fill should never split change",
            selection.change_amounts.len()
        );

        let sum_inputs: u128 = selection
            .selected
            .iter()
            .map(|(_, u)| u128::from(u.balance))
            .sum();
        let sum_change: u128 = selection.change_amounts.iter().sum();
        assert_eq!(
            sum_inputs + selection.user_payment,
            gross_amount + sum_change,
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
        let gross_amount: u128 = 1_500_000;

        let budgets: &[u64] = &[
            200_000, 100_000, 50_000, 20_000, 10_000, 5_000, 3_000, 2_000, 1_000, 500,
        ];

        println!(
            "\n=== anchor_fill | amount={gross_amount} sat | fee_rate={fee_rate} | pool=100 tiered ===\n"
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
                gross_amount,
                pool.clone(),
                pool_size,
                &params,
                chain,
                fee_rate,
                budget,
                false,
                0,
            ) {
                Ok(sel) => {
                    let n_in = sel.selected.len();
                    let n_out = 1 + sel.change_amounts.len();
                    let fee = crate::get_gas_fee(chain, n_in as u64, n_out as u64, fee_rate, false);
                    assert_invariants(&sel, gross_amount, &params);
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
            0,
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
            0,
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
        let gross_amount: u128 = 1_500_000;
        let max_gas_fee = 1_600u64;

        let sel = choose_utxos_anchor_fill(
            gross_amount,
            pool,
            pool_size,
            &params,
            chain,
            fee_rate,
            max_gas_fee,
            false,
            0,
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
        assert_invariants(&sel, gross_amount, &params);
    }

    #[test]
    fn anchor_fill_errors_when_budget_too_small() {
        let chain = ChainKind::Btc;
        let fee_rate = 10_000u64;
        let params = default_params();
        let pool = pool_100_tiered();
        let pool_size = pool.len() as u32;

        let res = choose_utxos_anchor_fill(
            1_500_000, pool, pool_size, &params, chain, fee_rate, 100, false, 0,
        );
        assert!(res.is_err(), "expected Err for tiny budget, got {res:?}");
    }

    /// LOW zone (`pool_size < passive_management_lower_limit`) requires
    /// `input_num < change_num`, which is unreachable under the single-change
    /// rule. The selector must bail upfront with a clear error rather than
    /// silently produce a contract-incompatible selection.
    #[test]
    fn anchor_fill_rejects_low_zone() {
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

        let mut pool = HashMap::new();
        for (i, bal) in [2_000_000u64, 1_500_000, 1_200_000, 1_000_000]
            .iter()
            .enumerate()
        {
            let (k, v) = mk_utxo(i, *bal);
            pool.insert(k, v);
        }
        let pool_size = pool.len() as u32;

        let res = choose_utxos_anchor_fill(
            1_400_000, pool, pool_size, &params, chain, fee_rate, 200_000, false, 0,
        );
        assert!(
            res.is_err(),
            "LOW zone must Err under the single-change rule, got {res:?}"
        );
        assert!(
            res.unwrap_err().contains("LOW zone"),
            "error message should mention LOW zone"
        );
    }

    /// Every successful selection must produce at most 2 outputs (1 target +
    /// at most 1 change).
    #[test]
    fn anchor_fill_never_produces_more_than_two_outputs() {
        let chain = ChainKind::Btc;
        let fee_rate = 3_000u64;
        let params = default_params();
        let pool = pool_100_tiered();
        let pool_size = pool.len() as u32;
        let gross_amount: u128 = 1_500_000;

        for &budget in &[
            200_000u64, 100_000, 50_000, 20_000, 10_000, 5_000, 3_000, 2_000, 1_000,
        ] {
            if let Ok(sel) = choose_utxos_anchor_fill(
                gross_amount,
                pool.clone(),
                pool_size,
                &params,
                chain,
                fee_rate,
                budget,
                false,
                0,
            ) {
                assert!(
                    sel.change_amounts.len() <= 1,
                    "budget={budget}: {} change outputs (expected ≤ 1)",
                    sel.change_amounts.len()
                );
            }
        }
    }

    /// `change_reserve > 0` must leave that many sats of headroom above
    /// `min_change_amount` in the total change, so a later RBF bump of up to
    /// `change_reserve` can shrink the change without driving it below the
    /// contract minimum. Also: absorption (no change) must NOT be selected
    /// when a reserve is required.
    #[test]
    fn anchor_fill_honors_change_reserve_for_rbf_headroom() {
        let chain = ChainKind::Btc;
        let fee_rate = 10_000u64;
        let params = default_params();
        let pool = pool_100_tiered();
        let pool_size = pool.len() as u32;
        let gross_amount: u128 = 1_500_000;
        let max_gas_fee = 200_000u64;
        let change_reserve: u128 = 20_000;

        let sel = choose_utxos_anchor_fill(
            gross_amount,
            pool,
            pool_size,
            &params,
            chain,
            fee_rate,
            max_gas_fee,
            false,
            change_reserve,
        )
        .expect("selection with RBF reserve should succeed");

        assert_invariants(&sel, gross_amount, &params);

        // Absorption is forbidden when reserve is required.
        assert!(
            !sel.change_amounts.is_empty(),
            "change_reserve > 0 must produce a non-empty change output"
        );

        // Total change must clear `min_change_amount + change_reserve`, so an
        // RBF bump up to `change_reserve` can shrink it and still satisfy the
        // contract's per-piece minimum.
        let total_change: u128 = sel.change_amounts.iter().sum();
        assert!(
            total_change >= params.min_change_amount + change_reserve,
            "total_change {total_change} < min_change_amount {} + reserve {change_reserve}",
            params.min_change_amount
        );
    }

    /// A reserve so large the contract's per-tx change cap can't supply it
    /// must produce a clean error rather than silently relax the headroom
    /// guarantee. Uses tight params so `valid_change_max = max_change_number
    /// × max_change_amount` is a small, exact bound that the reserve exceeds.
    #[test]
    fn anchor_fill_errors_when_reserve_unsatisfiable() {
        let chain = ChainKind::Btc;
        let fee_rate = 10_000u64;
        // valid_change_max = 5 * 2_000_000 = 10_000_000. A 20_000_000 reserve
        // exceeds this and no anchor can produce a fitting change.
        let params = WithdrawSelectionParams {
            min_change_amount: 5_000,
            max_change_amount: 2_000_000,
            max_withdrawal_input_number: 50,
            max_change_number: 5,
            passive_management_lower_limit: 10,
            passive_management_upper_limit: 200,
        };
        let pool = pool_100_tiered();
        let pool_size = pool.len() as u32;

        let res = choose_utxos_anchor_fill(
            1_500_000, pool, pool_size, &params, chain, fee_rate, 200_000, false, 20_000_000,
        );
        assert!(res.is_err(), "unsatisfiable reserve must Err, got {res:?}");
    }
}
