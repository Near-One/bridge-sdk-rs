use crate::{get_gas_fee, UTXO};
use bitcoin::OutPoint;
use bridge_connector_common::result::{BridgeSdkError, Result};
use std::collections::HashMap;

/// Constraints from the BTC connector contract that bound a single withdrawal
/// transaction. Defaults match the production `btc-bridge` contract config.
#[derive(Clone, Debug)]
pub struct SelectionLimits {
    /// Hard cap on input UTXOs in one withdrawal tx
    /// (`max_withdrawal_input_number`).
    pub max_inputs: usize,
    /// Smallest allowed change output value. Anything below this is folded
    /// into the fee instead of becoming a (dust) output (`min_change_amount`).
    pub min_change_amount: u64,
    /// Largest allowed change output value (`max_change_amount`).
    pub max_change_amount: u64,
    /// Floor on total transaction fee (`min_btc_gas_fee`).
    pub min_gas_fee: u64,
    /// Ceiling on total transaction fee (`max_btc_gas_fee`).
    pub max_gas_fee: u64,
}

impl Default for SelectionLimits {
    fn default() -> Self {
        Self {
            max_inputs: 10,
            min_change_amount: 537,
            max_change_amount: 100_000_000,
            min_gas_fee: 100,
            max_gas_fee: 5_000,
        }
    }
}

const BNB_MAX_TRIES: u32 = 100_000;

type Selection<'a> = (Vec<(&'a String, &'a UTXO)>, u128, u128);

fn utxo_to_out_points(utxos: Vec<(&String, &UTXO)>) -> Result<Vec<OutPoint>> {
    utxos
        .into_iter()
        .map(|(txid, utxo)| {
            let txid_str = txid.split('@').next().ok_or_else(|| {
                BridgeSdkError::UtxoClientError(format!("Invalid txid format: {txid}"))
            })?;

            let parsed_txid = txid_str.parse().map_err(|e| {
                BridgeSdkError::UtxoClientError(format!(
                    "Failed to parse txid '{txid_str}' into bitcoin::Txid: {e}"
                ))
            })?;

            Ok(OutPoint::new(parsed_txid, utxo.vout))
        })
        .collect()
}

/// Pick UTXOs to fund a withdrawal of `amount` sats.
///
/// Tries Branch-and-Bound first (Erhardt 2016 / Algorithm 6-7 of Ramezan et al.,
/// "A Survey on Coin Selection Algorithms in UTXO-based Blockchains"). BnB
/// looks for an input set whose total value lands in
/// `[amount + computed_fee, amount + computed_fee + min_change_amount - 1]`,
/// because anything in that band can be absorbed into the fee instead of
/// becoming a dust change output — yielding a change-free transaction. A
/// change-free tx saves the cost of an output now and the cost of an input
/// later (when that change UTXO would otherwise be spent), which is the
/// dominant long-run fee win for a high-throughput bridge hot wallet.
///
/// Falls back to descending-value greedy when no change-free match exists in
/// `BNB_MAX_TRIES` iterations or under the `max_inputs` cap. The greedy path
/// honours both `min_change_amount` and `max_change_amount`.
///
/// Returns `(out_points, total_balance, gas_fee)`. Caller computes
/// `change = balance - amount - gas_fee`. For BnB-success the change is 0 and
/// the small excess has been absorbed into `gas_fee`.
#[allow(clippy::implicit_hasher)]
pub fn choose_utxos(
    amount: u128,
    utxos: &HashMap<String, UTXO>,
    fee_rate: u64,
    limits: &SelectionLimits,
) -> Result<(Vec<OutPoint>, u128, u128)> {
    let mut utxo_list: Vec<(&String, &UTXO)> = utxos.iter().collect();
    utxo_list.sort_by(|a, b| b.1.balance.cmp(&a.1.balance));

    if let Some((selected, balance, gas_fee)) = bnb_select(&utxo_list, amount, fee_rate, limits) {
        let out_points = utxo_to_out_points(selected)?;
        return Ok((out_points, balance, gas_fee));
    }

    if let Some((selected, balance, gas_fee)) = greedy_select(&utxo_list, amount, fee_rate, limits)
    {
        let out_points = utxo_to_out_points(selected)?;
        return Ok((out_points, balance, gas_fee));
    }

    Err(BridgeSdkError::UtxoClientError(format!(
        "Could not select UTXOs to fund {amount} sats within contract limits \
         (max_inputs={}, min_change={}, max_change={}, min_gas={}, max_gas={})",
        limits.max_inputs,
        limits.min_change_amount,
        limits.max_change_amount,
        limits.min_gas_fee,
        limits.max_gas_fee,
    )))
}

/// Branch-and-Bound search for a change-free input set, respecting contract
/// limits. `sorted` must be sorted descending by `balance`; effective value
/// (`balance - cost_per_input`) preserves that order so the largest UTXOs are
/// tried first, biasing toward few-input solutions.
fn bnb_select<'a>(
    sorted: &[(&'a String, &'a UTXO)],
    amount: u128,
    fee_rate: u64,
    limits: &SelectionLimits,
) -> Option<Selection<'a>> {
    let cost_in = u128::from(fee_rate.saturating_mul(68) / 1024);
    let cost_out = u128::from(fee_rate.saturating_mul(31) / 1024);
    let base = u128::from(fee_rate.saturating_mul(12) / 1024 + 141);

    let target = amount.checked_add(base)?.checked_add(cost_out)?;
    // Widen the match range up to (min_change_amount - 1): any "change" below
    // min_change_amount can't be emitted as a real output anyway, so we accept
    // that wider window as change-free. Excess goes to the miner as fee.
    let match_range = std::cmp::max(
        cost_in.saturating_add(cost_out),
        u128::from(limits.min_change_amount).saturating_sub(1),
    );
    let upper = target.checked_add(match_range)?;
    let min_gas = u128::from(limits.min_gas_fee);
    let max_gas = u128::from(limits.max_gas_fee);

    let n = sorted.len();
    if n == 0 || limits.max_inputs == 0 {
        return None;
    }

    let eff: Vec<u128> = sorted
        .iter()
        .map(|(_, u)| u128::from(u.balance).saturating_sub(cost_in))
        .collect();
    let bal: Vec<u128> = sorted.iter().map(|(_, u)| u128::from(u.balance)).collect();
    let mut suffix = vec![0u128; n + 1];
    for i in (0..n).rev() {
        suffix[i] = suffix[i + 1].saturating_add(eff[i]);
    }
    if suffix[0] < target {
        return None;
    }

    let ctx = BnbCtx {
        eff: &eff,
        bal: &bal,
        suffix: &suffix,
        target,
        upper,
        amount,
        min_gas,
        max_gas,
        max_inputs: limits.max_inputs,
    };
    let mut state = BnbState {
        included: vec![false; n],
        current_eff: 0,
        current_bal: 0,
        current_count: 0,
        tries: BNB_MAX_TRIES,
        found: None,
    };

    state.dfs(&ctx, 0);

    let (pattern, balance, gas_fee) = state.found?;
    let selected: Vec<(&String, &UTXO)> = pattern
        .iter()
        .enumerate()
        .filter_map(|(i, &b)| if b { Some(sorted[i]) } else { None })
        .collect();
    Some((selected, balance, gas_fee))
}

struct BnbCtx<'a> {
    eff: &'a [u128],
    bal: &'a [u128],
    suffix: &'a [u128],
    target: u128,
    upper: u128,
    amount: u128,
    min_gas: u128,
    max_gas: u128,
    max_inputs: usize,
}

struct BnbState {
    included: Vec<bool>,
    current_eff: u128,
    current_bal: u128,
    current_count: usize,
    tries: u32,
    found: Option<(Vec<bool>, u128, u128)>,
}

impl BnbState {
    fn dfs(&mut self, ctx: &BnbCtx, i: usize) {
        if self.found.is_some() || self.tries == 0 {
            return;
        }
        self.tries -= 1;

        if self.current_eff > ctx.upper {
            return;
        }
        if self.current_eff.saturating_add(ctx.suffix[i]) < ctx.target {
            return;
        }
        if self.current_eff >= ctx.target {
            let fee = self.current_bal.saturating_sub(ctx.amount);
            if fee >= ctx.min_gas && fee <= ctx.max_gas {
                self.found = Some((self.included.clone(), self.current_bal, fee));
            }
            return;
        }
        if i >= ctx.eff.len() || self.current_count >= ctx.max_inputs {
            return;
        }

        self.included[i] = true;
        self.current_eff = self.current_eff.saturating_add(ctx.eff[i]);
        self.current_bal = self.current_bal.saturating_add(ctx.bal[i]);
        self.current_count += 1;
        self.dfs(ctx, i + 1);
        self.included[i] = false;
        self.current_eff -= ctx.eff[i];
        self.current_bal -= ctx.bal[i];
        self.current_count -= 1;

        if self.found.is_some() {
            return;
        }
        self.dfs(ctx, i + 1);
    }
}

/// Descending-value greedy fallback that respects every PSBT-validation
/// constraint enforced by `satoshi-bridge/src/psbt.rs`:
///
/// - `change >= min_change_amount` (or change-free)
/// - `change < min(input balances)` — anti-bloat rule, always required
/// - `change < max_change_amount` — only when `input_num > change_num` (i.e.,
///   when the tx has more than one input). Single-input txs are allowed to
///   produce a change of any size up to `min_input − 1`, which is essential
///   for spending lone large UTXOs the bridge has accumulated.
/// - `min_gas_fee <= fee <= max_gas_fee`
/// - `selected.len() <= max_inputs`
///
/// Iterates UTXOs in descending order, so the just-added UTXO is always the
/// smallest input — `change < utxo.balance` is therefore equivalent to
/// `change < min_input_amount`.
fn greedy_select<'a>(
    sorted: &[(&'a String, &'a UTXO)],
    amount: u128,
    fee_rate: u64,
    limits: &SelectionLimits,
) -> Option<Selection<'a>> {
    let min_change = u128::from(limits.min_change_amount);
    let max_change = u128::from(limits.max_change_amount);
    let min_gas = u128::from(limits.min_gas_fee);
    let max_gas = u128::from(limits.max_gas_fee);

    let mut selected: Vec<(&'a String, &'a UTXO)> = Vec::new();
    let mut balance: u128 = 0;

    for &(txid, utxo) in sorted {
        if selected.len() >= limits.max_inputs {
            break;
        }
        let next_count = (selected.len() + 1) as u64;
        let next_balance = balance.saturating_add(u128::from(utxo.balance));
        let fee = u128::from(get_gas_fee(next_count, 2, fee_rate)).max(min_gas);
        if fee > max_gas {
            return None;
        }

        let target_with_change = amount.checked_add(fee)?.checked_add(min_change)?;
        if next_balance >= target_with_change {
            let change = next_balance - amount - fee;
            let smallest_input = u128::from(utxo.balance);
            // Contract: `change < max_change_amount` is enforced only when
            // `input_num > change_num`. We only ever emit one change output,
            // so the rule applies iff selected.len() + 1 > 1 (multi-input).
            let max_change_ok = next_count == 1 || change < max_change;
            // Contract: `change < min_input_amount`, always.
            let min_input_ok = change < smallest_input;
            if max_change_ok && min_input_ok {
                selected.push((txid, utxo));
                return Some((selected, next_balance, fee));
            }
            // Selection valid in size but would fail a contract check. Skip
            // and try smaller UTXOs further down the descending list.
            continue;
        }
        selected.push((txid, utxo));
        balance = next_balance;
    }

    // Loop ended without completing — verify the accumulated selection
    // satisfies every contract constraint.
    let fee = u128::from(get_gas_fee(selected.len() as u64, 2, fee_rate)).max(min_gas);
    if fee > max_gas {
        return None;
    }
    let change = balance.checked_sub(amount.checked_add(fee)?)?;
    if change < min_change {
        return None;
    }
    let n_inputs = selected.len();
    if n_inputs > 1 && change >= max_change {
        return None;
    }
    let smallest_input = selected.iter().map(|(_, u)| u128::from(u.balance)).min()?;
    if change >= smallest_input {
        return None;
    }
    Some((selected, balance, fee))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn utxo(path: &str, balance: u64, idx: u32) -> (String, UTXO) {
        // Keys mirror the production format `<txid_hex>@<vout>` produced by
        // the contract's `get_utxos_paged`. The hex prefix is derived from
        // (balance, idx) to keep keys unique even when balances repeat.
        let txid = format!(
            "{:032x}{:032x}@{idx}",
            u128::from(balance),
            u128::from(idx)
        );
        (
            txid,
            UTXO {
                path: path.to_string(),
                tx_bytes: vec![],
                vout: idx,
                balance,
            },
        )
    }

    fn pool(balances: &[u64]) -> HashMap<String, UTXO> {
        balances
            .iter()
            .enumerate()
            .map(|(i, &b)| utxo(&format!("p{i}"), b, i as u32))
            .collect()
    }

    fn limits_no_floor() -> SelectionLimits {
        // Disable gas-fee floor so tests can use fee_rate = 0 cleanly.
        SelectionLimits {
            min_gas_fee: 0,
            ..SelectionLimits::default()
        }
    }

    #[test]
    fn bnb_finds_exact_match_two_inputs() {
        // At fee_rate=0 the per-byte costs vanish but the formula still has a
        // flat 141-sat overhead, so target = amount + 141. {7000, 3000} hits
        // it exactly → change-free.
        let pool = pool(&[50_000, 7_000, 3_000, 999]);
        let (sel, balance, fee) = choose_utxos(9_859, &pool, 0, &limits_no_floor()).unwrap();
        assert_eq!(sel.len(), 2);
        assert_eq!(balance, 10_000);
        assert_eq!(fee, 141);
    }

    #[test]
    fn bnb_widened_match_range_uses_min_change_window() {
        // {10_300} sums to 10_300; target = 9_859 + 141 = 10_000; the original
        // BnB match_range at fee_rate=0 is 0 sats so {10_300} would NOT match.
        // With min_change_amount = 537, match_range widens to 536, so 10_300
        // (= target + 300) is accepted as change-free with the 300 absorbed
        // into the fee.
        let pool = pool(&[50_000, 10_300, 999]);
        let (sel, balance, fee) = choose_utxos(9_859, &pool, 0, &limits_no_floor()).unwrap();
        assert_eq!(sel.len(), 1);
        assert_eq!(balance, 10_300);
        assert_eq!(fee, 441); // 141 base + 300 absorbed
    }

    #[test]
    fn bnb_respects_max_inputs_cap() {
        // Exact match needs 5 UTXOs of 200 each (1000 = 9_859 - 8_859 + 141).
        // With max_inputs=4, BnB must give up; greedy fallback also fails
        // because 4 * 200 < target. choose_utxos returns Err.
        let pool = pool(&[200, 200, 200, 200, 200, 200]);
        let limits = SelectionLimits {
            max_inputs: 4,
            min_gas_fee: 0,
            ..SelectionLimits::default()
        };
        let res = choose_utxos(859, &pool, 0, &limits);
        assert!(res.is_err());
    }

    #[test]
    fn dust_absorption_is_capped_by_max_gas_fee() {
        // Scenario: amount = 5_000 sats, pool = [3_000, 2_500] (sum = 5_500).
        // Choosing both UTXOs change-free leaves 500 sats of "would-be change",
        // below min_change_amount = 537 → BnB absorbs it as fee. The contract
        // (psbt.rs:234-243) enforces `actual_received ≤ user_request −
        // withdraw_fee − gas_fee`, so a relayer that pre-computed `amount` for
        // a small expected gas_fee will be rejected if the SDK silently
        // absorbs an extra 359 sats into the fee.
        //
        // The SDK guards against this via `max_gas_fee` — callers must pass
        // their actual fee budget (not the contract's hard 5_000-sat cap).
        // With a tight budget, the SDK refuses the dust-absorbing path.
        let pool = pool(&[3_000, 2_500]);

        // (1) Loose limits: caller used the contract's outer max as
        // max_gas_fee. SDK accepts the change-free selection and absorbs all
        // 500 sats into gas_fee. If the caller had pre-computed amount with a
        // smaller fee estimate, the contract will reject this.
        let loose = SelectionLimits {
            min_gas_fee: 0,
            ..SelectionLimits::default()
        };
        let (inputs, balance, fee) = choose_utxos(5_000, &pool, 0, &loose).unwrap();
        assert_eq!(inputs.len(), 2);
        assert_eq!(balance, 5_500);
        assert_eq!(fee, 500); // 141 base + 359 absorbed dust

        // (2) Tight limits: caller's true budget allows ~200 sats of fee. The
        // 500-sat absorbed-fee selection now exceeds max_gas_fee. BnB rejects
        // it; greedy can't produce a real change ≥ min_change_amount = 537
        // either (would need balance ≥ amount + fee + 537 = 5_737, pool only
        // has 5_500). choose_utxos returns Err — exactly the behaviour that
        // prevents the contract-side rejection.
        let tight = SelectionLimits {
            min_gas_fee: 0,
            max_gas_fee: 200,
            ..SelectionLimits::default()
        };
        let res = choose_utxos(5_000, &pool, 0, &tight);
        assert!(
            res.is_err(),
            "tight max_gas_fee must block the dust-absorbed selection",
        );
    }

    #[test]
    fn single_input_change_can_exceed_max_change_amount() {
        // Contract enforces `change < max_change_amount` only when
        // `input_num > change_num` (psbt.rs:218–225). A 1-input + 1-change
        // tx is allowed any change up to `min_input - 1`. So a 10 BTC UTXO
        // funding a tiny withdrawal is a valid selection, even though the
        // resulting change (~10 BTC) is well above the 1 BTC max_change_amount.
        let pool = pool(&[1_000_000_000, 6_400]);
        let limits = SelectionLimits {
            min_gas_fee: 0,
            ..SelectionLimits::default()
        };
        let (sel, balance, _fee) = choose_utxos(5_000, &pool, 0, &limits).unwrap();
        assert_eq!(sel.len(), 1);
        // Descending-greedy picks the largest first. The 10 BTC UTXO's
        // change ≈ 1B - 5141 ≈ 999_994_859, which is < min_input = 1B, so
        // the contract accepts it.
        assert_eq!(balance, 1_000_000_000);
    }

    /// Asserts that a successful `choose_utxos` result satisfies every
    /// constraint enforced by `satoshi-bridge/src/psbt.rs`. Both BnB and the
    /// greedy fallback must produce selections that pass through the contract
    /// untouched, so we verify on the public API rather than on the internal
    /// path.
    fn assert_passes_contract(
        sel: &[bitcoin::OutPoint],
        balance: u128,
        fee: u128,
        amount: u128,
        utxos: &HashMap<String, UTXO>,
        limits: &SelectionLimits,
    ) {
        // Reverse-look-up the chosen UTXOs to read their balances.
        let mut input_balances: Vec<u128> = Vec::with_capacity(sel.len());
        for op in sel {
            let key = format!("{}@{}", op.txid, op.vout);
            let u = utxos.get(&key).expect("selected outpoint missing from pool");
            input_balances.push(u128::from(u.balance));
        }
        let total: u128 = input_balances.iter().sum();
        assert_eq!(total, balance, "reported balance must match input sum");
        let change = balance - amount - fee;
        assert!(
            fee >= u128::from(limits.min_gas_fee) && fee <= u128::from(limits.max_gas_fee),
            "fee {fee} outside [{}, {}]",
            limits.min_gas_fee,
            limits.max_gas_fee,
        );
        assert!(sel.len() <= limits.max_inputs, "too many inputs");
        if change > 0 {
            assert!(
                change >= u128::from(limits.min_change_amount),
                "change {change} below min_change_amount {}",
                limits.min_change_amount,
            );
            let min_input = *input_balances.iter().min().unwrap();
            assert!(
                change < min_input,
                "change {change} not < min_input {min_input} (psbt.rs:196)",
            );
            // The `change < max_change_amount` rule applies only when
            // input_num > change_num (psbt.rs:218); we always emit ≤ 1 change
            // output, so it kicks in iff selected.len() > 1.
            if sel.len() > 1 {
                assert!(
                    change < u128::from(limits.max_change_amount),
                    "multi-input change {change} not < max_change_amount {}",
                    limits.max_change_amount,
                );
            }
        }
    }

    #[test]
    fn outputs_satisfy_contract_constraints_across_pool_shapes() {
        // Property check: across a variety of pool shapes and amounts, every
        // successful selection must pass the satoshi-bridge PSBT validator.
        // We don't care which path (BnB vs. greedy) produced it.
        let cases: &[(u128, &[u64], SelectionLimits)] = &[
            // Original "polarized pool": 1-input solution legal because the
            // contract waives max_change_amount when input_num == change_num.
            (
                5_000,
                &[1_000_000_000, 6_400][..],
                SelectionLimits {
                    min_gas_fee: 0,
                    ..SelectionLimits::default()
                },
            ),
            // Three equal small UTXOs that look like they'd violate
            // change < min_input if greedy were naive — verify the result
            // (whichever path produces it) still passes.
            (
                1_000,
                &[600, 600, 600][..],
                SelectionLimits {
                    min_gas_fee: 0,
                    min_change_amount: 100,
                    ..SelectionLimits::default()
                },
            ),
            // Multi-input where the second-largest pushes change above
            // max_change_amount unless the algorithm is careful.
            (
                5_000,
                &[150_000_000, 150_000_000][..],
                SelectionLimits {
                    min_gas_fee: 0,
                    ..SelectionLimits::default()
                },
            ),
            // Many small UTXOs — greedy hits the max_inputs cap.
            (
                900,
                &[200, 200, 200, 200, 200, 200, 200][..],
                SelectionLimits {
                    min_gas_fee: 0,
                    ..SelectionLimits::default()
                },
            ),
        ];
        for (amount, balances, limits) in cases {
            let p = pool(balances);
            if let Ok((sel, balance, fee)) = choose_utxos(*amount, &p, 0, limits) {
                assert_passes_contract(&sel, balance, fee, *amount, &p, limits);
            }
        }
    }

    #[test]
    fn empty_pool_returns_error() {
        let res = choose_utxos(1_000, &HashMap::new(), 1024, &SelectionLimits::default());
        assert!(res.is_err());
    }

    #[test]
    fn bnb_prefers_fewer_inputs() {
        // {10_000} and {6_000, 4_000} both fund the target. Inclusion-first
        // DFS on the value-descending pool must pick the single-input set.
        let pool = pool(&[10_000, 6_000, 4_000, 1_000]);
        let (sel, balance, _) = choose_utxos(9_859, &pool, 0, &limits_no_floor()).unwrap();
        assert_eq!(sel.len(), 1);
        assert_eq!(balance, 10_000);
    }
}
