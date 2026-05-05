//! Replay the production deposit + withdrawal streams chronologically against
//! the BnB+greedy coin-selection algorithm.
//!
//! Usage:
//!     cargo run -p btc-utils --example choose-utxo-simulator --release -- \
//!         --withdrawals <path> [--deposits <path>] [--utxos <path>] \
//!         [--fee-rate <sats/kvB>] [--mode replay|per_call] \
//!         [--offset <n>] [--limit <n>]
//!
//! Flags:
//!   --withdrawals <path>   (required) Production withdrawal log; needs a
//!                          `value` column and (when --deposits is also given)
//!                          a `createdAt` column for chronological merging.
//!   --deposits <path>      Production deposit log. When supplied, deposits
//!                          and withdrawals are merged into a single
//!                          chronologically-ordered event stream — every
//!                          deposit becomes a synthetic UTXO in the pool, so
//!                          the pool is replenished naturally as it would have
//!                          been in production. No pool recycling.
//!   --utxos <path>         Initial pool snapshot (raw `near contract
//!                          call-function ... get_utxos_paged ...` output;
//!                          only `balance` is read). Defaults to empty pool.
//!   --fee-rate <n>         sats/kvB. Default 5000.
//!   --mode <m>             replay (default) — process events in order,
//!                          mutating the pool. per_call — for every withdrawal
//!                          clone the pool-as-of-now, run the algorithm
//!                          against the clone, do not consume. Pool still
//!                          accumulates deposits in chronological order.
//!                          Per_call isolates algorithm signal from
//!                          withdrawal-induced fragmentation.
//!
//!   --offset <n>           Skip the first n events of the merged
//!                          chronological stream. Both deposits and
//!                          withdrawals get skipped — pair with --utxos to
//!                          seed a non-empty starting pool.
//!   --limit <n>            Process at most n events (after offset).
//!
//! When --deposits is omitted, the simulator falls back to the older
//! recycle-snapshot behaviour: it resets the pool to --utxos every time the
//! pool can no longer fund the next withdrawal.

use btc_utils::{
    choose_utxos, choose_utxos_random, get_gas_fee, SelectionLimits, UtxoSelection,
    WithdrawSelectionParams, UTXO,
};
use rand::{rngs::StdRng, SeedableRng};
use std::collections::HashMap;
use std::env;
use std::fs;

#[derive(Default)]
struct Stats {
    /// "Change-free" hits: BnB matches in `current`, absorption-cases in
    /// `random` (selection sums to net_amount exactly with no change output).
    bnb_hits: u64,
    /// "With-change" hits: greedy fallback in `current`, the standard /
    /// padded / split paths in `random`.
    greedy_hits: u64,
    errors_pool_empty: u64,
    errors_algo: u64,
    pool_resets: u64,
    total_fee_sats: u128,
    total_amount_sats: u128,
    /// Sum of `user_payment` reported by the random algo (dust-padding
    /// absorbed from the user's output). Always 0 for the current algo.
    total_user_payment_sats: u128,
    inputs_histogram: [u64; 12],
    max_inputs_seen: usize,
    change_outputs_created: u64,
    change_free_txs: u64,
    fail_max_inputs: u64,
    fail_change_too_large: u64,
    fail_other: u64,
    sample_failures: Vec<FailureSample>,
}

struct FailureSample {
    idx: usize,
    amount: u128,
    pool_size: usize,
    pool_balance: u128,
    pool_max: u64,
    pool_p50: u64,
    pool_p10: u64,
    top10_sum: u128,
    reason: &'static str,
}

#[derive(Default)]
struct Args {
    withdrawals: Option<String>,
    deposits: Option<String>,
    utxos: Option<String>,
    fee_rate: u64,
    mode: String,
    /// Skip the first N events of the merged chronological stream.
    offset: usize,
    /// Process at most N events after the offset (0 = all).
    limit: usize,
    /// Coin-selection algorithm: `current` (BnB+greedy from coin_selection.rs),
    /// `random` (PR #272's randomized iterative), or `both` for side-by-side.
    algo: String,
    /// Seed for the randomized algorithm.
    rng_seed: u64,
}

fn parse_args() -> Result<Args, Box<dyn std::error::Error>> {
    let mut a = Args {
        fee_rate: 5000,
        mode: "replay".to_string(),
        algo: "current".to_string(),
        rng_seed: 0xC0FF_EEC0_FFEE,
        ..Default::default()
    };
    let mut it = env::args().skip(1);
    while let Some(flag) = it.next() {
        let need_val = |it: &mut std::iter::Skip<env::Args>| {
            it.next()
                .ok_or_else(|| format!("missing value for {flag}"))
        };
        match flag.as_str() {
            "--withdrawals" => a.withdrawals = Some(need_val(&mut it)?),
            "--deposits" => a.deposits = Some(need_val(&mut it)?),
            "--utxos" => a.utxos = Some(need_val(&mut it)?),
            "--fee-rate" => a.fee_rate = need_val(&mut it)?.parse()?,
            "--mode" => a.mode = need_val(&mut it)?,
            "--offset" => a.offset = need_val(&mut it)?.parse()?,
            "--limit" => a.limit = need_val(&mut it)?.parse()?,
            "--algo" => a.algo = need_val(&mut it)?,
            "--rng-seed" => a.rng_seed = need_val(&mut it)?.parse()?,
            "-h" | "--help" => {
                print_usage();
                std::process::exit(0);
            }
            other => return Err(format!("unknown flag: {other}").into()),
        }
    }
    if a.withdrawals.is_none() {
        print_usage();
        return Err("missing --withdrawals".into());
    }
    Ok(a)
}

fn print_usage() {
    eprintln!(
        "Usage: choose-utxo-simulator --withdrawals <path> [--deposits <path>] \
        [--utxos <path>] [--fee-rate <n>] [--mode replay|per_call] \
        [--offset <n>] [--limit <n>]"
    );
}

#[derive(Clone, Copy)]
enum EventKind {
    Deposit,
    Withdrawal,
}

struct Event {
    ts: String,
    kind: EventKind,
    value: u128,
    seq: u32, // tie-breaker so iteration is deterministic
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = parse_args()?;
    let limits = SelectionLimits::default();

    let starting_pool = if let Some(p) = &args.utxos {
        load_utxos(p)?
    } else {
        HashMap::new()
    };
    let starting_pool_size = starting_pool.len();
    let starting_pool_balance: u128 =
        starting_pool.values().map(|u| u128::from(u.balance)).sum();

    let withdrawals_path = args.withdrawals.as_ref().unwrap();
    let mut events = if let Some(deposits_path) = &args.deposits {
        load_event_stream(deposits_path, withdrawals_path)?
    } else {
        // Legacy mode: no deposits, just withdrawals in CSV row order.
        load_withdrawals_only(withdrawals_path)?
    };
    let full_events_len = events.len();

    // --offset and --limit slice the chronological event stream so the
    // simulator can be re-run quickly on a window of interest. Both deposits
    // and withdrawals are sliced together, so seed the pool via --utxos if
    // the offset would otherwise leave it empty.
    if args.offset > 0 {
        let drop_n = args.offset.min(events.len());
        events.drain(..drop_n);
    }
    if args.limit > 0 && events.len() > args.limit {
        events.truncate(args.limit);
    }

    let total_withdrawals = events
        .iter()
        .filter(|e| matches!(e.kind, EventKind::Withdrawal))
        .count();
    let total_deposits = events
        .iter()
        .filter(|e| matches!(e.kind, EventKind::Deposit))
        .count();

    println!(
        "Starting pool: {starting_pool_size} UTXOs, {}",
        btc(starting_pool_balance)
    );
    println!("Deposits:    {total_deposits}");
    println!("Withdrawals: {total_withdrawals}");
    println!("Fee rate:    {} sats/kvB", args.fee_rate);
    println!("Mode:        {}", args.mode);
    if args.offset > 0 || args.limit > 0 {
        println!(
            "Window:      offset={} limit={} (full stream had {full_events_len} events)",
            args.offset, args.limit
        );
    }
    println!("Limits:      {limits:?}");
    println!("Algo:        {}\n", args.algo);

    // PR #272's randomized algorithm needs the full contract config subset.
    // We synthesize it from the same SelectionLimits — anything missing
    // (passive-management bounds, max_change_number) is defaulted to the
    // production btc-bridge values.
    let params = WithdrawSelectionParams {
        min_change_amount: u128::from(limits.min_change_amount),
        max_change_amount: u128::from(limits.max_change_amount),
        max_withdrawal_input_number: limits.max_inputs,
        max_change_number: 10,
        passive_management_lower_limit: 0,
        passive_management_upper_limit: 6_000,
    };

    let algos: &[AlgoChoice] = match args.algo.as_str() {
        "current" => &[AlgoChoice::Current],
        "random" => &[AlgoChoice::Random],
        "both" => &[AlgoChoice::Current, AlgoChoice::Random],
        other => return Err(format!("unknown --algo: {other} (current|random|both)").into()),
    };
    for &algo in algos {
        run_simulation(
            algo,
            &events,
            &starting_pool,
            total_withdrawals,
            &args,
            &limits,
            &params,
        )?;
    }

    Ok(())
}

#[derive(Clone, Copy, Debug)]
enum AlgoChoice {
    Current,
    Random,
}

impl AlgoChoice {
    fn label(self) -> &'static str {
        match self {
            Self::Current => "current (BnB + greedy)",
            Self::Random => "random (PR #272)",
        }
    }
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn run_simulation(
    algo: AlgoChoice,
    events: &[Event],
    starting_pool: &HashMap<String, UTXO>,
    total_withdrawals: usize,
    args: &Args,
    limits: &SelectionLimits,
    params: &WithdrawSelectionParams,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("================================================================");
    println!("=== Algo: {} ===", algo.label());
    println!("================================================================");

    let starting_pool_size = starting_pool.len();
    let starting_pool_balance: u128 =
        starting_pool.values().map(|u| u128::from(u.balance)).sum();
    let mut pool = starting_pool.clone();
    let mut stats = Stats::default();
    let mut next_synth_id: u64 = 0;
    let mut rng = StdRng::seed_from_u64(args.rng_seed);
    let mut first_algo_failure_at: Option<usize> = None;
    let mut withdrawal_idx: usize = 0;
    let no_deposits = args.deposits.is_none();

    for ev in events {
        match ev.kind {
            EventKind::Deposit => {
                pool.insert(synth_txid("deposit", &mut next_synth_id), to_utxo(ev.value)?);
            }
            EventKind::Withdrawal => {
                let i = withdrawal_idx;
                withdrawal_idx += 1;

                // For per_call mode, every withdrawal sees a clone of the
                // current pool — algorithm runs but does not consume UTXOs.
                // For replay mode, we mutate the running pool. With no
                // --deposits stream, fall back to the legacy recycle: when
                // the pool can't fund the next withdrawal, reset to the
                // starting snapshot.
                let working_pool = if args.mode == "per_call" {
                    &mut pool.clone()
                } else {
                    if no_deposits {
                        let need = ev.value.saturating_add(u128::from(limits.max_gas_fee));
                        let bal: u128 = pool.values().map(|u| u128::from(u.balance)).sum();
                        if bal < need {
                            pool = starting_pool.clone();
                            stats.pool_resets += 1;
                        }
                    }
                    &mut pool
                };
                let pool_balance: u128 =
                    working_pool.values().map(|u| u128::from(u.balance)).sum();

                let outcome = match algo {
                    AlgoChoice::Current => try_withdrawal(
                        working_pool,
                        ev.value,
                        args.fee_rate,
                        limits,
                        &mut next_synth_id,
                    ),
                    AlgoChoice::Random => try_withdrawal_random(
                        working_pool,
                        ev.value,
                        args.fee_rate,
                        params,
                        &mut rng,
                        &mut next_synth_id,
                    ),
                };

                match outcome {
                    Ok(outcome) => {
                        if outcome.was_bnb {
                            stats.bnb_hits += 1;
                        } else {
                            stats.greedy_hits += 1;
                        }
                        stats.total_fee_sats += outcome.fee;
                        stats.total_amount_sats += ev.value;
                        stats.total_user_payment_sats += outcome.user_payment;
                        let bucket = outcome.input_count.min(11);
                        stats.inputs_histogram[bucket] += 1;
                        stats.max_inputs_seen =
                            stats.max_inputs_seen.max(outcome.input_count);
                        if outcome.change_amount > 0 {
                            stats.change_outputs_created += 1;
                        } else {
                            stats.change_free_txs += 1;
                        }
                    }
                    Err(_) => {
                        if pool_balance < ev.value + u128::from(limits.max_gas_fee) {
                            stats.errors_pool_empty += 1;
                        } else {
                            stats.errors_algo += 1;
                            if first_algo_failure_at.is_none() {
                                first_algo_failure_at = Some(i);
                            }
                            diagnose_failure(i, ev.value, working_pool, limits, &mut stats);
                        }
                    }
                }
            }
        }
    }

    let final_pool_balance: u128 = pool.values().map(|u| u128::from(u.balance)).sum();
    let served = stats.bnb_hits + stats.greedy_hits;
    let cf_share = if served > 0 {
        100.0 * stats.bnb_hits as f64 / served as f64
    } else {
        0.0
    };
    let (cf_label, wc_label) = match algo {
        AlgoChoice::Current => ("BnB success (change-free)", "Greedy fallback           "),
        AlgoChoice::Random => ("Random absorption (change-free)", "Random with-change         "),
    };

    println!("=== Per-call outcomes ===");
    println!("Total withdrawals processed: {total_withdrawals}");
    println!(
        "  {cf_label}: {} ({:.2}%)",
        stats.bnb_hits,
        100.0 * stats.bnb_hits as f64 / total_withdrawals as f64
    );
    println!(
        "  {wc_label}: {} ({:.2}%)",
        stats.greedy_hits,
        100.0 * stats.greedy_hits as f64 / total_withdrawals as f64
    );
    println!(
        "  Errors (pool insufficient): {} ({:.2}%)",
        stats.errors_pool_empty,
        100.0 * stats.errors_pool_empty as f64 / total_withdrawals as f64
    );
    println!(
        "  Errors (algo + limits):     {} ({:.2}%)",
        stats.errors_algo,
        100.0 * stats.errors_algo as f64 / total_withdrawals as f64
    );
    println!("Change-free share of served: {cf_share:.2}%");
    if let Some(idx) = first_algo_failure_at {
        println!("First algo failure at withdrawal index: {idx}");
    } else {
        println!("First algo failure: never");
    }

    println!("\n=== Outputs ===");
    println!(
        "  Change-free txs:        {} ({:.2}% of served)",
        stats.change_free_txs,
        if served > 0 {
            100.0 * stats.change_free_txs as f64 / served as f64
        } else {
            0.0
        }
    );
    println!(
        "  With-change txs:        {} ({:.2}% of served)",
        stats.change_outputs_created,
        if served > 0 {
            100.0 * stats.change_outputs_created as f64 / served as f64
        } else {
            0.0
        }
    );

    println!("\n=== Inputs per tx ===");
    for (n, count) in stats.inputs_histogram.iter().enumerate() {
        if *count > 0 {
            let label = if n == 11 {
                "11+".to_string()
            } else {
                format!("{n:>3}")
            };
            println!(
                "  {label} inputs: {count:>6} ({:.2}%)",
                100.0 * *count as f64 / served as f64
            );
        }
    }
    println!("  max inputs seen: {}", stats.max_inputs_seen);

    if matches!(algo, AlgoChoice::Random) {
        println!("\n=== Dust-padding (user_payment) ===");
        println!(
            "  Total absorbed from user output: {}",
            btc(stats.total_user_payment_sats)
        );
        println!(
            "  Mean per served tx:              {}",
            if served > 0 {
                btc((stats.total_user_payment_sats as f64 / served as f64).round() as u128)
            } else {
                btc(0)
            }
        );
    }

    println!("\n=== Fees ===");
    println!("  Total fee paid:    {}", btc(stats.total_fee_sats));
    println!(
        "  Mean fee/tx:       {}",
        if served > 0 {
            btc((stats.total_fee_sats as f64 / served as f64).round() as u128)
        } else {
            btc(0)
        }
    );
    println!(
        "  Fee as % of moved: {:.4}%",
        if stats.total_amount_sats > 0 {
            100.0 * stats.total_fee_sats as f64 / stats.total_amount_sats as f64
        } else {
            0.0
        }
    );

    println!("\n=== Pool evolution ===");
    println!(
        "  Start: {starting_pool_size} UTXOs, {}",
        btc(starting_pool_balance)
    );
    println!("  End:   {} UTXOs, {}", pool.len(), btc(final_pool_balance));
    let net = (final_pool_balance as i128) - (starting_pool_balance as i128);
    println!(
        "  Net delta: {} (deposits + change in − withdrawals + fees out)",
        btc_signed(net)
    );
    if stats.pool_resets > 0 {
        let recycle_period = total_withdrawals as f64 / stats.pool_resets as f64;
        println!(
            "  Pool resets: {} (~every {recycle_period:.0} withdrawals)",
            stats.pool_resets
        );
    }

    if stats.errors_algo > 0 {
        println!("\n=== Algorithm-failure breakdown ===");
        println!(
            "  max_inputs_exhausted: {} ({:.1}% of algo errors) — pool too fragmented to sum to target in ≤{} inputs",
            stats.fail_max_inputs,
            100.0 * stats.fail_max_inputs as f64 / stats.errors_algo as f64,
            limits.max_inputs,
        );
        println!(
            "  change_too_large:     {} ({:.1}% of algo errors) — only oversized UTXOs left, change would exceed max_change",
            stats.fail_change_too_large,
            100.0 * stats.fail_change_too_large as f64 / stats.errors_algo as f64,
        );
        println!(
            "  other:                {} ({:.1}%)",
            stats.fail_other,
            100.0 * stats.fail_other as f64 / stats.errors_algo as f64,
        );

        println!("\n  Sample failures:");
        for s in &stats.sample_failures {
            println!(
                "    idx={:<6} amount={} pool[size={}, bal={}, max={}, p50={}, p10={}, top10_sum={}] → {}",
                s.idx,
                btc(s.amount),
                s.pool_size,
                btc(s.pool_balance),
                btc(u128::from(s.pool_max)),
                btc(u128::from(s.pool_p50)),
                btc(u128::from(s.pool_p10)),
                btc(s.top10_sum),
                s.reason,
            );
        }
    }

    Ok(())
}

/// Format sats as a BTC string with 8-decimal precision (Bitcoin's native
/// granularity). Keeping the helper in one place so changing the precision is
/// a single edit. `fee_rate` stays in sats/kvB — that's the unit miners and
/// fee estimators speak.
fn btc(sats: u128) -> String {
    format!("{:.8} BTC", sats as f64 / 1e8)
}

fn btc_signed(sats: i128) -> String {
    format!("{:+.8} BTC", sats as f64 / 1e8)
}

fn synth_txid(prefix: &str, counter: &mut u64) -> String {
    *counter += 1;
    // 64-char hex prefix so utxo_to_out_points can parse it as a Txid; the
    // counter is folded into the low bits, the prefix label only exists to
    // help when eyeballing pool dumps.
    let _ = prefix;
    format!("{:064x}@0", *counter)
}

fn to_utxo(value: u128) -> Result<UTXO, Box<dyn std::error::Error>> {
    let balance: u64 = value.try_into()?;
    Ok(UTXO {
        path: String::new(),
        tx_bytes: vec![],
        vout: 0,
        balance,
    })
}

fn diagnose_failure(
    idx: usize,
    amount: u128,
    pool: &HashMap<String, UTXO>,
    limits: &SelectionLimits,
    stats: &mut Stats,
) {
    let mut bal_desc: Vec<u64> = pool.values().map(|u| u.balance).collect();
    bal_desc.sort_unstable_by(|a, b| b.cmp(a));
    if bal_desc.is_empty() {
        return;
    }

    let max_change = u128::from(limits.max_change_amount);
    let min_change = u128::from(limits.min_change_amount);
    let max_gas = u128::from(limits.max_gas_fee);

    let usable_caps: Vec<u128> = bal_desc
        .iter()
        .filter(|&&b| u128::from(b) <= amount + max_gas + max_change)
        .take(limits.max_inputs)
        .map(|&b| u128::from(b))
        .collect();
    let top_n_sum: u128 = usable_caps.iter().sum();

    let reason = if top_n_sum < amount + min_change {
        stats.fail_max_inputs += 1;
        "max_inputs_exhausted"
    } else if !bal_desc.iter().any(|&b| {
        let bal = u128::from(b);
        if bal < amount + min_change {
            return false;
        }
        let change = bal.saturating_sub(amount);
        change <= max_change + max_gas
    }) && top_n_sum < amount + min_change
    {
        stats.fail_change_too_large += 1;
        "change_too_large"
    } else {
        stats.fail_other += 1;
        "other"
    };

    if stats.sample_failures.len() < 5 {
        let p50 = bal_desc[bal_desc.len() / 2];
        let p10 = bal_desc[bal_desc.len() * 9 / 10];
        let pool_balance: u128 = bal_desc.iter().map(|&b| u128::from(b)).sum();
        stats.sample_failures.push(FailureSample {
            idx,
            amount,
            pool_size: pool.len(),
            pool_balance,
            pool_max: bal_desc[0],
            pool_p50: p50,
            pool_p10: p10,
            top10_sum: top_n_sum,
            reason,
        });
    }
}

struct Outcome {
    /// True when no change output was emitted (BnB or absorption).
    was_bnb: bool,
    fee: u128,
    input_count: usize,
    /// Sum of all change outputs (1 for current, 0..N for random).
    change_amount: u128,
    /// Random algo's `user_payment` (dust-padding) — 0 for current algo.
    user_payment: u128,
}

fn try_withdrawal(
    pool: &mut HashMap<String, UTXO>,
    amount: u128,
    fee_rate: u64,
    limits: &SelectionLimits,
    next_synth_id: &mut u64,
) -> Result<Outcome, Box<dyn std::error::Error>> {
    let (out_points, balance, fee) = choose_utxos(amount, pool, fee_rate, limits)?;

    if out_points.is_empty() || balance < amount + fee {
        return Err("selection underfunded".into());
    }

    let change = balance - amount - fee;
    let was_bnb = change == 0;

    // The simulator's pool keys are always `<txid_hex>@<vout>` (set by
    // load_utxos and synth_txid), so we can construct them directly from
    // the OutPoint without scanning the pool.
    for op in &out_points {
        let key = format!("{}@{}", op.txid, op.vout);
        if pool.remove(&key).is_none() {
            return Err(format!("could not match outpoint {op:?} back to pool key").into());
        }
    }

    if change > 0 {
        let change_u64: u64 = change.try_into()?;
        pool.insert(
            synth_txid("change", next_synth_id),
            UTXO {
                path: "change".into(),
                tx_bytes: vec![],
                vout: 0,
                balance: change_u64,
            },
        );
    }

    Ok(Outcome {
        was_bnb,
        fee,
        input_count: out_points.len(),
        change_amount: change,
        user_payment: 0,
    })
}

/// Run PR #272's randomized algorithm against the live pool. The PR's
/// `choose_utxos_random` does *not* compute a miner fee — it expects the
/// caller to compute `gas_fee` post-selection and deduct it from the user
/// output. Mirroring that here so the comparison report uses the same
/// per-byte fee model as `current`.
fn try_withdrawal_random(
    pool: &mut HashMap<String, UTXO>,
    amount: u128,
    fee_rate: u64,
    params: &WithdrawSelectionParams,
    rng: &mut StdRng,
    next_synth_id: &mut u64,
) -> Result<Outcome, Box<dyn std::error::Error>> {
    let pool_size_u32 = u32::try_from(pool.len()).unwrap_or(u32::MAX);
    let pool_clone = pool.clone();

    let UtxoSelection {
        selected,
        user_payment,
        change_amounts,
    } = choose_utxos_random(amount, pool_clone, pool_size_u32, params, rng)
        .map_err(|e| -> Box<dyn std::error::Error> { e.into() })?;

    if selected.is_empty() {
        return Err("random selection returned no inputs".into());
    }

    let balance: u128 = selected.iter().map(|(_, u)| u128::from(u.balance)).sum();
    let total_change: u128 = change_amounts.iter().sum();
    let n_inputs = selected.len() as u64;
    let n_outputs = 1 + change_amounts.len() as u64;
    // PR #272's wiring (omni_connector.rs): gas_fee is computed from the
    // returned (input_count, output_count) using the per-byte rate, then
    // user_amount = net_amount − gas_fee − user_payment. We mirror that.
    let fee = u128::from(get_gas_fee(n_inputs, n_outputs, fee_rate));
    let user_output = amount
        .checked_sub(fee)
        .and_then(|x| x.checked_sub(user_payment))
        .ok_or("random selection: gas_fee + user_payment exceeds amount")?;
    // Sanity: balance == user_output + total_change + fee.
    if balance != user_output + total_change + fee {
        return Err(format!(
            "random selection invariant broken: balance={balance} user_output={user_output} \
             total_change={total_change} fee={fee} user_payment={user_payment}"
        )
        .into());
    }

    // Mutate the pool: remove inputs, add a synthetic UTXO per change output.
    for (key, _) in &selected {
        if pool.remove(key).is_none() {
            return Err(format!("could not match selected key {key} back to pool").into());
        }
    }
    for &c in &change_amounts {
        let change_u64: u64 = c.try_into()?;
        pool.insert(
            synth_txid("change", next_synth_id),
            UTXO {
                path: "change".into(),
                tx_bytes: vec![],
                vout: 0,
                balance: change_u64,
            },
        );
    }

    Ok(Outcome {
        was_bnb: change_amounts.is_empty(),
        fee,
        input_count: selected.len(),
        change_amount: total_change,
        user_payment,
    })
}

fn load_utxos(path: &str) -> Result<HashMap<String, UTXO>, Box<dyn std::error::Error>> {
    let raw = fs::read_to_string(path)?;
    let json_start = raw.find('{').ok_or("no JSON object in utxos file")?;
    let v: serde_json::Value = serde_json::from_str(&raw[json_start..])?;
    let obj = v.as_object().ok_or("utxos file must be a JSON object")?;
    let mut out = HashMap::with_capacity(obj.len());
    for (k, v) in obj {
        let balance: u64 = v
            .get("balance")
            .and_then(|b| b.as_str())
            .ok_or_else(|| format!("entry {k} missing string `balance`"))?
            .parse()?;
        let path = v
            .get("path")
            .and_then(|p| p.as_str())
            .unwrap_or("")
            .to_string();
        let vout: u32 = k
            .split('@')
            .nth(1)
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        out.insert(
            k.clone(),
            UTXO {
                path,
                tx_bytes: vec![],
                vout,
                balance,
            },
        );
    }
    Ok(out)
}

/// Read a CSV with header `id,value,...,createdAt[,...]`. Returns (timestamp,
/// value) pairs in row order — caller is responsible for chronological sort.
fn load_csv_rows(path: &str) -> Result<Vec<(String, u128)>, Box<dyn std::error::Error>> {
    let raw = fs::read_to_string(path)?;
    let mut lines = raw.lines();
    let header = lines.next().ok_or_else(|| format!("empty CSV: {path}"))?;
    let cols: Vec<&str> = header.split(',').collect();
    let value_idx = cols
        .iter()
        .position(|c| c.trim() == "value")
        .ok_or_else(|| format!("CSV {path} missing `value` column"))?;
    let ts_idx = cols
        .iter()
        .position(|c| c.trim() == "createdAt")
        .ok_or_else(|| format!("CSV {path} missing `createdAt` column"))?;
    let mut out = Vec::new();
    for line in lines {
        if line.trim().is_empty() {
            continue;
        }
        let fields: Vec<&str> = line.split(',').collect();
        if fields.len() <= value_idx.max(ts_idx) {
            continue;
        }
        if let Ok(v) = fields[value_idx].parse::<u128>() {
            out.push((fields[ts_idx].to_string(), v));
        }
    }
    Ok(out)
}

fn load_event_stream(
    deposits_path: &str,
    withdrawals_path: &str,
) -> Result<Vec<Event>, Box<dyn std::error::Error>> {
    let deposits = load_csv_rows(deposits_path)?;
    let withdrawals = load_csv_rows(withdrawals_path)?;

    let mut events: Vec<Event> = Vec::with_capacity(deposits.len() + withdrawals.len());
    let mut seq: u32 = 0;
    for (ts, v) in deposits {
        events.push(Event {
            ts,
            kind: EventKind::Deposit,
            value: v,
            seq,
        });
        seq += 1;
    }
    for (ts, v) in withdrawals {
        events.push(Event {
            ts,
            kind: EventKind::Withdrawal,
            value: v,
            seq,
        });
        seq += 1;
    }
    // The CSV timestamp format is "YYYY-MM-DD H:MM:SS" — lexicographic sort
    // works as long as the date portion is fixed-width, which it is. Hour can
    // be 1 or 2 digits, so pad before comparing to make sort correct.
    events.sort_by(|a, b| {
        let ka = pad_ts(&a.ts);
        let kb = pad_ts(&b.ts);
        ka.cmp(&kb).then(a.seq.cmp(&b.seq))
    });
    Ok(events)
}

fn pad_ts(ts: &str) -> String {
    // Pad single-digit hours: "2025-09-01 3:35:30" → "2025-09-01 03:35:30".
    let mut parts = ts.splitn(2, ' ');
    let date = parts.next().unwrap_or("");
    let time = parts.next().unwrap_or("");
    let mut tparts = time.splitn(2, ':');
    let h = tparts.next().unwrap_or("");
    let rest = tparts.next().unwrap_or("");
    if h.len() == 1 {
        format!("{date} 0{h}:{rest}")
    } else {
        ts.to_string()
    }
}

fn load_withdrawals_only(path: &str) -> Result<Vec<Event>, Box<dyn std::error::Error>> {
    let raw = fs::read_to_string(path)?;
    let mut lines = raw.lines();
    let header = lines.next().ok_or("empty CSV")?;
    let cols: Vec<&str> = header.split(',').collect();
    let value_idx = cols
        .iter()
        .position(|c| c.trim() == "value")
        .ok_or("CSV missing `value` column")?;
    let mut events = Vec::new();
    let mut seq: u32 = 0;
    for line in lines {
        if line.trim().is_empty() {
            continue;
        }
        let fields: Vec<&str> = line.split(',').collect();
        if fields.len() <= value_idx {
            continue;
        }
        if let Ok(v) = fields[value_idx].parse::<u128>() {
            events.push(Event {
                ts: String::new(),
                kind: EventKind::Withdrawal,
                value: v,
                seq,
            });
            seq += 1;
        }
    }
    Ok(events)
}
