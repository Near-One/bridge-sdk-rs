# Coin Selection Algorithm Recommendation for BTC Bridge Withdrawals

Source paper: *A Survey on Coin Selection Algorithms in UTXO-based Blockchains* (Ramezan, Schneider, McCann — Cardano Foundation, 2023).
Workload: `BTCs - Withdrawals.csv` (105,534 withdrawals, ~201 days).

## Recommendation: Branch and Bound (BnB) — Algorithm 6/7 in the paper

### Why BnB fits this workload

| Property | Value | Implication |
|---|---|---|
| Targets | 2,200 → 5,000,000,000 sats (5 orders of magnitude) | Algorithm must handle a wide range |
| No dust targets | All ≥ 2,200 sats | Pool dust is the worry, not target dust |
| Throughput | median 505/day, peak 4,028/day | Pool bloat compounds fast (objective O3) |
| Fee per tx | median 972 sats | Operator pays — O1 is the primary objective |
| Address | Public bridge hot wallet | **Privacy (O2) is not relevant** |

The paper's Table V evaluates each algorithm against five objectives:

- **O1**: Minimize transaction fee
- **O2**: Enhance privacy
- **O3**: Minimize UTXO pool size
- **O4**: Minimize confirmation time
- **O5**: Increase value range of UTXO pool

For this workload the priorities are **O1 (fees) > O3 (pool size) > O4 (confirmation)**, and **O2 (privacy) can be ignored**. That eliminates the privacy-oriented choices (Random Draw, Random Improve, Knapsack — which the paper notes "leads to higher transaction fees as the transaction size increases with the number of input UTXOs").

Among fee-minimizing options:

- **BnB (Algo 6)** — does a depth-first search on effective values (`u^v − f·u^s`) for a subset that matches the target within `[T, T + matchRange]`. When it succeeds, it **produces a change-free transaction**. The paper highlights the key win: *"If an exact match is found, there is no change output in the current transaction, and this change output, in turn, does not need to be spent as input in future transactions. In total, we can save the cost of an input plus the cost of an output."* That double-saving compounds at 500–4,000 tx/day.
- **Knapsack-with-Leverage / Greedy-and-Genetic** — also fee-minimizing per Table IV, but they're not deployed in real wallets, are heavier, and Knapsack-with-Leverage assumes you can defer requests across transactions (you can't here — each withdrawal is a separate user request).

BnB is also what **Bitcoin Core has used by default since Erhardt 2016** — it's the production-tested choice that matches the paper's analytic recommendation.

## Practical guidance for implementing it

1. **Primary: BnB** with `matchRange = cost_per_input + cost_per_output` so an "exact match" really does save a future input.
2. **Fallback when BnB returns ∅**: don't fall through to Knapsack (privacy-oriented, bloats inputs). Use **Greedy** (Algo 2) — it minimizes input count for that one tx and keeps the pool small (O3). This mirrors Bitcoin Core's BnB → Knapsack pair but swaps the fallback for the bridge's no-privacy context.
3. **Sort UTXOs by descending effective value** before BnB (line 4 of Algo 7) — at this scale, the sort is the hot path.
4. **Cap recursion** (`rounds = 1000` in the paper) to bound worst-case time on the 4,028-tx peak day.

## What to ignore from the paper

- All "random" components (Random Draw, Random Improve, Knapsack's coin-flip phase) — they exist to defeat chain analysis on user wallets. A bridge gains nothing and pays in higher fees and unpredictable tx sizes.
- LIFO/FIFO/HVF/LVF — none minimize O1, and HVF in particular blew up the pool size in the paper's simulation (Fig. 5).

## Algorithm references in the paper

- **Algorithm 6** — `BnB(U, T, mc)`: outer loop, 1,000 rounds, with random-draw fallback.
- **Algorithm 7** — `BnBRecursion(d, currentSelection)`: depth-first search over the effective-value-sorted pool, exploring inclusion branch first.
- **Algorithm 2** — `G(U)` Greedy: descending order, picks any UTXO ≤ remaining target. Suggested fallback.
