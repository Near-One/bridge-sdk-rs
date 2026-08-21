# Bridge CLI

![Status](https://img.shields.io/badge/Status-Beta-blue)
![Stability](https://img.shields.io/badge/Stability-Pre--Release-yellow)

A command-line interface for interacting with the Omni Bridge protocol, enabling seamless cross-chain token transfers and management.

> [!IMPORTANT]
> This CLI is in beta and approaching production readiness. While core functionality is stable, some features may still change. We recommend thorough testing before using in production environments.

## Command overview

```
bridge-cli [-n <mainnet|testnet|devnet>] [--dry-run] [--config <PATH>] <COMMAND>

transfer   Cross-chain transfers: start, sign, finalize, inspect
  init                Start a transfer (source chain = the token's chain prefix)
  hypercore           HyperCore -> any destination
  finalize            Finalize a transfer from its proof tx (destination auto-detected)
  sign                Sign an initialized transfer on NEAR
  status              Show a transfer's status

token      Token deployment and management
  log-metadata        Log a token's metadata on its chain
  deploy              Deploy a bridged token on a destination chain
  bind                Bind a deployed token on NEAR
  storage-deposit     Deposit NEP-141 storage for an account

utxo       Bitcoin/Zcash connector operations
  deposit-address     Get a deposit address for BTC/ZEC -> NEAR
  finalize-deposit    Finalize a BTC/ZEC deposit on NEAR
  fast-finalize-deposit
  submit-transfer     Build the withdrawal tx for a signed NEAR transfer
  sign                Request the MPC signature for a pending withdrawal
  broadcast           Broadcast the signed withdrawal to the UTXO chain
  verify-withdraw     Verify a withdrawal is confirmed on the UTXO chain
  bump-fee            Bump the fee of an RBF withdrawal tx
  cancel-withdraw     Cancel a pending withdrawal
  rebalance           Rebalance connector UTXOs
  verify-rebalance    Verify a rebalancing tx
  refund request|execute|verify

svm        Solana/Fogo bridge program administration
  initialize | version | set-admin | pause | update-metadata

config     Inspect configuration
  show                Print the resolved config for the selected network
  vars                List every override flag / env var
```

The network is selected with `-n/--network` or the `BRIDGE_NETWORK` env var and
**defaults to testnet** — mainnet operations always require an explicit
`-n mainnet` (or `BRIDGE_NETWORK=mainnet`).

Chains, tokens, and transactions are written with chain prefixes throughout:
`near:usdt.tether-token.near`, `eth:0x123...`, `sol:8xPxz...`,
`btc:cb9...36b`. The CLI dispatches on the prefix, so there is one `transfer
init` for every source chain and one `transfer finalize` for every proof.

## Installation

### Download binary

Visit [releases page](https://github.com/Near-One/bridge-sdk-rs/releases/latest) to download a binary for your platform

### Manual compilation

```bash
# Clone the repository
git clone https://github.com/near-one/bridge-sdk-rs.git
cd bridge-sdk-rs

# Build the CLI
cargo build --release

# The binary will be available at
./target/release/bridge-cli

# Or install globally with
cargo install --locked --path ./bridge-cli
```

## Configuration

Connection, key, and contract settings are resolved in order of precedence:

1. Command-line flags (hidden from help to keep it readable — `bridge-cli config vars` lists them all)
2. Environment variables (preferred way; a `.env` file in the working directory is loaded automatically)
3. JSON configuration file (`--config <PATH>` or `BRIDGE_CONFIG`)
4. Per-network defaults (`bridge-cli/src/defaults.rs`)

`bridge-cli -n testnet config show` prints the fully resolved configuration
(secrets redacted) so you can verify what a command would use.

### Setting up env file

```.env
BRIDGE_NETWORK=testnet

NEAR_SIGNER=<signer-account-id>
NEAR_PRIVATE_KEY=<signer-private-key>

ETH_PRIVATE_KEY=<eth-private-key>
BASE_PRIVATE_KEY=<base-private-key>
ARB_PRIVATE_KEY=<arbitrum-private-key>
HYPEREVM_PRIVATE_KEY=<hyperevm-private-key>
ABS_PRIVATE_KEY=<abs-private-key>

# you can provide solana's keypair as base58 string
SOLANA_KEYPAIR=<solana-keypair-bs58>
# or by providing an absolute path to the file where keypair is stored
# SOLANA_KEYPAIR=/Users/.../solana-wallet.json

STARKNET_ACCOUNT_ADDRESS=<starknet-account-address>
STARKNET_PRIVATE_KEY=<starknet-private-key>
```

### Offline / hardware-wallet signing (NEAR)

Any command that submits a NEAR transaction supports `--dry-run`. Instead of
signing and broadcasting, the CLI builds the transaction (fetching the current
nonce and a recent block hash) and prints it as a base64-encoded borsh payload,
ready to be signed externally — e.g. on a hardware wallet — and submitted by you.

`--dry-run` is valid for commands that submit to NEAR and, per the section
below, to SVM chains (Solana/Fogo); using it on a command that submits to any
other chain exits with an error rather than broadcasting.

In this mode **no private key is needed**; supply the signer account and the
public key that will sign (the access key must exist on the account):

```bash
bridge-cli -n mainnet token log-metadata \
    --token near:wrap.near \
    --near-signer omni-relayer.near \
    --near-public-key ed25519:Hb... \
    --dry-run
```

This prints a human-readable summary plus:

```
unsigned transaction (base64-encoded borsh):
CQAAA...AAAA
```

Sign and submit the printed payload with your preferred tool, for example
`near transaction sign-transaction <base64> ...` in
[near-cli-rs](https://github.com/near/near-cli-rs). The block hash is only valid
for ~24h, so sign and submit promptly.

Equivalent env vars: `NEAR_PUBLIC_KEY`, `DRY_RUN=true`.

### Offline signing (SVM: Solana & Fogo)

SVM commands support `--dry-run` too: instead of signing and broadcasting, the CLI
prints the unsigned transaction as base64-encoded bincode (the same wire format
`sendTransaction` accepts once signed) plus a human-readable summary. No keypair is
required — supply the fee payer's public key instead:

```bash
bridge-cli -n testnet transfer init \
  --token sol:<MINT> --amount 1000000 --recipient near:alice.testnet \
  --fee 0 --native-fee 10000 \
  --solana-public-key <PAYER_PUBKEY_BASE58> \
  --dry-run
```

Environment variables: `SOLANA_PUBLIC_KEY`, `FOGO_PUBLIC_KEY` (for `fogo:` tokens).

**Important:** unlike NEAR (whose block hash stays valid for ~24 h), a Solana/Fogo
blockhash expires after ~60-90 seconds. Sign and submit immediately, and pass
`--fee`/`--native-fee` explicitly to skip the fee-indexer round-trip. `svm initialize`
does not support `--dry-run` (the program keypair must sign for real).

Note: for token transfers, the sender's associated token account is derived
from the supplied public key — pass the public key of the wallet that actually
holds the tokens, or the transaction will reference the wrong token account.

#### Using the SDK without an RPC stack (`no-default-features`)

`solana-bridge-client` gates all RPC functionality behind the default-on
`client` feature. With `default-features = false` the crate exposes only the
instruction builders, PDA derivation, and unsigned-transaction assembly —
and builds for `wasm32-wasip2`:

```bash
cargo build -p solana-bridge-client --no-default-features --target wasm32-wasip2
```

The three token builders take `token_program_id` / `is_bridged_token`
explicitly in this mode (`build_log_metadata_instruction` takes only
`token_program_id`) (fetch them via `fetch_token_context` wherever an RPC
client is available), and `build_unsigned_transaction_with_blockhash` accepts
a caller-supplied blockhash.

## Quick Start

The examples run on testnet (the default network); pass `-n mainnet` for mainnet.

### Example 1: Deploy an ERC20 Token to NEAR

```bash
# 1. Log token metadata on Ethereum
bridge-cli token log-metadata --token eth:0x123...789

# 2. Wait for the transaction to be confirmed, then deploy the token on NEAR
bridge-cli token deploy --tx eth:0x123...456 --on near
```

### Example 2: Transfer a token from Ethereum to NEAR

```bash
# 1. Initialize the transfer on Ethereum (fees auto-fetched from the indexer)
bridge-cli transfer init \
    --token eth:0x123...789 \
    --amount 1000000 \
    --recipient near:alice.near

# 2. Wait for confirmation, then finalize on NEAR. The destination chain is
#    read from the transfer event; storage deposits are computed automatically.
bridge-cli transfer finalize --tx eth:0xabc...def
```

### Example 3: Transfer a token from NEAR to Solana

```bash
# 1. Initialize the transfer on NEAR
bridge-cli transfer init \
    --token near:wrap.testnet \
    --amount 5000000000000000000 \
    --recipient sol:123...789

# 2. Sign the transfer on NEAR (fees default to the transfer's stored values)
bridge-cli transfer sign --transfer near:42

# 3. Finalize on Solana. The destination chain and the SPL mint are read from
#    the signed payload.
bridge-cli transfer finalize --tx near:8xPxz...

# At any point, check where the transfer is:
bridge-cli transfer status --tx 8xPxz...
```

### Example 4: Transfer BTC from Bitcoin to NEAR

```bash
# 1. Get the deterministically calculated deposit address
bridge-cli utxo deposit-address --chain btc --recipient near:alice.near

# Example output:
# Deposit address: tb1q.....q4g

# 2. Send the amount to the generated address using your Bitcoin wallet.
# ATTENTION: Transactions with non-zero lock time are not supported. Make sure to set it to 0 in your wallet of choice.

# 3. Finalize and mint tokens on NEAR. The deposit message and output index
#    are looked up from the bridge indexer:
bridge-cli transfer finalize --tx btc:cb9.....36b

# To override the indexer lookup (or if the tx has multiple tracked deposit
# outputs), use the utxo command with --recipient and friends, or --vout to
# pick a specific output:
bridge-cli utxo finalize-deposit \
    --chain btc \
    --tx cb9.....36b \
    --recipient alice.near
```

### Example 5: Transfer BTC from NEAR to Bitcoin

```bash
# 1. Initialize the transfer normally (the MaxGasFee message is set from the
#    indexer's gas estimate)
bridge-cli transfer init \
    --token near:nbtc.n-bridge.testnet \
    --amount 50000 \
    --recipient btc:tb1q3....

# 2. Finalize: builds the bitcoin transaction, requests the MPC signature for
#    every input, and broadcasts it — logging each step's tx hash
bridge-cli transfer finalize --tx near:4Ss....ux

# (The same leg is available as granular steps, for recovery or when a step
#  was already performed by the relayer:
#    bridge-cli utxo submit-transfer --chain btc --near-tx 4Ss....ux
#    bridge-cli utxo sign --chain btc --near-tx 88f.....RM
#    bridge-cli utxo broadcast --chain btc --near-tx 2V6....3P )

# 3. Once confirmed, update UTXOs on the NEAR contract to keep it up-to-date
#    (normally done by the relayer)
bridge-cli utxo verify-withdraw --chain btc --tx 5d...a6
```

### Example 6: Refund a never-finalized BTC deposit

If you sent BTC to the bridge's deposit address but the transaction was never finalized on NEAR, you can pull the BTC back to a Bitcoin address you control.

The pipeline has three on-chain steps. Steps 1 and 3 go through `bridge-cli`. Step 2 is a direct call to the BTC connector contract via `near-cli`, because it only becomes callable after a timelock and may be invoked by anyone (not just the depositor).

```bash
# 1. Submit the refund request.
#
# The minimal invocation is just the chain and the BTC tx hash — the CLI asks
# the bridge indexer which output of the tx is a tracked deposit address,
# recovers the original DepositMsg, and uses its refund_address as the refund
# destination:
bridge-cli -n mainnet utxo refund request \
    --chain btc \
    --tx cb9.....36b

# Optional arguments:
#   --vout N            — pick a specific output if the tx has more than one
#                         tracked deposit address (the CLI will tell you which
#                         vouts to choose from).
#   --refund-address X  — only used when the original DepositMsg has no
#                         refund_address. If the deposit message carries one,
#                         that address is used as the refund destination.
#   --recipient, --fee, --msg, --no-deposit-refund-address
#                       — supply the original deposit args manually instead of
#                         relying on the indexer lookup. These must match the
#                         values used at deposit time; the contract recomputes
#                         the deposit address from them and rejects mismatches.
#   --dry-run           — print the unsigned `request_refund` NEAR transaction
#                         (base64 borsh) for offline/hardware-wallet signing
#                         instead of submitting it. Requires --near-public-key.
#                         See "Offline / hardware-wallet signing (NEAR)" above.
#
# Example with manual args (safe_deposit.msg path; `receiver_id` inside --msg
# is the intents account the deposit was routed to):
bridge-cli -n mainnet utxo refund request \
    --chain btc \
    --tx cb9.....36b \
    --recipient intents.near \
    --refund-address bc1q.... \
    --msg '{"receiver_id":"your_account.near"}'

# 2. Wait for the refund timelock, then call execute_refund directly on the
#    BTC connector contract via near-cli. Anyone can call it (the BTC tx
#    is already pinned to your refund_address by step 1).
#
# Timelock rules:
#   * 2 days — `refund_address` was provided in the original deposit
#   * 14 days — `refund_address` was NOT provided in the original deposit
#   * instant — caller has the DAO or RefundOperator role on the connector
#
# `utxo_storage_key` is "<btc_tx_hash>@<vout>" of the original deposit.
# Attach a small deposit to cover storage for the BTCPendingInfo entry.

near contract call-function as-transaction btc-connector.bridge.near \
    execute_refund \
    json-args '{"utxo_storage_key":"cb9.....36b@0"}' \
    prepaid-gas '100.0 Tgas' \
    attached-deposit '0.05 NEAR' \
    sign-as your-account.near \
    network-config mainnet sign-with-keychain send

# (Alternatively, `bridge-cli utxo refund execute --chain btc --tx cb9...36b --vout 0`
# performs the same call through the CLI.)

# 3. Trigger MPC signing of the refund BTC transaction.
#
# `execute_refund` creates a `BTCPendingInfo` and emits a
# `GenerateBtcPendingInfo` event. Find `btc_pending_id` in the event logs of
# the `execute_refund` tx (NEAR explorer or `near tx-status`) and pass it
# below. Once signed, the relayer broadcasts the BTC tx to Bitcoin.
bridge-cli -n mainnet utxo sign \
    --chain btc \
    --pending-id <btc_pending_id from execute_refund logs>
```

> [!NOTE]
> - The contract that owns this flow is [Near-One/btc-bridge](https://github.com/Near-One/btc-bridge) (`satoshi-bridge`). On mainnet it is `btc-connector.bridge.near`; on testnet `btc-connector.n-bridge.testnet`.
> - `request_refund` will be rejected by the contract if the deposit was already finalized via `verify_deposit` / `safe_verify_deposit`.
> - If the deposit's `DepositMsg.refund_address` was set, that address is the refund destination — `--refund-address` is ignored in this case. The contract enforces that the refund tx pays out to exactly that address.

> [!NOTE]
> - You have to wait for around 20 minutes for transaction confirmation after calling any method on EVM chain. Otherwise, you'll get `ERR_INVALID_BLOCK_HASH` meaning that light client or wormhole is not yet synced with the block that transaction was included in
> - Replace placeholder values (addresses, amounts, hashes) with actual values
> - Token amounts are specified in their smallest units (e.g., wei for ETH, yoctoNEAR for NEAR)
> - Always test with small amounts on testnet first
> - Ensure you have sufficient funds for gas fees and storage deposits
> - If you run these operations on testnet and mainnet and attach a sufficient fee, there is a good chance our relayer will handle it starting from step 2.

## Development Status

This CLI is under active development. Features and commands may be added, modified, or removed. Please report any issues or suggestions on our GitHub repository.

## License

This project is licensed under the terms specified in the [LICENSE](../LICENSE) file.
