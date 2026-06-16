# Bridge CLI

![Status](https://img.shields.io/badge/Status-Beta-blue)
![Stability](https://img.shields.io/badge/Stability-Pre--Release-yellow)

A command-line interface for interacting with the Omni Bridge protocol, enabling seamless cross-chain token transfers and management.

> [!IMPORTANT]  
> This CLI is in beta and approaching production readiness. While core functionality is stable, some features may still change. We recommend thorough testing before using in production environments.

## Features

- 🌉 Cross-chain token transfers and management
- 🌐 Network support for both Mainnet and Testnet
- ⚡ Fast and efficient command-line operations
- 🔧 Flexible configuration via CLI, environment variables, or config files

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

The CLI can be configured in multiple ways (in order of precedence):

1. Command-line arguments
2. Environment variables (preferred way)
3. Configuration file
4. Default values

### Setting up env file

```.env
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

### Configuration File

You can create a configuration file with your preferred settings. The CLI will look for it in the default location or you can specify it using the `--config` flag.

### Default file

You can manually modify `bridge-cli/src/defaults.rs` file

### Offline / hardware-wallet signing (NEAR)

Any command that submits a NEAR transaction supports `--dry-run`. Instead of
signing and broadcasting, the CLI builds the transaction (fetching the current
nonce and a recent block hash) and prints it as a base64-encoded borsh payload,
ready to be signed externally — e.g. on a hardware wallet — and submitted by you.

`--dry-run` is only valid for NEAR commands; using it on a command that submits
to another chain (EVM/SVM/Starknet, `btc-fin-transfer`, or `deploy-token` to a
non-Near chain) exits with an error rather than broadcasting.

In this mode **no private key is needed**; supply the signer account and the
public key that will sign (the access key must exist on the account):

```bash
bridge-cli mainnet log-metadata \
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

## Quick Start

### Example 1: Deploy an ERC20 Token to NEAR

This example shows how to deploy an existing ERC20 token from Ethereum to NEAR:

```bash
# 1. Log token metadata on Ethereum
bridge-cli testnet log-metadata --token eth:0x123...789

# 2. Wait for the transaction to be confirmed, then deploy token on Near
bridge-cli testnet deploy-token --source-chain Eth --chain Near --tx-hash 0x123...456
```

### Example 2: Transfer token from Ethereum to NEAR

This example demonstrates a complete flow of transferring token from Ethereum to NEAR:

```bash
# 1. Initialize the transfer on Ethereum
bridge-cli testnet evm-init-transfer \
    --chain eth \
    --token 0x123...789 \
    --amount 1000000 \
    --recipient near:alice.near \
    --fee 0 \
    --native-fee 10000 \
    --message ""

# 2. Wait for the transaction to be confirmed, then finalize on NEAR
bridge-cli testnet near-fin-transfer \
    --chain eth \
    --tx-hash 0xabc...def \
```

### Example 3: Transfer token from NEAR to Solana

This example shows how to transfer tokens from NEAR to Solana:

```bash
# 1. Initialize the transfer on NEAR
bridge-cli testnet near-init-transfer \
    --token wrap.testnet \
    --amount 5000000000000000000 \
    --recipient sol:123...789

# 2. Sign the transfer on NEAR
bridge-cli testnet near-sign-transfer \
    --origin-chain-id 1 \
    --origin-nonce 42 \
    --fee 0 \
    --native-fee 10000000000000000

# 3. Finalize the transfer on Solana
bridge-cli testnet solana-finalize-transfer \
    --tx-hash 8xPxz... \
    --sender-id alice.near \
    --solana-token So11111111111111111111111111111111111111112
```

### Example 4: Transfer BTC from Bitcoin to NEAR

This example shows how to transfer BTC to NEAR:

```bash
# 1. Get deterministically calculated deposit address
bridge-cli testnet get-bitcoin-address \
    --chain btc \
    --amount 50000 \
    --recipient alice.near

# Example output:
# BTC Address: tb1q.....q4g
# Amount you need to transfer, including the fee: 52000

# 2. Send the specified amount to the generated address using your Bitcoin wallet.
# ATTENTION: Transactions with non-zero lock time are not supported. Make sure to set it to 0 in your wallet of choice.

# 3. Finalize and mint tokens on NEAR
#
# Minimal invocation — the CLI looks up the original DepositMsg from the
# bridge indexer by the tx's deposit-address output:
bridge-cli testnet near-fin-transfer-btc \
    --chain btc \
    --btc-tx-hash cb9.....36b

# To override the indexer lookup (or if the tx has multiple tracked deposit
# outputs), pass --recipient-id and friends manually, or pass --vout to pick a
# specific output:
bridge-cli testnet near-fin-transfer-btc \
    --chain btc \
    --btc-tx-hash cb9.....36b \
    --recipient-id alice.near
```

### Example 5: Transfer BTC from NEAR to Bitcoin

This example shows how to transfer BTC back to Bitcoin:

```bash
# 1. Initialize the transfer normally
bridge-cli testnet near-init-transfer \
    --token nbtc.n-bridge.testnet \
    --amount 50000 \
    --recipient btc:tb1q3....

# 2. Submit transfer operation builds bitcoin transaction to send funds to the recipient
bridge-cli testnet near-submit-btc-transfer \
    --chain btc \
    --near-tx-hash 4Ss....ux

# 3. Request MPC to sign bitcoin transaction
bridge-cli testnet near-sign-btc-transaction \
    --chain btc \
    --near-tx-hash 88f.....RM

# 4. Send the signed transaction on bitcoin
bridge-cli testnet btc-fin-transfer \
    --chain btc \
    --near-tx-hash 2V6....3P

# 5. Once transaction is confirmed, update UTXOs on the Near contract to keep it up-to-date
bridge-cli testnet btc-verify-withdraw \
    --chain btc \
    --btc-tx-hash 5d...a6
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
bridge-cli mainnet btc-request-refund \
    --chain btc \
    --btc-tx-hash cb9.....36b

# Optional arguments:
#   --vout N            — pick a specific output if the tx has more than one
#                         tracked deposit address (the CLI will tell you which
#                         vouts to choose from).
#   --refund-address X  — only used when the original DepositMsg has no
#                         refund_address. If the deposit message carries one,
#                         that address is used as the refund destination.
#   --recipient-id, --fee, --msg, --no-deposit-refund-address
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
bridge-cli mainnet btc-request-refund \
    --chain btc \
    --btc-tx-hash cb9.....36b \
    --recipient-id intents.near \
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

# 3. Trigger MPC signing of the refund BTC transaction.
#
# `execute_refund` creates a `BTCPendingInfo` and emits a
# `GenerateBtcPendingInfo` event. Find `btc_pending_id` in the event logs of
# the `execute_refund` tx (NEAR explorer or `near tx-status`) and pass it
# below. Once signed, the relayer broadcasts the BTC tx to Bitcoin.
bridge-cli mainnet near-sign-btc-transaction \
    --chain btc \
    --btc-pending-id <btc_pending_id from execute_refund logs>
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

## Usage

The Bridge CLI supports various commands organized by network. Here's an overview of the main commands:

### Global Network Subcommand

```bash
# calling method on testnet
bridge-cli testnet log-metadata ...

# calling method on mainnet
bridge-cli mainnet log-metadata ...
```

#### NEAR Operations

```bash
# Deposit storage for a token on NEAR

bridge-cli near-storage-deposit \
    --token <TOKEN_ADDRESS> \
    --amount <AMOUNT>

# Initialize a transfer from NEAR
bridge-cli near-init-transfer \
    --token <TOKEN_ADDRESS> \
    --amount <AMOUNT> \
    --recipient <RECIPIENT_ADDRESS>

# Sign a transfer on NEAR
bridge-cli near-sign-transfer \
    --origin-chain-id <CHAIN_ID> \
    --origin-nonce <NONCE> \
    [--fee-recipient <ACCOUNT_ID>] \
    --fee <FEE_AMOUNT> \
    --native-fee <NATIVE_FEE_AMOUNT>

# Finalize a transfer on NEAR
bridge-cli near-fin-transfer \
    --chain <SOURCE_CHAIN> \
    --tx-hash <TX_HASH> \
```

#### EVM Chain Operations
```bash
# Initialize a transfer from EVM chain
bridge-cli evm-init-transfer \
    --chain <EVM_CHAIN> \
    --token <TOKEN_ADDRESS> \
    --amount <AMOUNT> \
    --recipient <NEAR_RECIPIENT> \
    --fee <FEE_AMOUNT> \
    --native-fee <NATIVE_FEE_AMOUNT>

# Finalize a transfer on EVM chain
bridge-cli evm-fin-transfer \
    --chain <EVM_CHAIN> \
    --tx-hash <NEAR_TX_HASH>
```

#### Solana Operations
```bash
# Initialize Solana bridge
bridge-cli solana-initialize \
    --program-keypair <KEYPAIR>

# Initialize a token transfer from Solana
bridge-cli solana-init-transfer \
    --token <TOKEN_ADDRESS> \
    --amount <AMOUNT> \
    --recipient <RECIPIENT_ADDRESS>

# Initialize a SOL transfer
bridge-cli solana-init-transfer-sol \
    --amount <AMOUNT> \
    --recipient <RECIPIENT_ADDRESS>

# Finalize a token transfer on Solana
bridge-cli solana-finalize-transfer \
    --tx-hash <NEAR_TX_HASH> \
    [--sender-id <NEAR_SENDER_ID>] \
    --solana-token <TOKEN_ADDRESS>

# Finalize a SOL transfer
bridge-cli solana-finalize-transfer-sol \
    --tx-hash <NEAR_TX_HASH> \
    [--sender-id <NEAR_SENDER_ID>]
```

## Development Status

This CLI is under active development. Features and commands may be added, modified, or removed. Please report any issues or suggestions on our GitHub repository.


## License

This project is licensed under the terms specified in the [LICENSE](../LICENSE) file.
