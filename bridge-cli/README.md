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

# mainnet
TOKEN_LOCKER_ID=omni.bridge.near

# testnet
# TOKEN_LOCKER_ID=omni-locker.testnet

ETH_PRIVATE_KEY=<eth-private-key>
BASE_PRIVATE_KEY=<base-private-key>
ARB_PRIVATE_KEY=<arbitrum-private-key>

# you can provide solana's keypair as base58 string
SOLANA_KEYPAIR=<solana-keypair-bs58>
# or by providing an absolute path to the file where keypair is stored
# SOLANA_KEYPAIR=/Users/.../solana-wallet.json
```

### Configuration File

You can create a configuration file with your preferred settings. The CLI will look for it in the default location or you can specify it using the `--config` flag.

### Default file

You can manually modify `bridge-cli/src/defaults.rs` file

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
bridge-cli testnet near-fin-transfer-with-evm-proof \
    --chain eth \
    --tx-hash 0xabc...def \
    --storage-deposit-actions usdc.near:alice.near:0.1
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

> [!NOTE]
> - You have to wait for around 20 minutes for transaction confirmation after calling any method on EVM chain. Otherwise, you'll get `ERR_INVALID_BLOCK_HASH` meaning that light client or wormhole is not yet synced with the block that transaction was included in
> - Replace placeholder values (addresses, amounts, hashes) with actual values
> - Token amounts are specified in their smallest units (e.g., wei for ETH, yoctoNEAR for NEAR)
> - Always test with small amounts on testnet first
> - Ensure you have sufficient funds for gas fees and storage deposits

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

# Finalize a transfer on NEAR (using EVM proof)
bridge-cli near-fin-transfer-with-evm-proof \
    --chain <SOURCE_CHAIN> \
    --tx-hash <TX_HASH> \
    --storage-deposit-actions <TOKEN1:ACCOUNT1:AMOUNT1,...>

# Finalize a transfer on NEAR (using VAA)
bridge-cli near-fin-transfer-with-vaa \
    --chain <SOURCE_CHAIN> \
    --storage-deposit-actions <TOKEN1:ACCOUNT1:AMOUNT1,...> \
    --vaa <VAA_DATA>
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
