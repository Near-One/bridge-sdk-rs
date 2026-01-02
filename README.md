# Omni Bridge SDK (Rust)

![Status](https://img.shields.io/badge/Status-Beta-blue)
![Stability](https://img.shields.io/badge/Stability-Pre--Release-yellow)
[![License](https://img.shields.io/badge/License-GPL%20v3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)

This is the Rust SDK for the **Omni Bridge**, the next generation of the Rainbow Bridge.  The Omni Bridge provides secure and efficient cross-chain communication and asset transfers between NEAR, Ethereum, Arbitrum, Base, and Solana. For detailed information about the Omni Bridge protocol and its capabilities, please visit the [Omni Bridge Repository](https://github.com/Near-One/omni-bridge). 

This SDK is primarily intended for developers building applications that require direct interaction with the Omni Bridge protocol. 

> [!IMPORTANT]
> This SDK is in beta and approaching production readiness. Core functionality is stable, but some features may still change.  Thorough testing is recommended before using in production environments.  For most users, the [Bridge CLI](bridge-cli/README.md) offers a more convenient and user-friendly way to interact with the Omni Bridge.

## Bridge CLI

The repository also contains the CLI tool, which provides a way to perform bridge operations from command line. For detailed instructions and a complete list of CLI commands and options, refer to the [Bridge CLI README](bridge-cli/README.md).

## Getting Started

### Prerequisites
- Rust 1.86.0 or later
- Cargo package manager

### Installation

The SDK is not yet published so you must refer to this GitHub repo in your `Cargo.toml`. For example:
```toml
[dependencies]
omni-connector = { git = "https://github.com/Near-One/bridge-sdk-rs", package = "omni-connector" }
solana-bridge-client = { git = "https://github.com/Near-One/bridge-sdk-rs", package = "solana-bridge-client" }
```

### Development

1. Clone the repository:
```bash
git clone https://github.com/Near-One/bridge-sdk-rs
cd bridge-sdk-rs
```

2. Build the SDK:
```bash
cargo build
```

3. Run tests:
```bash
cargo test
```

## Components

This repository contains the following key components:

### 1. `bridge-clients`

These are low-level clients for interacting with bridge contracts on specific blockchain networks. Each client provides a tailored interface for its respective chain.

*   **`evm-bridge-client`:**  For interacting with Ethereum and other EVM-compatible chains (e.g., Arbitrum, Base)

*   **`near-bridge-client`:**  For interacting with the NEAR blockchain

*   **`solana-bridge-client`:**  For interacting with the Solana blockchain

*   **`utxo-bridge-client`:**  For interacting with BTC-like chains (Bitcoin, Zcash, Litecoin, Dogecoin)

*   **`wormhole-bridge-client`:**  A client specifically for retrieving Wormhole's Verified Action Approvals (VAAs). These are used to prove events across Wormhole-connected chains (like Solana, Base, Arbitrum)

### 2. `connectors`

These are higher-level abstractions that combine multiple clients to simplify common bridging operations.

*   **`omni-connector`:** Provides a unified interface for token bridging operations across all supported chains, including metadata management, token deployment, and cross-chain transfers.

### 3. `eth-proof`

Provides functionality for generating Ethereum Merkle Patricia Trie proofs, used to verify events on Ethereum.

### 4. `near-rpc-client`

A client for interacting directly with the NEAR RPC.  Used by other components for:

*   Querying NEAR blockchain state.
*   Submitting transactions to NEAR.
*   Waiting for transaction finality.
*   Retrieving light client proofs.

### 5. `light-client`

A component for interacting with light clients deployed on NEAR (e.g. Ethereum light client, Bitcoin light client)

### 6. `bridge-cli`

The [Bridge CLI](bridge-cli/README.md) is a command-line interface for Omni-Bridge.  It provides easy-to-use commands for common Omni Bridge operations, built on top of the SDK. Use the CLI to:

*   Deploy bridged tokens
*   Transfer tokens between NEAR, Ethereum, Solana, and other supported chains.
*   Manage storage deposits.

## License

This project is licensed under the GPL v3 License - see the [LICENSE](./LICENSE) file for details.
