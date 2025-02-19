# Omni Bridge SDK (Rust)

![Status](https://img.shields.io/badge/Status-Beta-blue)
![Stability](https://img.shields.io/badge/Stability-Pre--Release-yellow)
[![License](https://img.shields.io/badge/License-GPL%20v3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)

This is the Rust SDK for the **Omni Bridge**, the next generation of the Rainbow Bridge.  The Omni Bridge provides secure and efficient cross-chain communication and asset transfers between NEAR, Ethereum, Arbitrum, Base, and Solana. For detailed information about the Omni Bridge protocol and its capabilities, please visit the [Omni Bridge Repository](https://github.com/near/omni-bridge). 

This SDK is primarily intended for developers building applications that require direct interaction with the Omni Bridge protocol. 

> [!IMPORTANT]
> This SDK is in beta and approaching production readiness. Core functionality is stable, but some features may still change.  Thorough testing is recommended before using in production environments.  For most users, the [Bridge CLI](bridge-cli/README.md) offers a more convenient and user-friendly way to interact with the Omni Bridge.

## Bridge CLI

The repository also contains the CLI tool, which provides a way to perform bridge operations from command line. For detailed instructions and a complete list of CLI commands and options, refer to the [Bridge CLI README](bridge-cli/README.md).

## Getting Started

### Prerequisites
- Rust 1.82.0 or later
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

### 5. `bridge-cli`

The [Bridge CLI](bridge-cli/README.md) is the recommended interface for most users.  It provides easy-to-use commands for common Omni Bridge operations, built on top of the SDK. Use the CLI to:

*   Deploy bridged tokens
*   Transfer tokens between NEAR, Ethereum, Solana, and other supported chains.
*   Manage storage deposits.

**For most users, the CLI will be the preferred way to interact with the Omni Bridge.**

### Legacy Components (for previous Rainbow Bridge versions):
- `legacy-bridge-sdk/connectors/eth-connector`: Provides access to the old ETH connector (for Aurora).
- `legacy-bridge-sdk/connectors/nep141-connector`: Provides access to the old NEP141 connector (for transferring tokens between NEAR and EVM).
- `legacy-bridge-sdk/connectors/fast-bridge`: Client for the Fast Bridge (for transferring tokens between NEAR and Aurora, fast but with additional trust assumptions).
- `legacy-bridge-sdk/near-light-client-on-eth`: A client for interacting with the NEAR light client *deployed on Ethereum*. **This is specific to the legacy Rainbow Bridge and is not used in the Omni Bridge, which uses MPC signatures.**
- `legacy-bridge-cli`: A command-line interface for the legacy connectors.

**These legacy components are provided for compatibility with older versions of the Rainbow Bridge.  New projects should use the `omni-connector` and `bridge-cli`.**

## License

This project is licensed under the GPL v3 License - see the [LICENSE](./LICENSE) file for details.
