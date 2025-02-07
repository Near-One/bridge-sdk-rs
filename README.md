# Omni Bridge SDK (Rust)

![Status](https://img.shields.io/badge/Status-Beta-blue)
![Stability](https://img.shields.io/badge/Stability-Pre--Release-yellow)
[![License](https://img.shields.io/badge/License-GPL%20v3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)

This is the Rust SDK for the **Omni Bridge**, the next generation of the Rainbow Bridge.  The Omni Bridge provides secure and efficient cross-chain communication and asset transfers between NEAR, Ethereum, other EVM-compatible blockchains (like Arbitrum and Base), Solana, and other chains supported by the Wormhole network.  This SDK is primarily intended for developers building applications that require direct interaction with the Omni Bridge protocol.  Most users will find the [**Bridge CLI**](bridge-cli/README.md) a more convenient and user-friendly option for common bridging operations.

> [!IMPORTANT]
> This SDK is in beta and approaching production readiness. Core functionality is stable, but some features may still change.  Thorough testing is recommended before using in production environments.  For most users, the [Bridge CLI](bridge-cli/README.md) offers a more convenient and user-friendly way to interact with the Omni Bridge.

## Quick Start (using the Bridge CLI)

The easiest way to get started with the Omni Bridge is to use the command-line interface (CLI). The CLI provides a simplified interface for common tasks like deploying tokens and transferring assets.

1.  **Install the CLI:** Follow the instructions in the [Bridge CLI README](bridge-cli/README.md) to build and install the CLI binary.

2.  **Configure the CLI:** The CLI can be configured using environment variables, a configuration file, or command-line arguments.  See the [Bridge CLI README](bridge-cli/README.md) for details on configuring the necessary RPC endpoints, private keys, and account IDs.

3.  **Use the CLI:**  Explore the available commands with `bridge-cli --help` and the specific commands for each chain (e.g., `bridge-cli near --help`). Common operations include:

    *   `bridge-cli <network> log-metadata ...`
    *   `bridge-cli <network> deploy-token ...`
    *   `bridge-cli <network> near-init-transfer ...`
    *   `bridge-cli <network> evm-init-transfer ...`
    *   `bridge-cli <network> solana-init-transfer ...`
    *   `bridge-cli <network> near-fin-transfer-with-evm-proof ...`
    *   `bridge-cli <network> near-fin-transfer-with-vaa ...`
    *   `bridge-cli <network> evm-fin-transfer ...`
    *    And more.

**For detailed instructions and a complete list of CLI commands and options, refer to the [Bridge CLI README](bridge-cli/README.md).**

## Overview: The Omni Bridge

The Omni Bridge is an evolution of the original Rainbow Bridge, designed for improved security, scalability, and wider chain support. It facilitates:

1.  **Cross-Chain Token Bridging:** Transferring fungible tokens (like ERC-20 on Ethereum or NEP-141 on NEAR) between supported blockchains.  This works by locking tokens on the source chain and minting "wrapped" tokens on the destination chain (and burning/unlocking in the reverse direction).
2.  **Generalized Cross-Chain Calls:**  (Future Development) Execute smart contract functions on one blockchain, triggered by actions on another.  This powerful capability allows for the creation of truly decentralized cross-chain applications.
3.  **MPC-Based Security:** Unlike the original Rainbow Bridge, which relied on light clients for foreign chains, the Omni Bridge utilizes a Multi-Party Computation (MPC) network for signing and verifying cross-chain messages.  This distributed approach enhances security and decentralization.
4. **Wormhole Integration:** For communication with Solana and other Wormhole-compatible chains, the Omni Bridge integrates with the Wormhole protocol, using Verified Action Approvals (VAAs) as proofs.

## Core Concepts

*   **Token Locker:**  A smart contract on NEAR that manages the locking and unlocking of NEP-141 tokens during cross-chain transfers.
*   **Bridge Token Factory:**  A smart contract on EVM chains that manages the deployment and minting/burning of bridged tokens.
*   **MPC Signers:** A network of nodes that collectively generate signatures for cross-chain messages and proofs, ensuring no single point of failure.
*   **Proofs:** Cryptographic proofs that verify the occurrence of an event on one chain, allowing it to be processed on another chain. The Omni Bridge utilizes:
    *   **Ethereum Merkle Patricia Trie Proofs:**  Prove the inclusion of transaction receipts and logs within an Ethereum block.
    *   **Wormhole VAAs (Verified Action Approvals):** Standardized proofs from the Wormhole network for events on supported chains.
    *   **NEAR Sign Transfer Event:** Proof of `sign_transfer` action executed on the NEAR chain.

## Components

This repository contains the following key components:

### 1. `bridge-clients`

These are low-level clients for interacting with specific blockchain networks. Each client provides a tailored interface for its respective chain.

*   **`evm-bridge-client`:**  For interacting with Ethereum and other EVM-compatible chains (e.g., Arbitrum, Base).  This includes:
    *   Interacting with ERC-20 token contracts.
    *   Interacting with the `BridgeTokenFactory` contract.
    *   `initTransfer`: Initiate a token transfer *from* an EVM chain.
    *   `finTransfer`: Finalize a token transfer *to* an EVM chain (using a NEAR `sign_transfer` event as proof).
    *   `logMetadata`: Log token metadata on an EVM chain.
    *   `deployToken`: Deploy a new wrapped token on an EVM chain.
    *   `get_proof_for_event`: Generate an Ethereum proof for a given transaction hash and event.
    *   Estimating gas costs.

*   **`near-bridge-client`:**  For interacting with the NEAR blockchain, including:
    *   Interacting with NEP-141 token contracts.
    *   Interacting with the `omni-locker` contract (the token locker).
    *   `log_metadata`: Log token metadata on NEAR.
    *   `deploy_token`: Deploy a new mirrored token (either using EVM proofs or Wormhole VAAs).
    *   `storage_deposit_for_token`: Deposit storage for a token (required for transferring to the locker).
    *   `init_transfer`: Initiate a token transfer *from* NEAR.
    *   `sign_transfer`: Have the MPC network sign a transfer, creating a proof for use on the destination chain.
    *   `fin_transfer`: Finalize a token transfer *to* NEAR (using either an EVM proof or a Wormhole VAA).
    * `get_token_id`: Retrieves the ID of a token, given its address.
    * `get_native_token_id`: Retrieves the ID of native token, given the chain id.
    * `get_storage_balance`: Gets storage balance of an account.
    * `get_required_storage_deposit`: Get required storage deposit to perform an action

*   **`solana-bridge-client`:**  For interacting with the Solana blockchain, including:
    *   Initializing and managing the Solana bridge program.
    *   Interacting with SPL-Token contracts.
    *   Initiating and finalizing transfers of both SPL-Tokens and native SOL.
    *   Integrating with the Wormhole bridge for cross-chain communication.

*   **`wormhole-bridge-client`:**  A client specifically for retrieving Wormhole's Verified Action Approvals (VAAs). These are used to prove events across Wormhole-connected chains (including Solana, Ethereum, and others).  The client provides:
    *   `get_vaa`: Retrieves a VAA given a chain ID, emitter address, and sequence number.
    *   `get_vaa_by_tx_hash`: Retrieves a VAA given a transaction hash.  Used for retrieving proofs for actions on Wormhole-connected chains.

### 2. `connectors`

These are higher-level abstractions that combine multiple clients to simplify common bridging operations.

*   **`omni-connector`:** The main connector for the Omni Bridge. It provides a unified interface for working with multiple chains, hiding much of the underlying complexity. It allows you to:
    *   `log_metadata`: Log token metadata on any supported chain.
    *   `deploy_token`: Deploy a token on any supported chain, given the origin chain and proof of the `log_metadata` call.
    *   `init_transfer`: Initiate a token transfer from any supported chain.
    *   `fin_transfer`: Finalize a token transfer to any supported chain.
    *   `bind_token`: Bind token on any supported Wormhole chain.
*   **`bridge-connector-common`:**  Shared types and utilities for all bridge connectors.

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

This project is licensed under the GPL v3 License - see the [LICENSE](../LICENSE) file for details.
