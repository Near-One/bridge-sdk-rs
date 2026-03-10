## Overview

Omni Bridge SDK — a Rust workspace for cross-chain token bridging between NEAR, Ethereum, Arbitrum, Base, Solana, Bitcoin, Zcash, Starknet, HyperEVM, and Abstract. The SDK powers the [Omni Bridge](https://github.com/Near-One/omni-bridge) protocol.

## Build & Test Commands

```bash
cargo build                    # compile all workspace members
cargo test                     # run all tests
cargo test -p <crate-name>     # run tests for a specific crate (e.g. starknet-bridge-client)
cargo fmt                      # format code
cargo fmt --check              # check formatting without modifying
cargo clippy                   # lint
cargo build --release          # release build
```

Toolchain: Rust 1.88.0 (pinned in `rust-toolchain`). Clippy configured with `large-error-threshold = 500` in `clippy.toml`.

## Workspace Structure

```
bridge-cli/                         # CLI binary (clap-based) for bridge operations
bridge-sdk/
  connectors/
    omni-connector/                 # High-level unified connector (OmniConnector)
  bridge-clients/
    evm-bridge-client/              # Shared client for all EVM chains (Eth, Arb, Base, HyperEVM, Abstract)
    near-bridge-client/             # NEAR bridge client
    solana-bridge-client/           # Solana bridge client
    starknet-bridge-client/         # Starknet bridge client
    utxo-bridge-client/             # Bitcoin/Zcash UTXO bridge client
    wormhole-bridge-client/         # Wormhole VAA retrieval client
  eth-proof/                        # Ethereum Merkle Patricia Trie proof generation
  near-rpc-client/                  # NEAR RPC interaction
  crypto-utils/                     # Cryptographic utilities
  utxo-utils/                       # UTXO chain utilities
  light-client/                     # Light client interactions on NEAR
```

## Architecture

### Adding a New EVM Chain

The primary pattern for adding EVM chain support (follow HyperEVM/Abstract as examples):

1. **`omni-types` dependency** (`Cargo.toml`): Bump the rev to include the new `ChainKind::Xxx` and `OmniAddress::Xxx` variants
2. **`bridge-cli/src/defaults.rs`**: Add RPC URL and bridge token factory address constants for mainnet/testnet/devnet
3. **`bridge-cli/src/main.rs`**: Add fields to `CliConfig` struct, `or()` merge method, `env_config()`, and `default_config()` for all 3 networks
4. **`bridge-cli/src/omni_connector_command.rs`**: Add to `derive_evm_sender()`, deploy token match, `NearFinTransfer` match (wormhole arm or unsupported arm), build bridge client in `omni_connector()`, add to `OmniConnectorBuilder`
5. **`bridge-sdk/connectors/omni-connector/src/omni_connector.rs`**: Add `xxx_bridge_client: Option<EvmBridgeClient>` field, update `evm_bridge_client()`, `log_metadata()`, `is_transfer_finalised()`, `utxo_bridge_client()`, `get_storage_deposit_actions_for_tx()`
6. **`bridge-sdk/bridge-clients/evm-bridge-client/src/evm_bridge_client.rs`**: Add `OmniAddress::Xxx` to `convert_omni_address()`

### Key Patterns

- **Builder pattern**: `OmniConnector`, `EvmBridgeClient`, and other structs use `derive_builder` crate. Fields are built with `XxxBuilder::default()...build().unwrap()`.
- **Exhaustive matching**: `ChainKind` and `OmniAddress` enums from `omni-types` must be exhaustively matched. When adding a new chain, check all `match` arms.
- **One `EvmBridgeClient` per EVM chain**: Each EVM chain (Eth, Arb, Base, HyperEVM, Abstract) gets its own `EvmBridgeClient` instance with different config (RPC, keys, bridge address, optional wormhole address).
- **Wormhole**: Some EVM chains use Wormhole VAAs for proof verification (Eth, Arb, Base). Others don't (HyperEVM, Abstract) — these use `wormhole_core_address(None)` and go in the unsupported arm for `NearFinTransfer`.
- **CLI config precedence**: CLI args > env vars > config file > defaults (defined in `defaults.rs`)

### External Dependencies

- `omni-types` from `github.com/near-one/omni-bridge`: Provides `ChainKind`, `OmniAddress`, and related types. Pinned by git rev.
- `alloy`: EVM interaction (replaces ethers-rs)
- `near-*` crates: NEAR blockchain interaction
- `solana-*` crates: Solana interaction
- `starknet`: Starknet interaction
