Title: feat: add Solana optimistic POC client (experimental, gated)

Summary
- Adds an experimental Solana→NEAR optimistic POC client (feature-gated) and a CLI subcommand to run devnet fixtures.
- Client verifies Solana transactions before calling the NEAR POC contract: program id, log payload at log_index, PDA presence, and SPL balance increase (defaults to wSOL/PDA seeds [b"escrow","wsol"]).
- Adds docs (architecture, testing notes, limitations) and opt-in fixture tests.

Changes
- New crate: bridge-sdk/bridge-clients/solana-optimistic-poc-client with proof verification and NEAR call helpers.
- bridge-cli: feature-gated poc-solana-test subcommand to run fixture-driven happy/challenge flows.
- Docs: config/env reference, architecture summary, testing notes (fixtures, commands, known limitations).
- Tests: opt-in devnet fixture tests (RUN_SOL_POC_E2E=1 cargo test -p solana-optimistic-poc-client -- --ignored).

Security/Limitations
- POC is optimistic and testnet-only; feature-gated and off by default.
- NEAR contract stores a single transfer; no Solana state proof; no challenger bond/slash; escrow check is balance-only.
- Solana program id 736wDEshwzrD18KrN7iqBAW9uPbNNVCKpQoJf8de3PF7, PDA seeds [b"escrow","wsol"]; upgrade authority set to none.
- Fixtures: latest.json (wSOL), latest-nonwsol.json (mint 3yarra...), latest-no-transfer.json (negative, expected fail).

Testing
- Local: RUN_SOL_POC_E2E=1 cargo test -p solana-optimistic-poc-client -- --ignored (hits devnet; wSOL/non-wSOL pass, no-transfer fails).
- Manual demos documented in solana-optimistic-poc/docs/testing-notes.md (Node, agents, bridge-cli subcommand).

Notes
- Experimental/testnet-only; does not affect production defaults.
- Omni-relayer POC helper not included here (private dependency on bridge-indexer-rs).
