# Run the choose-utxo coin-selection simulator against historical data.
#
# Inputs (must live in this directory):
#   Deposits.csv      — production deposit log    (id,value,nearTokenId,createdAt)
#   Withdrawals.csv   — production withdrawal log (id,value,nearTokenId,createdAt,vaultTxSubmissionDate,vaultTxFee)
#   utxos.json        — optional on-chain UTXO snapshot (run `make snapshot`)
#
# Quick start:
#   make              # 10k-event smoke test, ~seconds
#   make full         # full replay across the entire history
#   make per_call     # algorithm-only signal (no withdrawal-induced fragmentation)
#   make snapshot     # refresh utxos.json from mainnet
#
# Override knobs at the command line, e.g.:
#   make full FEE_RATE=10000
#   make smoke OFFSET=200000 LIMIT=20000

FEE_RATE ?= 5000
OFFSET   ?= 0
LIMIT    ?= 10000

CARGO_RUN := cargo run -p btc-utils --example choose-utxo-simulator --release -- \
  --deposits Deposits.csv \
  --withdrawals Withdrawals.csv \
  --fee-rate $(FEE_RATE)

.DEFAULT_GOAL := smoke
.PHONY: smoke full per_call snapshot build clean help

smoke:
	$(CARGO_RUN) --offset $(OFFSET) --limit $(LIMIT) --mode replay

full:
	$(CARGO_RUN) --mode replay

per_call:
	$(CARGO_RUN) --mode per_call

snapshot:
	near contract call-function as-read-only btc-connector.bridge.near \
	  get_utxos_paged json-args '{}' network-config mainnet now \
	  > utxos.json 2>/dev/null
	@echo "wrote utxos.json ($$(wc -c < utxos.json) bytes)"

build:
	cargo build -p btc-utils --example choose-utxo-simulator --release

clean:
	rm -f utxos.json

help:
	@echo "Targets:"
	@echo "  smoke    (default) 10k-event smoke test"
	@echo "  full     full replay across entire history"
	@echo "  per_call algorithm-only signal (no consumption between calls)"
	@echo "  snapshot fetch fresh UTXO snapshot to utxos.json via near CLI"
	@echo "  build    cargo build --release"
	@echo "  clean    remove utxos.json"
	@echo ""
	@echo "Knobs (override at command line):"
	@echo "  FEE_RATE=$(FEE_RATE)   OFFSET=$(OFFSET)   LIMIT=$(LIMIT)"
