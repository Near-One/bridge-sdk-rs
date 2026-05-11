#!/usr/bin/env bash
#
# Wrapper around bridge-cli for active UTXO management on BTC mainnet.
#
# Flow:
#   run     – run active-utxo-management, parse NEAR tx hash and btc_pending_id
#             (= BTC txid), then call near-sign-btc-transaction N times
#             (default 10, one per input).
#   loop    – run `run` REPEAT_COUNT times; sleeps ITERATION_SLEEP_SEC after
#             every iteration; on failure, retries the same iteration after
#             the sleep (counter doesn't advance).
#   list    – print pending/verified entries from the state file.
#   verify  – iterate "signed" entries and call btc-verify-active-utxo-management
#             with the saved BTC txid.
#
# State is appended to a JSON-Lines file (one record per line) so it's safe to
# run concurrently/repeatedly and easy to grep.
#
# Env vars consumed by bridge-cli (typically loaded from a .env file by it):
#   NEAR_RPC, NEAR_SIGNER, NEAR_PRIVATE_KEY, BTC_CONNECTOR, SATOSHI_RELAYER, ...
#
# Script-specific overrides:
#   BRIDGE_CLI            bridge-cli binary name or path (default: bridge-cli, from PATH)
#   STATE_FILE            JSONL state file
#                         (default: $REPO/scripts/active_utxo_mgmt.state.jsonl)
#   NEAR_RPC_URL          NEAR RPC for receipt lookups
#                         (default: https://archival-rpc.mainnet.fastnear.com/)
#   SIGN_COUNT            total number of sign-indexes to sign (default: 10)
#   BATCH_SIZE            how many signs to dispatch in parallel per batch (default: 2)
#   REPEAT_COUNT          number of successful `run` iterations for the `loop`
#                         command (default: 100)
#   ITERATION_SLEEP_SEC   sleep between iterations of `loop` regardless of
#                         success/failure; on failure the same iteration is
#                         retried after the sleep (default: 60)
#   CHAIN                 chain arg for bridge-cli (default: btc)
#   ENV_FILE              dotenv file auto-sourced into the script's environment
#                         so NEAR_SIGNER etc. are visible (default: ./.env in
#                         current working directory). Set ENV_FILE= to disable.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

ENV_FILE="${ENV_FILE-./.env}"
if [[ -n "$ENV_FILE" && -f "$ENV_FILE" ]]; then
    set -a
    # shellcheck disable=SC1090
    source "$ENV_FILE"
    set +a
    printf '[%s] loaded env from %s\n' "$(date -u +%H:%M:%S)" "$ENV_FILE" >&2
fi

BRIDGE_CLI="${BRIDGE_CLI:-bridge-cli}"
STATE_FILE="${STATE_FILE:-$SCRIPT_DIR/active_utxo_mgmt.state.jsonl}"
NEAR_RPC_URL="${NEAR_RPC_URL:-${NEAR_RPC:-https://archival-rpc.mainnet.fastnear.com/}}"
SIGN_COUNT="${SIGN_COUNT:-10}"
BATCH_SIZE="${BATCH_SIZE:-2}"
REPEAT_COUNT="${REPEAT_COUNT:-100}"
ITERATION_SLEEP_SEC="${ITERATION_SLEEP_SEC:-${RETRY_SLEEP_SEC:-60}}"
CHAIN="${CHAIN:-btc}"
NETWORK="mainnet"

die()  { printf 'error: %s\n' "$*" >&2; exit 1; }
log()  { printf '[%s] %s\n' "$(date -u +%H:%M:%S)" "$*" >&2; }

require() { command -v "$1" >/dev/null 2>&1 || die "missing dependency: $1"; }

require jq
require curl
command -v "$BRIDGE_CLI" >/dev/null 2>&1 || [[ -x "$BRIDGE_CLI" ]] \
    || die "bridge-cli not found (looked for '$BRIDGE_CLI' in PATH and as a path)"

mkdir -p "$(dirname "$STATE_FILE")"
touch "$STATE_FILE"

# ---------- helpers ----------

# Parses bridge-cli stderr looking for `tx_hash="…"` next to "Init BTC transfer".
# bridge-cli's tracing layout puts span name + message on one line, then each
# field on its own line as `field="value"`. We grab the LAST tx_hash that
# appears after the "Init BTC transfer" message.
extract_near_tx_hash() {
    local file="$1"
    awk '
        /Init BTC transfer/ { found=1; next }
        found && /tx_hash="/ {
            match($0, /tx_hash="[^"]+"/)
            s = substr($0, RSTART+9, RLENGTH-10)
            print s
            exit
        }
    ' "$file"
}

# Queries NEAR RPC for the tx receipts and pulls btc_pending_id from the
# generate_btc_pending_info EVENT_JSON log.
fetch_btc_pending_id() {
    local near_tx="$1" signer="$2"
    local body
    body=$(cat <<EOF
{"jsonrpc":"2.0","id":1,"method":"EXPERIMENTAL_tx_status","params":{"tx_hash":"$near_tx","sender_account_id":"$signer","wait_until":"EXECUTED_OPTIMISTIC"}}
EOF
)
    local resp
    resp=$(curl -sS -X POST -H 'Content-Type: application/json' --data "$body" "$NEAR_RPC_URL")
    # Walk every receipt outcome's logs, find EVENT_JSON for generate_btc_pending_info,
    # and emit btc_pending_id.
    echo "$resp" | jq -r '
        .result.receipts_outcome[]?.outcome.logs[]?
        | select(startswith("EVENT_JSON:"))
        | sub("^EVENT_JSON:"; "")
        | fromjson?
        | select(.event == "generate_btc_pending_info")
        | .data[0].btc_pending_id
    ' | head -n1
}

state_append() {
    # $1 = JSON object
    printf '%s\n' "$1" >> "$STATE_FILE"
}

state_mark_verified() {
    local near_tx="$1" verify_tx="$2"
    local tmp
    tmp=$(mktemp)
    jq -c --arg near "$near_tx" --arg vtx "$verify_tx" '
        if .near_tx_hash == $near
        then .status = "verified" | .verify_near_tx = $vtx
        else . end
    ' "$STATE_FILE" > "$tmp"
    mv "$tmp" "$STATE_FILE"
}

# ---------- commands ----------

cmd_run() {
    local signer="${NEAR_SIGNER:-}"
    [[ -n "$signer" ]] || die "NEAR_SIGNER must be set in env so we can query the tx receipt"

    local log_file
    log_file=$(mktemp -t active_utxo_mgmt.XXXXXX.log)
    log "running active-utxo-management (network=$NETWORK chain=$CHAIN); log=$log_file"

    if ! "$BRIDGE_CLI" "$NETWORK" active-utxo-management --chain "$CHAIN" \
            >"$log_file" 2>&1; then
        cat "$log_file" >&2
        die "active-utxo-management failed (see log above)"
    fi
    cat "$log_file" >&2

    local near_tx
    near_tx=$(extract_near_tx_hash "$log_file" || true)
    [[ -n "$near_tx" ]] || die "could not parse NEAR tx hash from bridge-cli output ($log_file)"
    log "active-utxo-management NEAR tx: $near_tx"

    log "fetching btc_pending_id from NEAR receipt…"
    local btc_pending_id
    btc_pending_id=$(fetch_btc_pending_id "$near_tx" "$signer" || true)
    if [[ -z "$btc_pending_id" || "$btc_pending_id" == "null" ]]; then
        log "warning: btc_pending_id not yet visible in receipt; saving entry without it"
        btc_pending_id=""
    else
        log "btc_pending_id (= BTC txid): $btc_pending_id"
    fi

    log "signing $SIGN_COUNT inputs in batches of $BATCH_SIZE…"
    if ! "$BRIDGE_CLI" "$NETWORK" near-sign-btc-transaction \
            --chain "$CHAIN" \
            --near-tx-hash "$near_tx" \
            --sign-index 0 \
            --sign-count "$SIGN_COUNT" \
            --batch-size "$BATCH_SIZE" >&2; then
        die "sign batch failed; partial state NOT saved (some sign-indexes may have succeeded — rerun with adjusted --sign-index/--sign-count)"
    fi

    local entry
    entry=$(jq -nc \
        --arg ts "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
        --arg near "$near_tx" \
        --arg btc "$btc_pending_id" \
        --arg chain "$CHAIN" \
        --argjson signs "$SIGN_COUNT" \
        --argjson batch "$BATCH_SIZE" \
        '{timestamp:$ts, network:"mainnet", chain:$chain, near_tx_hash:$near, btc_pending_id:$btc, sign_count:$signs, batch_size:$batch, status:"signed"}')

    state_append "$entry"
    log "saved state entry → $STATE_FILE"
    printf '%s\n' "$entry"
}

cmd_list() {
    if [[ ! -s "$STATE_FILE" ]]; then
        log "state file is empty: $STATE_FILE"
        return 0
    fi
    jq -r '
        [.timestamp, .status, .near_tx_hash, (.btc_pending_id // "-"), (.verify_near_tx // "-")]
        | @tsv
    ' "$STATE_FILE" | column -t -s $'\t' -N TIME,STATUS,NEAR_TX,BTC_TXID,VERIFY_NEAR_TX
}

cmd_verify() {
    [[ -s "$STATE_FILE" ]] || die "state file is empty: $STATE_FILE"

    local pending
    pending=$(jq -c 'select(.status == "signed")' "$STATE_FILE")
    if [[ -z "$pending" ]]; then
        log "nothing to verify (no entries with status=signed)"
        return 0
    fi

    while IFS= read -r entry; do
        local near_tx btc_txid
        near_tx=$(echo "$entry" | jq -r '.near_tx_hash')
        btc_txid=$(echo "$entry" | jq -r '.btc_pending_id')
        if [[ -z "$btc_txid" || "$btc_txid" == "null" ]]; then
            log "skip $near_tx: btc_pending_id missing — fill it in $STATE_FILE manually first"
            continue
        fi

        log "verifying BTC txid=$btc_txid (from NEAR tx $near_tx)…"
        local verify_log
        verify_log=$(mktemp -t verify_active_utxo.XXXXXX.log)
        if ! "$BRIDGE_CLI" "$NETWORK" btc-verify-active-utxo-management \
                --chain "$CHAIN" \
                --btc-tx-hash "$btc_txid" >"$verify_log" 2>&1; then
            cat "$verify_log" >&2
            log "verify FAILED for $btc_txid (likely not yet enough BTC confirmations); leaving as signed"
            continue
        fi
        cat "$verify_log" >&2

        local verify_tx
        verify_tx=$(awk '
            /Sent BTC Verify Active UTXO Management/ { found=1; next }
            found && /tx_hash="/ {
                match($0, /tx_hash="[^"]+"/)
                print substr($0, RSTART+9, RLENGTH-10); exit
            }' "$verify_log")
        verify_tx="${verify_tx:-unknown}"

        state_mark_verified "$near_tx" "$verify_tx"
        log "  → verified, near verify tx: $verify_tx"
    done <<< "$pending"
}

cmd_loop() {
    local total="$REPEAT_COUNT"
    local iter_sleep="$ITERATION_SLEEP_SEC"
    local i=1
    local fail_streak=0
    log "loop: target $total successful iterations; sleep ${iter_sleep}s after every iteration"
    while (( i <= total )); do
        log "=== iteration $i/$total starting ==="
        # Subshell so `die` (exit 1) inside cmd_run terminates only the iteration.
        # `set +e` around the call: `set -e` would otherwise kill the loop on a
        # non-zero subshell exit instead of routing to the failure branch.
        local rc=0
        set +e
        ( cmd_run )
        rc=$?
        set -e
        if (( rc == 0 )); then
            log "=== iteration $i/$total OK ==="
            i=$(( i + 1 ))
            fail_streak=0
        else
            fail_streak=$(( fail_streak + 1 ))
            log "=== iteration $i FAILED (rc=$rc, consecutive failures=$fail_streak); will retry same iteration ==="
        fi
        log "sleeping ${iter_sleep}s before next iteration"
        sleep "$iter_sleep"
    done
    log "loop: all $total iterations succeeded"
}

usage() {
    cat <<EOF
usage: $(basename "$0") <run|loop|list|verify>

  run     active-utxo-management + $SIGN_COUNT signs in batches of $BATCH_SIZE; appends to state file
  loop    run $REPEAT_COUNT times; sleeps ${ITERATION_SLEEP_SEC}s after every iteration; on failure retries the same iteration
  list    show saved state entries
  verify  call btc-verify-active-utxo-management for each signed entry

state file: $STATE_FILE
EOF
}

cmd="${1:-}"
case "$cmd" in
    run)    cmd_run ;;
    loop)   cmd_loop ;;
    list)   cmd_list ;;
    verify) cmd_verify ;;
    -h|--help|help|"") usage ;;
    *)      usage; exit 1 ;;
esac
