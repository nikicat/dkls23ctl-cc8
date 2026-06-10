#!/usr/bin/env bash
# Launch a threshold signing session in parallel on this host.
#
# Usage: scripts/sign.sh <key_id> <message> <peer1> [peer2 ...]
#   Provide at least T peers that each hold a share of <key_id>.
#
# Prints the signature (hex) and verifies it.
# Example: scripts/sign.sh mykey "hello" alice carol
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
ensure_built

key_id="${1:?usage: sign.sh <key_id> <message> <peers...>}"
msg="${2:?need message}"
shift 2
peers=("$@")
[[ ${#peers[@]} -ge 1 ]] || { fail "need at least one signer"; exit 1; }

info "sign key_id='${key_id}' msg='${msg}' signers=[${peers[*]}]"
export CMD="exec '$BIN' sign --key-id '$key_id' --peer-id \"\$PEER\" --msg '$msg' --timeout 90"
RUST_LOG="${RUST_LOG:-dkls23ctl=info}" launch_peers "sign_${key_id}" "${peers[@]}"
rc=$?

if [[ $rc -ne 0 ]]; then
  fail "signing failed; see $LOG_DIR/sign_${key_id}_*.log"
  exit $rc
fi

sig="$(cat "$LOG_DIR/sign_${key_id}_${peers[0]}.out")"
ok "signature: $sig"
if "$BIN" verify --key-id "$key_id" --msg "$msg" --signature "$sig" >/dev/null 2>&1; then
  ok "signature verified"
else
  fail "signature did NOT verify"
  exit 1
fi
