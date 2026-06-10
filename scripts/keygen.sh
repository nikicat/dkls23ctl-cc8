#!/usr/bin/env bash
# Launch a full keygen committee in parallel on this host.
#
# Usage: scripts/keygen.sh <t> <n> <key_id> [peer1 peer2 ...]
#   If peer names are omitted, peers p0..p(n-1) are used.
#
# Example: scripts/keygen.sh 2 3 mykey alice bob carol
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
ensure_built

t="${1:?usage: keygen.sh <t> <n> <key_id> [peers...]}"
n="${2:?need n}"
key_id="${3:?need key_id}"
shift 3
peers=("$@")
if [[ ${#peers[@]} -eq 0 ]]; then
  for ((i=0; i<n; i++)); do peers+=("p$i"); done
fi

info "keygen ${t}-of-${n} key_id='${key_id}' peers=[${peers[*]}]"
export CMD="exec '$BIN' keygen -t $t -n $n --peer-id \"\$PEER\" --key-id '$key_id' --timeout 90"
RUST_LOG="${RUST_LOG:-dkls23ctl=info}" launch_peers "keygen_${key_id}" "${peers[@]}"
rc=$?

if [[ $rc -eq 0 ]]; then
  pk="$("$BIN" pubkey --key-id "$key_id" 2>/dev/null)"
  ok "keygen complete. public key: $pk"
else
  fail "keygen failed; see $LOG_DIR/keygen_${key_id}_*.log"
fi
exit $rc
