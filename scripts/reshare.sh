#!/usr/bin/env bash
# Launch a reshare session in parallel on this host.
#
# Usage: scripts/reshare.sh <key_id> <new_t> <new_n> <peer1> [peer2 ...]
#   Run with max(new_n, old_t) peers. Peers that already hold a share provide it;
#   peers that don't will receive new shares (if in the new committee).
#
# Example (grow 2-of-3 -> 2-of-4): scripts/reshare.sh mykey 2 4 alice bob carol dave
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
ensure_built

key_id="${1:?usage: reshare.sh <key_id> <new_t> <new_n> <peers...>}"
new_t="${2:?need new_t}"
new_n="${3:?need new_n}"
shift 3
peers=("$@")
[[ ${#peers[@]} -ge 1 ]] || { fail "need at least one participant"; exit 1; }

pk_before="$("$BIN" pubkey --key-id "$key_id" 2>/dev/null || echo '?')"
info "reshare key_id='${key_id}' -> ${new_t}-of-${new_n} participants=[${peers[*]}]"
export CMD="exec '$BIN' reshare --peer-id \"\$PEER\" --key-id '$key_id' -t $new_t -n $new_n --timeout 120"
RUST_LOG="${RUST_LOG:-dkls23ctl=info}" launch_peers "reshare_${key_id}" "${peers[@]}"
rc=$?

pk_after="$("$BIN" pubkey --key-id "$key_id" 2>/dev/null || echo '?')"
if [[ $rc -eq 0 ]]; then
  ok "reshare complete"
  echo "  public key before: $pk_before"
  echo "  public key after:  $pk_after"
  [[ "$pk_before" == "$pk_after" ]] && ok "public key unchanged" || fail "public key changed!"
else
  fail "reshare failed; see $LOG_DIR/reshare_${key_id}_*.log"
fi
exit $rc
