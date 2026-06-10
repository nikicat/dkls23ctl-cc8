#!/usr/bin/env bash
# End-to-end QA for dkls23ctl: drives the real CLI through every scenario and
# asserts the outcomes. Runs in an isolated temp working directory.
#
# Usage: scripts/qa.sh
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
ensure_built

WORK="$(mktemp -d /tmp/dkls23ctl-qa.XXXXXX)"
cd "$WORK"
info "working dir: $WORK"
info "binary:      $BIN"

PASS=0; FAIL=0
record() { if [[ $1 -eq 0 ]]; then ok "$2"; ((PASS++)); else fail "$2"; ((FAIL++)); fi; }

# verify <key_id> <msg> <sig>  -> 0 if valid
vrfy() { "$BIN" verify --key-id "$1" --msg "$2" --signature "$3" >/dev/null 2>&1; }
pk_of() { "$BIN" pubkey --key-id "$1" 2>/dev/null; }

# kg <key> <t> <n> <peers...>  (parallel keygen)
kg() {
  local key=$1 t=$2 n=$3; shift 3
  export CMD="exec '$BIN' keygen -t $t -n $n --peer-id \"\$PEER\" --key-id '$key' --timeout 60"
  RUST_LOG=dkls23ctl=warn launch_peers "kg_${key}" "$@"
}
# sg <key> <msg> <peers...>   (parallel sign); echoes first signer's sig
sg() {
  local key=$1 msg=$2; shift 2
  local first=$1
  export CMD="exec '$BIN' sign --key-id '$key' --peer-id \"\$PEER\" --msg '$msg' --timeout 60"
  RUST_LOG=dkls23ctl=warn launch_peers "sg_${key}" "$@" || return 1
  cat "$LOG_DIR/sg_${key}_${first}.out"
}
# rs <key> <t> <n> <peers...> (parallel reshare)
rs() {
  local key=$1 t=$2 n=$3; shift 3
  export CMD="exec '$BIN' reshare --key-id '$key' --peer-id \"\$PEER\" -t $t -n $n --timeout 120"
  RUST_LOG=dkls23ctl=warn launch_peers "rs_${key}" "$@"
}

echo; info "===== 1. Singleton (t=1) ====="
PK="$("$BIN" keygen -t 1 --peer-id solo --key-id s1 2>/dev/null)"
[[ -n "$PK" ]]; record $? "singleton keygen prints pubkey"
[[ "$(pk_of s1)" == "$PK" ]]; record $? "pubkey command matches"
SIG="$("$BIN" sign --key-id s1 --peer-id solo --msg 'hello' 2>/dev/null)"
vrfy s1 'hello' "$SIG"; record $? "singleton sign + verify"
! vrfy s1 'tampered' "$SIG"; record $? "tampered message rejected"

echo; info "===== 2. TSS 2-of-3 keygen + sign ====="
kg t23 2 3 alice bob carol; record $? "2-of-3 keygen (3 peers)"
PK23="$(pk_of t23)"
# all three stored files agree on the pubkey
agree=0; for p in alice bob carol; do
  grep -q "$PK23" "$WORK/.secrets/t23/$p.json" || agree=1
done
[[ $agree -eq 0 ]]; record $? "all peers agree on the public key"
SIG="$(sg t23 'pay alice' alice bob)"; vrfy t23 'pay alice' "$SIG"; record $? "sign with {alice,bob}"
SIG="$(sg t23 'pay bob' bob carol)"; vrfy t23 'pay bob' "$SIG"; record $? "sign with {bob,carol} (different subset)"
! vrfy t23 'pay eve' "$SIG"; record $? "wrong message rejected"

echo; info "===== 3. TSS 3-of-5 keygen + sign ====="
kg t35 3 5 n0 n1 n2 n3 n4; record $? "3-of-5 keygen (5 peers)"
SIG="$(sg t35 'big tx' n1 n3 n4)"; vrfy t35 'big tx' "$SIG"; record $? "sign with 3 of 5"

echo; info "===== 4. Reshare TSS->TSS (2-of-3 -> 2-of-4, add dave) ====="
rs t23 2 4 alice bob carol dave; record $? "reshare to 2-of-4"
[[ "$(pk_of t23)" == "$PK23" ]]; record $? "public key unchanged after reshare"
SIG="$(sg t23 'after reshare' carol dave)"; vrfy t23 'after reshare' "$SIG"; record $? "new committee signs (incl. new member dave)"

echo; info "===== 5. Reshare singleton -> TSS (import) ====="
PKI="$("$BIN" keygen -t 1 --peer-id owner --key-id imp 2>/dev/null)"
rs imp 2 3 owner x1 x2; record $? "import singleton -> 2-of-3"
[[ "$(pk_of imp)" == "$PKI" ]]; record $? "public key unchanged after import"
SIG="$(sg imp 'imported' x1 x2)"; vrfy imp 'imported' "$SIG"; record $? "imported TSS key signs"

echo; info "===== 6. Reshare TSS -> singleton (export) ====="
kg exp 2 3 e0 e1 e2; PKE="$(pk_of exp)"
rs exp 1 1 e0 e1 e2; record $? "export 2-of-3 -> singleton"
[[ "$(pk_of exp)" == "$PKE" ]]; record $? "public key unchanged after export"
# receiver is the lexicographically-first holder => e0
SIG="$("$BIN" sign --key-id exp --peer-id e0 --msg 'exported' 2>/dev/null)"
vrfy exp 'exported' "$SIG"; record $? "reconstructed singleton signs"

echo; info "===== 7. Negative: threshold not met ====="
# Only 1 signer for a 2-of-3 with a short timeout must fail.
timeout 30 "$BIN" sign --key-id t35 --peer-id n0 --msg 'lonely' --timeout 12 >/dev/null 2>&1
[[ $? -ne 0 ]]; record $? "single signer below threshold fails (times out)"

echo
echo "================ SUMMARY ================"
echo "  ${c_green}passed: $PASS${c_reset}   ${c_red}failed: $FAIL${c_reset}"
echo "  logs: $LOG_DIR    secrets: $WORK/.secrets"
echo "========================================"
[[ $FAIL -eq 0 ]] || exit 1
