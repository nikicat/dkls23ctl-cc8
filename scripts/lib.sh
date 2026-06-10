#!/usr/bin/env bash
# Shared helpers for the dkls23ctl QA / demo scripts.
set -uo pipefail

# Resolve the repo root (parent of this scripts/ dir) and the debug binary.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
BIN="${DKLS23CTL_BIN:-$ROOT_DIR/target/debug/dkls23ctl}"
LOG_DIR="${DKLS23CTL_LOGS:-/tmp/dkls23ctl-logs}"

mkdir -p "$LOG_DIR"

c_green=$'\e[32m'; c_red=$'\e[31m'; c_yellow=$'\e[33m'; c_reset=$'\e[0m'

ensure_built() {
  if [[ ! -x "$BIN" ]]; then
    echo "${c_yellow}Building dkls23ctl (debug)...${c_reset}"
    ( cd "$ROOT_DIR" && cargo build ) || { echo "${c_red}build failed${c_reset}"; exit 1; }
  fi
}

info() { echo "${c_yellow}» $*${c_reset}"; }
ok()   { echo "${c_green}✓ $*${c_reset}"; }
fail() { echo "${c_red}✗ $*${c_reset}"; }

# run_parallel <logprefix> -- <cmd-template-with-PEER> <peer1> <peer2> ...
# Launches one process per peer in the background, substituting %PEER%,
# and waits for all. Each peer's stdout -> $LOG_DIR/<prefix>_<peer>.out
# Returns 0 only if every process exited 0.
launch_peers() {
  local prefix="$1"; shift
  local -a peers=("$@")
  local -a pids=()
  local -A pid_peer=()
  for peer in "${peers[@]}"; do
    # The caller exports CMD as an array template using the env var PEER.
    PEER="$peer" bash -c "$CMD" >"$LOG_DIR/${prefix}_${peer}.out" 2>"$LOG_DIR/${prefix}_${peer}.log" &
    local pid=$!
    pids+=("$pid"); pid_peer[$pid]="$peer"
  done
  local rc=0
  for pid in "${pids[@]}"; do
    if ! wait "$pid"; then rc=1; fi
  done
  return $rc
}
