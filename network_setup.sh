#!/usr/bin/env bash

set -euo pipefail

SCRIPT_NAME="$(basename "$0")"
DEFAULT_DEV="lo"

usage() {
  cat <<EOF
Usage:
  ${SCRIPT_NAME} apply <rtt_ms> <rate> [dev]
  ${SCRIPT_NAME} clear [dev]
  ${SCRIPT_NAME} show [dev]

Examples:
  ${SCRIPT_NAME} apply 80 5
  ${SCRIPT_NAME} apply 80 5mbit lo
  ${SCRIPT_NAME} clear
  ${SCRIPT_NAME} show

Notes:
  - The script treats the input RTT as round-trip latency and applies half of
    it as one-way delay via tc/netem.
  - Plain numeric rates are interpreted as mbit.
  - Applying qdisc requires root or CAP_NET_ADMIN in the target namespace.
EOF
}

require_tc() {
  if ! command -v tc >/dev/null 2>&1; then
    echo "tc is not installed or not in PATH" >&2
    exit 1
  fi
}

normalize_rate() {
  local rate="$1"
  if [[ "$rate" =~ [[:alpha:]]$ ]]; then
    printf '%s\n' "$rate"
  else
    printf '%smbit\n' "$rate"
  fi
}

to_one_way_delay() {
  local rtt_ms="$1"
  awk -v rtt="$rtt_ms" 'BEGIN { printf "%.3fms\n", rtt / 2.0 }'
}

apply_qdisc() {
  local rtt_ms="$1"
  local rate="$2"
  local dev="${3:-$DEFAULT_DEV}"
  local delay

  delay="$(to_one_way_delay "$rtt_ms")"
  rate="$(normalize_rate "$rate")"

  echo "Applying tc/netem on ${dev}: RTT=${rtt_ms}ms, one-way delay=${delay}, rate=${rate}"
  tc qdisc replace dev "$dev" root netem delay "$delay" rate "$rate"
  tc -s qdisc show dev "$dev"
}

clear_qdisc() {
  local dev="${1:-$DEFAULT_DEV}"
  echo "Clearing tc/netem on ${dev}"
  tc qdisc del dev "$dev" root 2>/dev/null || true
  tc -s qdisc show dev "$dev"
}

show_qdisc() {
  local dev="${1:-$DEFAULT_DEV}"
  tc -s qdisc show dev "$dev"
}

main() {
  require_tc

  if [[ $# -lt 1 ]]; then
    usage
    exit 1
  fi

  case "$1" in
    apply)
      if [[ $# -lt 3 || $# -gt 4 ]]; then
        usage
        exit 1
      fi
      apply_qdisc "$2" "$3" "${4:-$DEFAULT_DEV}"
      ;;
    clear)
      if [[ $# -gt 2 ]]; then
        usage
        exit 1
      fi
      clear_qdisc "${2:-$DEFAULT_DEV}"
      ;;
    show)
      if [[ $# -gt 2 ]]; then
        usage
        exit 1
      fi
      show_qdisc "${2:-$DEFAULT_DEV}"
      ;;
    *)
      usage
      exit 1
      ;;
  esac
}

main "$@"
