#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/../.." && pwd)"
NETWORK_SETUP="${SCRIPT_DIR}/network_setup.sh"
DEFAULT_OUTPUT_ROOT="${SCRIPT_DIR}/benchmark_logs"
DEFAULT_REPEATS=5

declare -a DEFAULT_BACKENDS=("krtw" "iblt")
declare -a DEFAULT_SCENARIOS=("LAN" "WAN_200Mbps" "WAN_50Mbps" "WAN_5Mbps")
declare -A RTT_MS=(
  ["LAN"]="0.2"
  ["WAN_200Mbps"]="80"
  ["WAN_50Mbps"]="80"
  ["WAN_5Mbps"]="80"
)
declare -A RATE_MBIT=(
  ["LAN"]="1000"
  ["WAN_200Mbps"]="200"
  ["WAN_50Mbps"]="50"
  ["WAN_5Mbps"]="5"
)

OUTPUT_DIR=""
REPEATS="${DEFAULT_REPEATS}"
SKIP_BUILD=0
declare -a BACKENDS=("${DEFAULT_BACKENDS[@]}")
declare -a SCENARIOS=("${DEFAULT_SCENARIOS[@]}")

usage() {
  cat <<EOF
Usage: $(basename "$0") [options]

Options:
  --repeats=N              Number of runs per backend/scenario pair.
  --backends=a,b           Comma-separated backends: krtw,iblt.
  --scenarios=a,b          Comma-separated scenarios: LAN,WAN_200Mbps,WAN_50Mbps,WAN_5Mbps.
  --output-dir=PATH        Output directory for logs and summary files.
  --skip-build             Reuse the existing bazel binary without rebuilding.
  --help                   Show this help.

Examples:
  ./run_benchmarks.sh
  ./run_benchmarks.sh --backends=krtw --scenarios=WAN_5Mbps --repeats=1
EOF
}

split_csv() {
  local csv="$1"
  local -n out_ref="$2"
  out_ref=()
  IFS=',' read -r -a out_ref <<<"$csv"
}

contains() {
  local needle="$1"
  shift
  local item
  for item in "$@"; do
    if [[ "$item" == "$needle" ]]; then
      return 0
    fi
  done
  return 1
}

validate_inputs() {
  local backend
  for backend in "${BACKENDS[@]}"; do
    if ! contains "$backend" "${DEFAULT_BACKENDS[@]}"; then
      echo "Unsupported backend: ${backend}" >&2
      exit 1
    fi
  done

  local scenario
  for scenario in "${SCENARIOS[@]}"; do
    if ! contains "$scenario" "${DEFAULT_SCENARIOS[@]}"; then
      echo "Unsupported scenario: ${scenario}" >&2
      exit 1
    fi
  done

  if ! [[ "${REPEATS}" =~ ^[0-9]+$ ]] || [[ "${REPEATS}" -lt 1 ]]; then
    echo "--repeats must be a positive integer" >&2
    exit 1
  fi
}

ensure_namespace() {
  if [[ "${UPSI_BENCH_IN_NS:-0}" == "1" ]]; then
    return
  fi
  if [[ "$(id -u)" -eq 0 ]]; then
    return
  fi
  if command -v unshare >/dev/null 2>&1; then
    exec unshare -Urn env \
      UPSI_BENCH_IN_NS=1 \
      PATH="${PATH}" \
      HOME="${HOME}" \
      bash "$0" "$@"
  fi
  echo "This script needs root/CAP_NET_ADMIN or an available unshare command." >&2
  exit 1
}

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --repeats=*)
        REPEATS="${1#*=}"
        ;;
      --backends=*)
        split_csv "${1#*=}" BACKENDS
        ;;
      --scenarios=*)
        split_csv "${1#*=}" SCENARIOS
        ;;
      --output-dir=*)
        OUTPUT_DIR="${1#*=}"
        ;;
      --skip-build)
        SKIP_BUILD=1
        ;;
      --help|-h)
        usage
        exit 0
        ;;
      *)
        echo "Unknown argument: $1" >&2
        usage
        exit 1
        ;;
    esac
    shift
  done
}

prepare_output_dir() {
  if [[ -z "${OUTPUT_DIR}" ]]; then
    local timestamp
    timestamp="$(date +%Y%m%d_%H%M%S)"
    OUTPUT_DIR="${DEFAULT_OUTPUT_ROOT}/${timestamp}"
  fi
  mkdir -p "${OUTPUT_DIR}/runs"
  mkdir -p "${DEFAULT_OUTPUT_ROOT}"
  ln -sfn "${OUTPUT_DIR}" "${DEFAULT_OUTPUT_ROOT}/latest"
}

log_msg() {
  local message="$1"
  printf '[%s] %s\n' "$(date +'%F %T')" "${message}" | tee -a "${EXEC_LOG}"
}

cleanup_qdisc() {
  bash "${NETWORK_SETUP}" clear >>"${EXEC_LOG}" 2>&1 || true
}

setup_loopback() {
  if command -v ip >/dev/null 2>&1; then
    ip link set lo up
  fi
}

build_binary() {
  if [[ "${SKIP_BUILD}" -eq 1 ]]; then
    return
  fi
  log_msg "Building //examples/upsi:upsi"
  (cd "${REPO_ROOT}" && bazel build //examples/upsi:upsi) >>"${EXEC_LOG}" 2>&1
}

extract_metric() {
  local pattern="$1"
  local file="$2"
  awk -v pattern="${pattern}" '$0 ~ pattern { print $(NF-1); exit }' "${file}"
}

record_details() {
  local backend="$1"
  local scenario="$2"
  local run_id="$3"
  local status="$4"
  local exit_code="$5"
  local log_file="$6"
  local setup_s="$7"
  local base_psi_s="$8"
  local base_comm_mb="$9"
  local upsi_s="${10}"
  local upsi_comm_mb="${11}"

  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
    "${backend}" \
    "${scenario}" \
    "${RTT_MS[${scenario}]}" \
    "${RATE_MBIT[${scenario}]}" \
    "${run_id}" \
    "${status}" \
    "${setup_s}" \
    "${base_psi_s}" \
    "${base_comm_mb}" \
    "${upsi_s}" \
    "${upsi_comm_mb}" \
    "${log_file}" \
    "${exit_code}" >>"${DETAILS_TSV}"
}

format_metric() {
  local value="$1"
  if [[ -z "${value}" || "${value}" == "NA" ]]; then
    printf 'NA'
  else
    printf '%.4f' "${value}"
  fi
}

calc_stats_for_column() {
  local backend="$1"
  local scenario="$2"
  local column="$3"
  awk -F'\t' -v backend="${backend}" -v scenario="${scenario}" -v column="${column}" '
    NR == 1 { next }
    $1 == backend && $2 == scenario && $6 == "OK" && $column != "" {
      value = $column + 0
      count++
      sum += value
      sum_sq += value * value
      if (count == 1 || value < min) min = value
      if (count == 1 || value > max) max = value
    }
    END {
      if (count == 0) {
        print "NA\tNA\tNA\tNA"
        exit
      }
      mean = sum / count
      variance = (sum_sq / count) - (mean * mean)
      if (variance < 0 && variance > -1e-12) {
        variance = 0
      }
      stddev = sqrt(variance)
      printf "%.6f\t%.6f\t%.6f\t%.6f\n", mean, stddev, min, max
    }
  ' "${DETAILS_TSV}"
}

count_runs() {
  local backend="$1"
  local scenario="$2"
  awk -F'\t' -v backend="${backend}" -v scenario="${scenario}" '
    NR == 1 { next }
    $1 == backend && $2 == scenario { runs++ }
    END { print runs + 0 }
  ' "${DETAILS_TSV}"
}

count_successes() {
  local backend="$1"
  local scenario="$2"
  awk -F'\t' -v backend="${backend}" -v scenario="${scenario}" '
    NR == 1 { next }
    $1 == backend && $2 == scenario && $6 == "OK" { ok++ }
    END { print ok + 0 }
  ' "${DETAILS_TSV}"
}

run_single_benchmark() {
  local backend="$1"
  local scenario="$2"
  local run_id="$3"
  local log_file="${OUTPUT_DIR}/runs/${backend}_${scenario}_run${run_id}.log"

  log_msg "Starting backend=${backend} scenario=${scenario} run=${run_id} rtt_ms=${RTT_MS[${scenario}]} rate_mbit=${RATE_MBIT[${scenario}]}"
  bash "${NETWORK_SETUP}" apply "${RTT_MS[${scenario}]}" "${RATE_MBIT[${scenario}]}" >>"${EXEC_LOG}" 2>&1

  local exit_code=0
  set +e
  (
    cd "${REPO_ROOT}" &&
      UPSI_PSU_BACKEND="${backend}" bazel-bin/examples/upsi/upsi
  ) >"${log_file}" 2>&1
  exit_code=$?
  set -e

  local status="OK"
  if [[ "${exit_code}" -ne 0 ]]; then
    status="FAIL"
  fi

  local setup_s=""
  local base_psi_s=""
  local base_comm_mb=""
  local upsi_s=""
  local upsi_comm_mb=""
  setup_s="$(extract_metric '^Setup time:' "${log_file}" || true)"
  base_psi_s="$(extract_metric '^Base PSI time:' "${log_file}" || true)"
  base_comm_mb="$(extract_metric '^Base PSI Total Communication:' "${log_file}" || true)"
  upsi_s="$(extract_metric '^UPSI time:' "${log_file}" || true)"
  upsi_comm_mb="$(extract_metric '^UPSI Total Communication:' "${log_file}" || true)"

  record_details \
    "${backend}" "${scenario}" "${run_id}" "${status}" "${exit_code}" \
    "${log_file}" "${setup_s}" "${base_psi_s}" "${base_comm_mb}" \
    "${upsi_s}" "${upsi_comm_mb}"

  log_msg "Finished backend=${backend} scenario=${scenario} run=${run_id} status=${status} exit_code=${exit_code} upsi_s=${upsi_s:-NA} log=${log_file}"
  bash "${NETWORK_SETUP}" clear >>"${EXEC_LOG}" 2>&1 || true
}

write_summary_files() {
  {
    printf 'backend\tscenario\truns\tsuccesses\tsetup_avg_s\tsetup_std_s\tbase_psi_avg_s\tbase_psi_std_s\tbase_comm_avg_mb\tbase_comm_std_mb\tupsi_avg_s\tupsi_std_s\tupsi_comm_avg_mb\tupsi_comm_std_mb\n'

    local backend scenario runs successes
    local setup_stats base_stats base_comm_stats upsi_stats upsi_comm_stats
    local setup_mean setup_std base_mean base_std base_comm_mean base_comm_std
    local upsi_mean upsi_std upsi_comm_mean upsi_comm_std

    for backend in "${BACKENDS[@]}"; do
      for scenario in "${SCENARIOS[@]}"; do
        runs="$(count_runs "${backend}" "${scenario}")"
        successes="$(count_successes "${backend}" "${scenario}")"
        setup_stats="$(calc_stats_for_column "${backend}" "${scenario}" 7)"
        base_stats="$(calc_stats_for_column "${backend}" "${scenario}" 8)"
        base_comm_stats="$(calc_stats_for_column "${backend}" "${scenario}" 9)"
        upsi_stats="$(calc_stats_for_column "${backend}" "${scenario}" 10)"
        upsi_comm_stats="$(calc_stats_for_column "${backend}" "${scenario}" 11)"

        IFS=$'\t' read -r setup_mean setup_std _ <<<"${setup_stats}"
        IFS=$'\t' read -r base_mean base_std _ <<<"${base_stats}"
        IFS=$'\t' read -r base_comm_mean base_comm_std _ <<<"${base_comm_stats}"
        IFS=$'\t' read -r upsi_mean upsi_std _ <<<"${upsi_stats}"
        IFS=$'\t' read -r upsi_comm_mean upsi_comm_std _ <<<"${upsi_comm_stats}"

        printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
          "${backend}" "${scenario}" "${runs}" "${successes}" \
          "${setup_mean}" "${setup_std}" \
          "${base_mean}" "${base_std}" \
          "${base_comm_mean}" "${base_comm_std}" \
          "${upsi_mean}" "${upsi_std}" \
          "${upsi_comm_mean}" "${upsi_comm_std}"
      done
    done
  } >"${SUMMARY_TSV}"

  {
    echo "# UPSI Benchmark Summary"
    echo
    echo "- Generated at: $(date +'%F %T')"
    echo "- Output directory: \`${OUTPUT_DIR}\`"
    echo "- Repeats per backend/scenario pair: \`${REPEATS}\`"
    echo "- Backends: \`${BACKENDS[*]}\`"
    echo "- Scenarios: \`${SCENARIOS[*]}\`"
    echo
    echo "> Note: the current IBLT PSU implementation uses in-process local sockets."
    echo "> The WAN shaping therefore affects RR22/APSI link traffic, but not the internal IBLT PSU exchange itself."
    echo
    echo "## Aggregate Results"
    echo
    echo "| Backend | Scenario | Runs | Successes | Setup Avg +- Std (s) | Base PSI Avg +- Std (s) | Base Comm Avg +- Std (MB) | UPSI Avg +- Std (s) | UPSI Comm Avg +- Std (MB) |"
    echo "|---|---|---:|---:|---:|---:|---:|---:|---:|"
    awk -F'\t' '
      NR == 1 { next }
      {
        printf "| %s | %s | %s | %s | %s +- %s | %s +- %s | %s +- %s | %s +- %s | %s +- %s |\n",
          $1, $2, $3, $4,
          fmt($5), fmt($6),
          fmt($7), fmt($8),
          fmt($9), fmt($10),
          fmt($11), fmt($12),
          fmt($13), fmt($14)
      }
      function fmt(value) {
        if (value == "" || value == "NA") {
          return "NA"
        }
        return sprintf("%.4f", value + 0)
      }
    ' "${SUMMARY_TSV}"
    echo
    echo "## Per-Run Results"
    echo
    echo "| Backend | Scenario | Run | Status | Setup (s) | Base PSI (s) | Base Comm (MB) | UPSI (s) | UPSI Comm (MB) | Log |"
    echo "|---|---|---:|---|---:|---:|---:|---:|---:|---|"
    awk -F'\t' '
      NR == 1 { next }
      {
        printf "| %s | %s | %s | %s | %s | %s | %s | %s | %s | `%s` |\n",
          $1, $2, $5, $6,
          fmt($7), fmt($8), fmt($9), fmt($10), fmt($11), $12
      }
      function fmt(value) {
        if (value == "") {
          return "NA"
        }
        return sprintf("%.4f", value + 0)
      }
    ' "${DETAILS_TSV}"
  } >"${SUMMARY_MD}"
}

main() {
  ensure_namespace "$@"
  parse_args "$@"
  validate_inputs
  prepare_output_dir

  EXEC_LOG="${OUTPUT_DIR}/execution.log"
  DETAILS_TSV="${OUTPUT_DIR}/details.tsv"
  SUMMARY_TSV="${OUTPUT_DIR}/summary.tsv"
  SUMMARY_MD="${OUTPUT_DIR}/summary.md"

  : >"${EXEC_LOG}"
  printf 'backend\tscenario\trtt_ms\trate_mbit\trun\tstatus\tsetup_s\tbase_psi_s\tbase_comm_mb\tupsi_s\tupsi_comm_mb\tlog_file\texit_code\n' >"${DETAILS_TSV}"

  setup_loopback
  trap cleanup_qdisc EXIT

  log_msg "Benchmark run directory: ${OUTPUT_DIR}"
  log_msg "Backends: ${BACKENDS[*]}"
  log_msg "Scenarios: ${SCENARIOS[*]}"
  log_msg "Repeats: ${REPEATS}"
  log_msg "IBLT caveat: network shaping does not cover the internal in-process PSU socket path."

  build_binary

  local backend scenario run_id
  for backend in "${BACKENDS[@]}"; do
    for scenario in "${SCENARIOS[@]}"; do
      for ((run_id = 1; run_id <= REPEATS; ++run_id)); do
        run_single_benchmark "${backend}" "${scenario}" "${run_id}"
      done
    done
  done

  write_summary_files
  log_msg "Wrote details to ${DETAILS_TSV}"
  log_msg "Wrote aggregate summary to ${SUMMARY_TSV}"
  log_msg "Wrote markdown summary to ${SUMMARY_MD}"
}

main "$@"
