#!/usr/bin/env bash
# Real-prove each saved step input in its own process (RISC0_DEV_MODE=0, CPU
# prover), recording wall time and peak memory. Output: results/proving.csv,
# one full log per proof in results/logs/.
set -euo pipefail
cd "$(dirname "$0")/.."
export RISC0_DEV_MODE=0
out=results/proving.csv
mkdir -p results/logs
echo "program,input,total_cycles,user_cycles,segments,prove_s,receipt_bytes,peak_rss_mib" > "$out"
run() {
  local prog=$1 input=$2 log line rss
  log=results/logs/$(basename "$input" .bin).log
  if [ "$(uname)" = Darwin ]; then
    # BSD time: -l reports peak RSS in bytes
    /usr/bin/time -l ./target/release/helios-check prove "$prog" "$input" > "$log" 2>&1
    rss=$(awk '/maximum resident set size/ {print int($1/1048576)}' "$log")
  else
    # GNU time: -v reports peak RSS in KiB
    /usr/bin/time -v ./target/release/helios-check prove "$prog" "$input" > "$log" 2>&1
    rss=$(awk '/Maximum resident set size/ {print int($6/1024)}' "$log")
  fi
  line=$(grep '^PROVED' "$log")
  echo "$line peak_rss_mib=$rss"
  echo "$line" | sed -E "s/^PROVED ([^ ]+) ([^ ]+) total_cycles=([0-9]+) user_cycles=([0-9]+) segments=([0-9]+) prove_s=([0-9.]+) receipt_bytes=([0-9]+)/\1,\2,\3,\4,\5,\6,\7,$rss/" >> "$out"
}
run inclusion results/inputs/inclusion_tx250_log0_logs1.bin
run step3 results/inputs/handoff_step3.bin
run step2 results/inputs/handoff_step2.bin
run step1 results/inputs/handoff_step1.bin
run step1 results/inputs/finality_only_step1.bin
run inclusion results/inputs/inclusion_tx194_log21_logs300.bin
echo done
