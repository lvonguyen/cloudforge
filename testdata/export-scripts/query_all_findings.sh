#!/usr/bin/env bash
# All-CBU Security Findings Export — Run all 3 clouds concurrently
# Usage: bash query_all_findings.sh [output-dir]
#
# Runs Azure, GCP, and AWS exports in parallel.
# Each writes to its own log file. Exit code is non-zero if any fail.
# Output dir defaults to ../export-outputs (relative to this script).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUTPUT_DIR="${1:-$(dirname "$SCRIPT_DIR")/export-outputs}"
LOG_DIR="${OUTPUT_DIR}/logs"
mkdir -p "$OUTPUT_DIR" "$LOG_DIR"

TS=$(date +%Y%m%d_%H%M%S)

echo "================================================================"
echo "All-CBU Security Findings Export"
echo "================================================================"
echo "[*] Output:  $OUTPUT_DIR"
echo "[*] Logs:    $LOG_DIR"
echo "[*] Started: $(date '+%Y-%m-%dT%H:%M:%S%z')"
echo ""
echo "[*] Launching 3 cloud exports in parallel..."
echo ""

# Launch all 3 in background
python3 "$SCRIPT_DIR/query_azure_all_findings.py" --output-dir "$OUTPUT_DIR" \
    > "$LOG_DIR/azure_${TS}.log" 2>&1 &
PID_AZURE=$!

python3 "$SCRIPT_DIR/query_gcp_all_findings.py" --output-dir "$OUTPUT_DIR" \
    > "$LOG_DIR/gcp_${TS}.log" 2>&1 &
PID_GCP=$!

python3 "$SCRIPT_DIR/query_aws_all_findings.py" --output-dir "$OUTPUT_DIR" \
    > "$LOG_DIR/aws_${TS}.log" 2>&1 &
PID_AWS=$!

# Clean up child processes on interrupt
trap 'kill "$PID_AZURE" "$PID_GCP" "$PID_AWS" 2>/dev/null; exit 130' INT TERM

echo "    Azure  PID=$PID_AZURE  -> $LOG_DIR/azure_${TS}.log"
echo "    GCP    PID=$PID_GCP  -> $LOG_DIR/gcp_${TS}.log"
echo "    AWS    PID=$PID_AWS  -> $LOG_DIR/aws_${TS}.log"
echo ""
echo "[*] Waiting for all to complete..."
echo ""

# Wait and collect exit codes (disable set -e for non-zero waits)
set +e
wait "$PID_AZURE"; AZURE_RC=$?
wait "$PID_GCP";   GCP_RC=$?
wait "$PID_AWS";   AWS_RC=$?
set -e

FAIL=0

# Report results
echo "================================================================"
echo "RESULTS"
echo "================================================================"

if [ "$AZURE_RC" -eq 0 ]; then
    echo "  [+] Azure:  OK"
else
    echo "  [!] Azure:  FAILED (exit $AZURE_RC) — see $LOG_DIR/azure_${TS}.log"
    FAIL=1
fi

if [ "$GCP_RC" -eq 0 ]; then
    echo "  [+] GCP:    OK"
else
    echo "  [!] GCP:    FAILED (exit $GCP_RC) — see $LOG_DIR/gcp_${TS}.log"
    FAIL=1
fi

if [ "$AWS_RC" -eq 0 ]; then
    echo "  [+] AWS:    OK"
else
    echo "  [!] AWS:    FAILED (exit $AWS_RC) — see $LOG_DIR/aws_${TS}.log"
    FAIL=1
fi

echo ""
echo "[*] Output files:"
ls -lh "$OUTPUT_DIR"/*_all_findings_*.csv 2>/dev/null || echo "  (no CSV files found)"
echo ""
echo "[*] Finished: $(date '+%Y-%m-%dT%H:%M:%S%z')"
echo "================================================================"

exit $FAIL
