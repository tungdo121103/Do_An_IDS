#!/usr/bin/env bash
set -u

# Low-rate baseline traffic for the isolated IDS lab.
TARGET_IP="${1:-192.168.247.20}"
TARGET_URL="${2:-http://192.168.247.20/}"
DURATION_SECONDS="${DURATION_SECONDS:-180}"
INTERVAL_SECONDS="${INTERVAL_SECONDS:-5}"

if ! command -v curl >/dev/null 2>&1; then
  echo "[!] curl is not installed. Run: sudo apt install -y curl"
  exit 1
fi

END_TIME=$((SECONDS + DURATION_SECONDS))
REQUESTS=0

echo "[*] Normal baseline traffic"
echo "[*] Target: ${TARGET_URL} (${TARGET_IP})"
echo "[*] Duration: ${DURATION_SECONDS}s | one HTTP request every ${INTERVAL_SECONDS}s"
echo "[*] Press Ctrl+C to stop early."

while [ "$SECONDS" -lt "$END_TIME" ]; do
  curl --silent --show-error --max-time 3 "$TARGET_URL" >/dev/null || true
  ping -c 1 -W 1 "$TARGET_IP" >/dev/null 2>&1 || true
  REQUESTS=$((REQUESTS + 1))
  echo "[*] Normal round ${REQUESTS}"
  sleep "$INTERVAL_SECONDS"
done

echo "[*] Finished normal traffic"
echo "[*] HTTP requests sent: ${REQUESTS}"
