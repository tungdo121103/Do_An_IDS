#!/usr/bin/env bash
set -u

# Controlled UDP traffic for the isolated IDS lab only.
TARGET_IP="${1:-192.168.247.20}"
TARGET_PORT="${2:-80}"
DURATION_SECONDS="${DURATION_SECONDS:-180}"
PACKETS_PER_ROUND="${PACKETS_PER_ROUND:-2000}"
SLEEP_SECONDS="${SLEEP_SECONDS:-2}"
INTERVAL_US="${INTERVAL_US:-10000}" # 100 packets/second

if ! command -v hping3 >/dev/null 2>&1; then
  echo "[!] hping3 is not installed. Run: sudo apt install -y hping3"
  exit 1
fi

END_TIME=$((SECONDS + DURATION_SECONDS))
ROUND=1
TOTAL_SENT=0

cleanup() {
  echo
  echo "[!] Stopping local UDP traffic..."
  sudo -n pkill -f "hping3.*${TARGET_IP}" 2>/dev/null || true
  exit 130
}
trap cleanup INT TERM

echo "[*] Controlled UDP traffic -> ${TARGET_IP}:${TARGET_PORT}"
echo "[*] Duration: ${DURATION_SECONDS}s | per round: ${PACKETS_PER_ROUND} packets | sleep: ${SLEEP_SECONDS}s"
echo "[*] Rate: about 100 packets/s. Press Ctrl+C to stop early."

while [ "$SECONDS" -lt "$END_TIME" ]; do
  REMAINING=$((END_TIME - SECONDS))
  echo "[*] Round ${ROUND} | remaining ${REMAINING}s"
  timeout --signal=INT "${REMAINING}s" sudo hping3 --udp \
    --numeric --count "$PACKETS_PER_ROUND" --interval "u${INTERVAL_US}" \
    --destport "$TARGET_PORT" "$TARGET_IP"
  TOTAL_SENT=$((TOTAL_SENT + PACKETS_PER_ROUND))
  ROUND=$((ROUND + 1))
  [ "$SECONDS" -lt "$END_TIME" ] && sleep "$SLEEP_SECONDS"
done
echo "[*] Finished. Planned packets sent: $TOTAL_SENT"
