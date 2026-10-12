#!/usr/bin/env bash
set -euo pipefail

# Controlled UDP test for the isolated IDS lab only.
VICTIM_IP="${1:-192.168.247.20}"
PORT="${2:-80}"
DURATION="${DURATION:-15}"
PACKETS="${PACKETS:-1500}"
INTERVAL_US="${INTERVAL_US:-10000}" # 100 packets/second

if ! command -v hping3 >/dev/null 2>&1; then
  echo "Missing hping3. Install it on the Kali attacker VM first." >&2
  exit 1
fi

echo "Controlled UDP test: ${PACKETS} packets, max ${DURATION}s, ${VICTIM_IP}:${PORT}"
echo "Stop with Ctrl+C if the lab needs to be reset."
sudo timeout --signal=INT "${DURATION}s" \
  hping3 --udp --count "${PACKETS}" --interval "u${INTERVAL_US}" \
  --destport "${PORT}" "${VICTIM_IP}"

echo "UDP test finished."
