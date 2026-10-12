#!/usr/bin/env bash
set -u

DURATION_SECONDS="${DURATION_SECONDS:-180}"
REQUESTS_PER_ROUND="${REQUESTS_PER_ROUND:-2000}"
CONCURRENCY="${CONCURRENCY:-50}"
SLEEP_SECONDS="${SLEEP_SECONDS:-2}"

# Kali-only mode: run this same script on both hosts as one controlled session.
# On the Bot, the script is called without --with-bot and uses the normal mode.
if [[ "${1:-}" == "--with-bot" ]]; then
  set -euo pipefail
  BOT_HOST="bot@192.168.247.11"
  BOT_SCRIPT="/home/bot/attack_http_flood.sh"
  KALI_SCRIPT="${BASH_SOURCE[0]}"

  for value in "$DURATION_SECONDS" "$REQUESTS_PER_ROUND" "$CONCURRENCY" "$SLEEP_SECONDS"; do
    if [[ ! "$value" =~ ^[0-9]+$ ]]; then
      echo "[!] Duration, request count, concurrency and sleep must be whole numbers." >&2
      exit 2
    fi
  done
  if (( DURATION_SECONDS < 1 || DURATION_SECONDS > 180 || REQUESTS_PER_ROUND < 1 || CONCURRENCY < 1 || CONCURRENCY > REQUESTS_PER_ROUND )); then
    echo "[!] Use 1-180 seconds and a positive concurrency not exceeding requests per round." >&2
    exit 2
  fi
  if ! ssh -o BatchMode=yes -o ConnectTimeout=5 "$BOT_HOST" "test -f '$BOT_SCRIPT'"; then
    echo "[!] Bot script or passwordless SSH is unavailable. Nothing was started." >&2
    exit 1
  fi

  RUN_ID="$(date +%s)-${RANDOM}"
  BOT_PID_FILE="/tmp/ids-http-flood-${RUN_ID}.pid"
  BOT_SSH_PID=""
  KALI_PID=""

  cleanup_session() {
    local status=$?
    trap - EXIT INT TERM

    if [[ -n "$KALI_PID" ]]; then
      kill -TERM "$KALI_PID" 2>/dev/null || true
    fi
    if [[ -n "$BOT_SSH_PID" ]]; then
      if ! ssh -o BatchMode=yes -o ConnectTimeout=5 "$BOT_HOST" bash -s -- "$BOT_PID_FILE" <<'REMOTE_STOP'
pid_file=$1
if [[ -f "$pid_file" ]]; then
  read -r pid < "$pid_file"
  if [[ "$pid" =~ ^[0-9]+$ ]] && [[ -r "/proc/$pid/environ" ]] &&
     tr '\0' '\n' < "/proc/$pid/environ" | grep -Fxq "IDS_LAB_PIDFILE=$pid_file"; then
    kill -TERM "$pid"
  fi
fi
REMOTE_STOP
      then
        echo "[!] Could not confirm Bot stopped; check it with pgrep on the Bot." >&2
      fi
      kill -TERM "$BOT_SSH_PID" 2>/dev/null || true
    fi

    if [[ -n "$KALI_PID" ]]; then
      wait "$KALI_PID" 2>/dev/null || true
    fi
    if [[ -n "$BOT_SSH_PID" ]]; then
      wait "$BOT_SSH_PID" 2>/dev/null || true
    fi
    exit "$status"
  }

  trap cleanup_session EXIT
  trap 'exit 130' INT
  trap 'exit 143' TERM

  echo "[*] Starting Kali and Bot for up to ${DURATION_SECONDS}s. Press Ctrl+C to stop both."
  ssh -o BatchMode=yes "$BOT_HOST" \
    "DURATION_SECONDS=$DURATION_SECONDS REQUESTS_PER_ROUND=$REQUESTS_PER_ROUND CONCURRENCY=$CONCURRENCY SLEEP_SECONDS=$SLEEP_SECONDS IDS_LAB_PIDFILE=$BOT_PID_FILE bash '$BOT_SCRIPT'" &
  BOT_SSH_PID=$!

  BOT_READY=0
  for (( attempt=0; attempt<20; attempt++ )); do
    if ssh -o BatchMode=yes -o ConnectTimeout=5 "$BOT_HOST" "test -f '$BOT_PID_FILE'"; then
      BOT_READY=1
      break
    fi
    if ! kill -0 "$BOT_SSH_PID" 2>/dev/null; then
      break
    fi
    sleep 0.25
  done
  if (( BOT_READY == 0 )); then
    echo "[!] Bot did not start; Kali was not started." >&2
    exit 1
  fi

  DURATION_SECONDS="$DURATION_SECONDS" REQUESTS_PER_ROUND="$REQUESTS_PER_ROUND" \
    CONCURRENCY="$CONCURRENCY" SLEEP_SECONDS="$SLEEP_SECONDS" bash "$KALI_SCRIPT" &
  KALI_PID=$!

  # Stop the other side if either side finishes or fails.
  wait -n "$BOT_SSH_PID" "$KALI_PID"
  exit $?
fi

TARGET="${1:-http://192.168.247.20/}"
CONTROL_PID_FILE="${IDS_LAB_PIDFILE:-}"
AB_PID=""

if [[ -n "$CONTROL_PID_FILE" && ! "$CONTROL_PID_FILE" =~ ^/tmp/ids-http-flood-[0-9]+-[0-9]+\.pid$ ]]; then
  echo "[!] Invalid IDS_LAB_PIDFILE." >&2
  exit 2
fi

cleanup() {
  if [[ -n "$AB_PID" ]]; then
    kill -TERM "$AB_PID" 2>/dev/null || true
    wait "$AB_PID" 2>/dev/null || true
  fi
  if [[ -n "$CONTROL_PID_FILE" ]]; then
    rm -f -- "$CONTROL_PID_FILE"
  fi
}

trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

if ! command -v ab >/dev/null 2>&1; then
  echo "[!] ApacheBench 'ab' is not installed."
  echo "    Install on Kali with: sudo apt install -y apache2-utils"
  exit 1
fi

if [ "$CONCURRENCY" -gt "$REQUESTS_PER_ROUND" ]; then
  echo "[!] CONCURRENCY must be less than or equal to REQUESTS_PER_ROUND."
  exit 1
fi

if [[ -n "$CONTROL_PID_FILE" ]]; then
  umask 077
  printf '%s\n' "$$" > "$CONTROL_PID_FILE"
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

  ab -n "$REQUESTS_PER_ROUND" -c "$CONCURRENCY" "$TARGET" &
  AB_PID=$!
  wait "$AB_PID"
  EXIT_CODE=$?
  AB_PID=""
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
