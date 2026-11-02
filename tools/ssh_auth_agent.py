#!/usr/bin/env python3
"""Forward failed SSH logins from the lab Victim to the IDS dashboard.

Run on the Victim before the SSH demo. This sends source address and port only;
passwords and attempted usernames never leave the Victim.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import subprocess
import time
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


FAILED_PASSWORD = re.compile(
    r"Failed password for (?:invalid user )?\S+ from (?P<ip>\S+) port (?P<port>\d+)\b"
)


def parse_event(record: dict) -> dict | None:
    match = FAILED_PASSWORD.search(str(record.get("MESSAGE", "")))
    cursor = record.get("__CURSOR")
    if not match or not isinstance(cursor, str) or not cursor:
        return None
    try:
        source_ip = str(ipaddress.ip_address(match.group("ip")))
        source_port = int(match.group("port"))
    except ValueError:
        return None
    if not 1 <= source_port <= 65535:
        return None
    return {"event_key": cursor, "source_ip": source_ip, "source_port": source_port}


def send_event(url: str, token: str, event: dict) -> None:
    payload = json.dumps(event).encode("utf-8")
    request = Request(
        url,
        data=payload,
        headers={"Content-Type": "application/json", "X-IDS-Token": token},
        method="POST",
    )
    while True:
        try:
            with urlopen(request, timeout=5) as response:
                response.read()
            return
        except HTTPError as error:
            if error.code in {400, 401, 413}:
                raise RuntimeError(f"IDS rejected the log event (HTTP {error.code}); check the shared token and endpoint") from error
            print(f"IDS unavailable (HTTP {error.code}); retrying this log event in 3 seconds", flush=True)
            time.sleep(3)
        except (URLError, TimeoutError) as error:
            print(f"IDS unavailable ({error}); retrying this log event in 3 seconds", flush=True)
            time.sleep(3)


def main() -> None:
    parser = argparse.ArgumentParser(description="Send new SSH password failures to the IDS lab dashboard.")
    parser.add_argument(
        "--ids-url",
        default="http://192.168.247.30:5000/api/ssh-auth-event",
        help="IDS SSH auth event endpoint",
    )
    args = parser.parse_args()
    token = os.environ.get("IDS_SSH_AUTH_TOKEN", "")
    if not token:
        parser.error("Set IDS_SSH_AUTH_TOKEN to the same value on Victim and IDS")

    command = ["journalctl", "-u", "ssh", "-u", "sshd", "-n", "0", "-f", "-o", "json", "--no-pager"]
    print("Watching new SSH password failures on Victim. Press Ctrl+C to stop.", flush=True)
    try:
        while True:
            journal = subprocess.Popen(command, stdout=subprocess.PIPE, text=True, encoding="utf-8")
            try:
                assert journal.stdout is not None
                for line in journal.stdout:
                    try:
                        record = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    event = parse_event(record)
                    if event is None:
                        continue
                    send_event(args.ids_url, token, event)
                    print(f"Failed SSH password from {event['source_ip']}:{event['source_port']}", flush=True)
            finally:
                if journal.poll() is None:
                    journal.terminate()
                journal.wait()
            print("journalctl stopped; restarting in 3 seconds", flush=True)
            time.sleep(3)
    except KeyboardInterrupt:
        print("Stopped SSH auth agent.", flush=True)
    except RuntimeError as error:
        parser.exit(1, f"{error}\n")


if __name__ == "__main__":
    main()
