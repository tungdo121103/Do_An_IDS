from __future__ import annotations

import hmac
import ipaddress
import os
import sqlite3
import sys
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

from flask import Flask, jsonify, redirect, render_template, request, url_for

PROJECT_DIR = Path(__file__).resolve().parents[1]
if str(PROJECT_DIR) not in sys.path:
    sys.path.insert(0, str(PROJECT_DIR))

from src.realtime_detect import DATA_DIR, DB_PATH, LIVE_FLOWS_PATH, FlowDetector
HISTORY_SIZE = 30
ALERT_SIZE = 20
SSH_FAILURE_WINDOW_SECONDS = 60
SSH_FAILURE_ALERT_THRESHOLD = 10

app = Flask(__name__)
detector = FlowDetector()


@contextmanager
def get_db() -> Iterator[sqlite3.Connection]:
    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row
    try:
        with connection:
            yield connection
    finally:
        connection.close()


def ensure_column(connection: sqlite3.Connection, table: str, column: str, definition: str) -> None:
    columns = {row["name"] for row in connection.execute(f"PRAGMA table_info({table})")}
    if column not in columns:
        connection.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")


def init_db() -> None:
    DATA_DIR.mkdir(exist_ok=True)
    LIVE_FLOWS_PATH.touch(exist_ok=True)
    with get_db() as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS flow_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at TEXT NOT NULL,
                batch_no INTEGER,
                input_source TEXT,
                model_name TEXT,
                attack_type TEXT,
                batch_total INTEGER NOT NULL,
                attack_count INTEGER NOT NULL,
                benign_count INTEGER NOT NULL,
                attack_rate REAL NOT NULL,
                status TEXT NOT NULL,
                level TEXT NOT NULL,
                source_ip TEXT NOT NULL,
                destination_ip TEXT NOT NULL,
                message TEXT NOT NULL
            )
            """
        )
        ensure_column(connection, "flow_logs", "batch_no", "INTEGER")
        ensure_column(connection, "flow_logs", "input_source", "TEXT")
        ensure_column(connection, "flow_logs", "model_name", "TEXT")
        ensure_column(connection, "flow_logs", "attack_type", "TEXT")
        connection.execute("UPDATE flow_logs SET batch_no = id WHERE batch_no IS NULL")
        connection.execute("UPDATE flow_logs SET input_source = 'legacy' WHERE input_source IS NULL")
        connection.execute("UPDATE flow_logs SET model_name = 'Random Forest' WHERE model_name IS NULL")
        connection.execute("UPDATE flow_logs SET attack_type = 'ddos' WHERE attack_type IS NULL")
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS ssh_auth_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_key TEXT NOT NULL UNIQUE,
                received_at INTEGER NOT NULL,
                source_ip TEXT NOT NULL,
                source_port INTEGER NOT NULL
            )
            """
        )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_ssh_auth_received_at ON ssh_auth_events(received_at)"
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS ssh_log_alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at INTEGER NOT NULL,
                source_ip TEXT NOT NULL,
                failed_passwords INTEGER NOT NULL,
                window_seconds INTEGER NOT NULL
            )
            """
        )


def load_dashboard_data() -> dict:
    with get_db() as connection:
        totals = connection.execute(
            """
            SELECT
                COALESCE(SUM(batch_total), 0) AS total_flows,
                COALESCE(SUM(attack_count), 0) AS total_attacks,
                COALESCE(SUM(CASE WHEN attack_type = 'ddos' THEN attack_count ELSE 0 END), 0) AS total_ddos,
                COALESCE(SUM(CASE WHEN attack_type = 'ssh' THEN attack_count ELSE 0 END), 0) AS total_ssh,
                COALESCE(SUM(CASE WHEN attack_type = 'ssh' THEN batch_total ELSE 0 END), 0) AS total_ssh_flows,
                COALESCE(SUM(benign_count), 0) AS total_benign
            FROM flow_logs
            """
        ).fetchone()
        latest = connection.execute(
            """
            SELECT * FROM flow_logs
            ORDER BY id DESC
            LIMIT 1
            """
        ).fetchone()
        history_rows = connection.execute(
            """
            SELECT batch_no, created_at, input_source, model_name, attack_type, batch_total, attack_count, benign_count, attack_rate
            FROM flow_logs
            ORDER BY id DESC
            LIMIT ?
            """,
            (HISTORY_SIZE,),
        ).fetchall()
        auth_total = connection.execute(
            "SELECT COUNT(*) AS failures, MAX(received_at) AS last_seen FROM ssh_auth_events"
        ).fetchone()
        auth_recent = connection.execute(
            "SELECT COUNT(*) AS failures FROM ssh_auth_events WHERE received_at >= ?",
            (int(time.time()) - SSH_FAILURE_WINDOW_SECONDS,),
        ).fetchone()
        auth_sources = connection.execute(
            """
            SELECT source_ip, COUNT(*) AS failures, COUNT(DISTINCT source_port) AS connections,
                   MAX(received_at) AS last_seen,
                   SUM(CASE WHEN received_at >= ? THEN 1 ELSE 0 END) AS recent_failures
            FROM ssh_auth_events
            GROUP BY source_ip
            ORDER BY failures DESC
            LIMIT 10
            """,
            (int(time.time()) - SSH_FAILURE_WINDOW_SECONDS,),
        ).fetchall()
        last_log_alert = connection.execute(
            "SELECT created_at, source_ip, failed_passwords, window_seconds FROM ssh_log_alerts ORDER BY id DESC LIMIT 1"
        ).fetchone()
        active_ssh = connection.execute(
            """
            SELECT COALESCE(SUM(batch_total), 0) AS flows,
                   COALESCE(SUM(attack_count), 0) AS attacks
            FROM flow_logs
            WHERE attack_type = 'ssh' AND model_name = ?
            """,
            (detector.model_label_for("ssh"),),
        ).fetchone()
        alert_rows = connection.execute(
            """
            SELECT batch_no, created_at, level, message, source_ip, destination_ip
            FROM flow_logs
            WHERE attack_count > 0
            ORDER BY id DESC
            LIMIT ?
            """,
            (ALERT_SIZE,),
        ).fetchall()

    history = [
        {
            "batch_no": row["batch_no"],
            "time": row["created_at"].split()[-1],
            "input_source": row["input_source"],
            "model_name": row["model_name"],
            "attack_type": row["attack_type"],
            "flows": row["batch_total"],
            "attacks": row["attack_count"],
            "ddos": row["attack_count"] if row["attack_type"] == "ddos" else 0,
            "ssh": row["attack_count"] if row["attack_type"] == "ssh" else 0,
            "benign": row["benign_count"],
            "attack_rate": row["attack_rate"],
        }
        for row in reversed(history_rows)
    ]
    alerts = [
        {
            "batch_no": row["batch_no"],
            "time": row["created_at"].split()[-1],
            "level": row["level"],
            "message": row["message"],
            "source_ip": row["source_ip"],
            "destination_ip": row["destination_ip"],
        }
        for row in alert_rows
    ]

    status = latest["status"] if latest else "Idle"
    if detector.finished:
        status = "Live Finished"
    elif detector.running and status in {"Idle", "Normal", "Paused"}:
        status = "Running"
    elif not detector.running:
        status = "Paused"

    return {
        "total_flows": totals["total_flows"],
        "total_attacks": totals["total_attacks"],
        "total_ddos": totals["total_ddos"],
        "total_ssh": totals["total_ssh"],
        "total_ssh_flows": totals["total_ssh_flows"],
        "ssh_active_model": {
            "flows": active_ssh["flows"],
            "attacks": active_ssh["attacks"],
        },
        "total_benign": totals["total_benign"],
        "last_batch": latest["batch_total"] if latest else 0,
        "last_attack_rate": latest["attack_rate"] if latest else 0,
        "input_source": latest["input_source"] if latest else "none",
        "model_name": latest["model_name"] if latest else detector.active_model_label,
        "active_model_key": detector.active_model_key,
        "active_model_label": detector.active_model_label,
        "available_models": detector.available_models(),
        "status": status,
        "running": detector.running,
        "simulation_finished": detector.finished,
        "live_flows_path": str(LIVE_FLOWS_PATH),
        "history": history,
        "alerts": alerts,
        "ssh_auth": {
            "enabled": bool(os.environ.get("IDS_SSH_AUTH_TOKEN")),
            "failed_passwords": auth_total["failures"],
            "recent_failed_passwords": auth_recent["failures"],
            "last_seen": auth_total["last_seen"],
            "window_seconds": SSH_FAILURE_WINDOW_SECONDS,
            "threshold": SSH_FAILURE_ALERT_THRESHOLD,
            "log_alert": any(row["recent_failures"] >= SSH_FAILURE_ALERT_THRESHOLD for row in auth_sources),
            "last_log_alert": dict(last_log_alert) if last_log_alert else None,
            "sources": [
                {
                    "ip": row["source_ip"],
                    "failures": row["failures"],
                    "connections": row["connections"],
                    "recent_failures": row["recent_failures"],
                    "last_seen": row["last_seen"],
                }
                for row in auth_sources
            ],
        },
    }


def load_page_data(attack_type: str) -> dict:
    """Return only the selected detector's predictions; SSH log evidence stays separate."""
    model_label = detector.model_label_for(attack_type)
    with get_db() as connection:
        where = "WHERE attack_type = ? AND model_name = ?"
        params = (attack_type, model_label)
        totals = connection.execute(
            f"SELECT COALESCE(SUM(batch_total), 0) AS flows, COALESCE(SUM(attack_count), 0) AS attacks, "
            f"COALESCE(SUM(benign_count), 0) AS benign FROM flow_logs {where}", params
        ).fetchone()
        latest = connection.execute(
            f"SELECT * FROM flow_logs {where} ORDER BY id DESC LIMIT 1", params
        ).fetchone()
        history_rows = connection.execute(
            f"SELECT batch_no, created_at, batch_total, attack_count, benign_count FROM flow_logs {where} "
            "ORDER BY id DESC LIMIT ?", (*params, HISTORY_SIZE)
        ).fetchall()
        alert_rows = connection.execute(
            f"SELECT batch_no, created_at, level, message, source_ip, destination_ip, attack_count "
            f"FROM flow_logs {where} AND attack_count > 0 ORDER BY id DESC LIMIT ?",
            (*params, ALERT_SIZE),
        ).fetchall()
        auth = None
        if attack_type == "ssh":
            now = int(time.time())
            auth_total = connection.execute(
                "SELECT COUNT(*) AS failures, MAX(received_at) AS last_seen FROM ssh_auth_events"
            ).fetchone()
            auth_recent = connection.execute(
                "SELECT COUNT(*) AS failures FROM ssh_auth_events WHERE received_at >= ?",
                (now - SSH_FAILURE_WINDOW_SECONDS,),
            ).fetchone()["failures"]
            source_rows = connection.execute(
                "SELECT source_ip, COUNT(*) AS failures, COUNT(DISTINCT source_port) AS connections, "
                "MAX(received_at) AS last_seen, SUM(CASE WHEN received_at >= ? THEN 1 ELSE 0 END) AS recent_failures "
                "FROM ssh_auth_events GROUP BY source_ip ORDER BY failures DESC LIMIT 10",
                (now - SSH_FAILURE_WINDOW_SECONDS,),
            ).fetchall()
            last_alert = connection.execute(
                "SELECT created_at, source_ip, failed_passwords, window_seconds "
                "FROM ssh_log_alerts ORDER BY id DESC LIMIT 1"
            ).fetchone()
            timeline_rows = connection.execute(
                "SELECT (received_at / 10) * 10 AS bucket, COUNT(*) AS failures "
                "FROM ssh_auth_events GROUP BY bucket ORDER BY bucket DESC LIMIT 30"
            ).fetchall()
            auth = {
                "enabled": bool(os.environ.get("IDS_SSH_AUTH_TOKEN")),
                "failed_passwords": auth_total["failures"],
                "recent_failed_passwords": auth_recent,
                "last_seen": auth_total["last_seen"],
                "window_seconds": SSH_FAILURE_WINDOW_SECONDS,
                "threshold": SSH_FAILURE_ALERT_THRESHOLD,
                "log_alert": any(row["recent_failures"] >= SSH_FAILURE_ALERT_THRESHOLD for row in source_rows),
                "last_log_alert": dict(last_alert) if last_alert else None,
                "sources": [dict(row) | {"ip": row["source_ip"]} for row in source_rows],
                "timeline": [dict(row) for row in reversed(timeline_rows)],
            }

    history = [
        {"batch_no": row["batch_no"], "time": row["created_at"].split()[-1],
         "flows": row["batch_total"], "attacks": row["attack_count"],
         "benign": row["benign_count"]}
        for row in reversed(history_rows)
    ]
    alerts = [
        {"batch_no": row["batch_no"], "time": row["created_at"].split()[-1],
         "level": row["level"], "message": row["message"], "source_ip": row["source_ip"],
         "destination_ip": row["destination_ip"], "count": row["attack_count"]}
        for row in alert_rows
    ]
    status = "Paused" if not detector.running else latest["status"] if latest and latest["attack_count"] else "Running"
    rate = round(100 * totals["attacks"] / totals["flows"], 1) if totals["flows"] else 0
    return {
        "attack_type": attack_type, "total_flows": totals["flows"],
        "total_attacks": totals["attacks"], "total_benign": totals["benign"],
        "flagged_rate": rate, "last_batch": latest["batch_total"] if latest else 0,
        "last_attack_rate": latest["attack_rate"] if latest else 0,
        "active_model_key": detector.model_key_for(attack_type),
        "active_model_label": model_label,
        "available_models": detector.available_models(attack_type),
        "status": status, "running": detector.running, "simulation_finished": detector.finished,
        "history": history, "alerts": alerts, "ssh_auth": auth,
    }


@app.route("/")
def index():
    return redirect(url_for("ddos_page"))


@app.route("/ddos")
def ddos_page():
    return render_template("detector.html", attack_type="ddos")


@app.route("/ssh")
def ssh_page():
    return render_template("detector.html", attack_type="ssh")


@app.route("/api/stats")
def stats():
    attack_type = request.args.get("attack_type")
    if attack_type not in (None, "ddos", "ssh"):
        return jsonify({"error": "Invalid attack type"}), 400
    with get_db() as connection:
        detector.tick(connection)

    return jsonify(load_page_data(attack_type) if attack_type else load_dashboard_data())


@app.post("/api/model")
def set_model():
    model_key = request.json.get("model") if request.is_json else None
    attack_type = request.json.get("attack_type") if request.is_json else None
    if attack_type not in (None, "ddos", "ssh"):
        return jsonify({"error": "Invalid attack type"}), 400

    try:
        detector.set_model(model_key, attack_type)
    except ValueError as error:
        return jsonify({"error": str(error)}), 400

    return jsonify(load_page_data(attack_type) if attack_type else load_dashboard_data())


@app.post("/api/ssh-auth-event")
def ssh_auth_event():
    expected_token = os.environ.get("IDS_SSH_AUTH_TOKEN", "")
    supplied_token = request.headers.get("X-IDS-Token", "")
    if not expected_token:
        return jsonify({"error": "SSH auth log receiver is not configured"}), 503
    if not hmac.compare_digest(supplied_token, expected_token):
        return jsonify({"error": "Unauthorized"}), 401

    event = request.get_json(silent=True)
    if not isinstance(event, dict):
        return jsonify({"error": "Expected a JSON object"}), 400
    event_key = event.get("event_key")
    source_ip = event.get("source_ip")
    source_port = event.get("source_port")
    if not isinstance(event_key, str) or not 1 <= len(event_key) <= 512:
        return jsonify({"error": "Invalid event key"}), 400
    try:
        if not isinstance(source_ip, str):
            raise ValueError("Invalid source IP")
        source_ip = str(ipaddress.ip_address(source_ip))
        if isinstance(source_port, bool) or not isinstance(source_port, int) or not 1 <= source_port <= 65535:
            raise ValueError("Invalid source port")
    except ValueError:
        return jsonify({"error": "Invalid source address or port"}), 400

    recorded_at = int(time.time())
    with get_db() as connection:
        cursor = connection.execute(
            "INSERT OR IGNORE INTO ssh_auth_events (event_key, received_at, source_ip, source_port) VALUES (?, ?, ?, ?)",
            (event_key, recorded_at, source_ip, source_port),
        )
        if cursor.rowcount == 1:
            recent_failures = connection.execute(
                "SELECT COUNT(*) FROM ssh_auth_events WHERE source_ip = ? AND received_at >= ?",
                (source_ip, recorded_at - SSH_FAILURE_WINDOW_SECONDS),
            ).fetchone()[0]
            if recent_failures == SSH_FAILURE_ALERT_THRESHOLD:
                connection.execute(
                    "INSERT INTO ssh_log_alerts (created_at, source_ip, failed_passwords, window_seconds) VALUES (?, ?, ?, ?)",
                    (recorded_at, source_ip, recent_failures, SSH_FAILURE_WINDOW_SECONDS),
                )
    return jsonify({"recorded": cursor.rowcount == 1})


@app.post("/api/control")
def control():
    action = request.json.get("action") if request.is_json else None
    attack_type = request.json.get("attack_type") if request.is_json else None
    if attack_type not in (None, "ddos", "ssh"):
        return jsonify({"error": "Invalid attack type"}), 400

    if action == "start":
        detector.start()
    elif action == "pause":
        detector.pause()
    elif action == "reset":
        if attack_type:
            with get_db() as connection:
                connection.execute("DELETE FROM flow_logs WHERE attack_type = ? AND model_name = ?",
                                   (attack_type, detector.model_label_for(attack_type)))
                if attack_type == "ssh":
                    connection.execute("DELETE FROM ssh_auth_events")
                    connection.execute("DELETE FROM ssh_log_alerts")
        else:
            detector.reset()
            with get_db() as connection:
                connection.execute("DELETE FROM flow_logs")
                connection.execute("DELETE FROM ssh_auth_events")
                connection.execute("DELETE FROM ssh_log_alerts")
                connection.execute("DELETE FROM sqlite_sequence WHERE name = 'flow_logs'")
                connection.execute("DELETE FROM sqlite_sequence WHERE name = 'ssh_auth_events'")
                connection.execute("DELETE FROM sqlite_sequence WHERE name = 'ssh_log_alerts'")
            LIVE_FLOWS_PATH.write_text("", encoding="utf-8")
    else:
        return jsonify({"error": "Invalid action"}), 400

    return jsonify(load_page_data(attack_type) if attack_type else load_dashboard_data())


init_db()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)




