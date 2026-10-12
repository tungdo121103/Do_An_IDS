from __future__ import annotations

import sqlite3
import sys
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

from flask import Flask, jsonify, render_template, request

PROJECT_DIR = Path(__file__).resolve().parents[1]
if str(PROJECT_DIR) not in sys.path:
    sys.path.insert(0, str(PROJECT_DIR))

from src.realtime_detect import DATA_DIR, DB_PATH, LIVE_FLOWS_PATH, FlowDetector
HISTORY_SIZE = 30
ALERT_SIZE = 20

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


def load_dashboard_data() -> dict:
    with get_db() as connection:
        totals = connection.execute(
            """
            SELECT
                COALESCE(SUM(batch_total), 0) AS total_flows,
                COALESCE(SUM(attack_count), 0) AS total_attacks,
                COALESCE(SUM(CASE WHEN attack_type = 'ddos' THEN attack_count ELSE 0 END), 0) AS total_ddos,
                COALESCE(SUM(CASE WHEN attack_type = 'ssh' THEN attack_count ELSE 0 END), 0) AS total_ssh,
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
    }


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/stats")
def stats():
    with get_db() as connection:
        detector.tick(connection)

    return jsonify(load_dashboard_data())


@app.post("/api/model")
def set_model():
    model_key = request.json.get("model") if request.is_json else None

    try:
        detector.set_model(model_key)
    except ValueError as error:
        return jsonify({"error": str(error)}), 400

    return jsonify(load_dashboard_data())


@app.post("/api/control")
def control():
    action = request.json.get("action") if request.is_json else None

    if action == "start":
        detector.start()
    elif action == "pause":
        detector.pause()
    elif action == "reset":
        detector.reset()
        with get_db() as connection:
            connection.execute("DELETE FROM flow_logs")
            connection.execute("DELETE FROM sqlite_sequence WHERE name = 'flow_logs'")
        LIVE_FLOWS_PATH.write_text("", encoding="utf-8")
    else:
        return jsonify({"error": "Invalid action"}), 400

    return jsonify(load_dashboard_data())


init_db()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)




