"""Exercise SSH log ingestion without requiring model libraries on the host."""

from __future__ import annotations

import importlib.util
import os
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import patch


PROJECT_DIR = Path(__file__).resolve().parents[1]


class FakeFlask:
    def __init__(self, name):
        self.name = name

    def route(self, *args, **kwargs):
        return lambda function: function

    post = route


class FakeDetector:
    active_model_label = "Random Forest"
    active_model_key = "random_forest"
    running = False
    finished = False

    active_model_keys = {"ddos": "random_forest", "ssh": "random_forest"}

    def model_label_for(self, attack_type):
        return "LightGBM" if self.active_model_keys[attack_type] == "lightgbm" else "Random Forest"

    def model_key_for(self, attack_type):
        return self.active_model_keys[attack_type]

    def available_models(self, attack_type="ddos"):
        return []

    def set_model(self, model_key, attack_type=None):
        if model_key not in {"random_forest", "lightgbm"}:
            raise ValueError("Unknown model")
        for kind in ([attack_type] if attack_type else ["ddos", "ssh"]):
            self.active_model_keys[kind] = model_key

    def reset(self):
        self.running = False
        self.finished = False


class SshDashboardApiTests(unittest.TestCase):
    def test_auth_event_dedup_stats_and_reset_preserve_ddos_until_reset(self):
        with tempfile.TemporaryDirectory() as temporary_dir:
            root = Path(temporary_dir)
            request = types.SimpleNamespace(headers={}, is_json=True)
            flask_stub = types.ModuleType("flask")
            flask_stub.Flask = FakeFlask
            flask_stub.jsonify = lambda value: value
            flask_stub.render_template = lambda name, **kwargs: name
            flask_stub.redirect = lambda value: value
            flask_stub.url_for = lambda endpoint: endpoint
            flask_stub.request = request
            detector_stub = types.ModuleType("src.realtime_detect")
            detector_stub.DATA_DIR = root
            detector_stub.DB_PATH = root / "ids_logs.db"
            detector_stub.LIVE_FLOWS_PATH = root / "live_flows.csv"
            detector_stub.FlowDetector = FakeDetector
            spec = importlib.util.spec_from_file_location("ssh_dashboard_test_app", PROJECT_DIR / "dashboard" / "app.py")
            module = importlib.util.module_from_spec(spec)
            with patch.dict(sys.modules, {"flask": flask_stub, "src.realtime_detect": detector_stub}), patch.dict(
                os.environ, {"IDS_SSH_AUTH_TOKEN": "lab-test-token"}
            ):
                spec.loader.exec_module(module)
                with module.get_db() as connection:
                    connection.execute(
                        """
                        INSERT INTO flow_logs (created_at, batch_no, input_source, model_name, attack_type,
                            batch_total, attack_count, benign_count, attack_rate, status, level,
                            source_ip, destination_ip, message)
                        VALUES ('2026-10-26 10:00:00', 1, 'live_sensor', 'Random Forest', 'ddos',
                            5, 2, 3, 40, 'DDoS Detected', 'MEDIUM', '192.168.247.10',
                            '192.168.247.20', 'test')
                        """
                    )

                event = {"event_key": "s=demo;i=1", "source_ip": "192.168.247.10", "source_port": 32936}
                request.get_json = lambda silent=True: event
                request.headers = {"X-IDS-Token": "wrong"}
                self.assertEqual(module.ssh_auth_event()[1], 401)
                request.headers = {"X-IDS-Token": "lab-test-token"}
                self.assertEqual(module.ssh_auth_event(), {"recorded": True})
                self.assertEqual(module.ssh_auth_event(), {"recorded": False})

                stats = module.load_dashboard_data()
                self.assertEqual(stats["ssh_auth"]["failed_passwords"], 1)
                self.assertEqual(stats["ssh_auth"]["sources"][0]["connections"], 1)
                self.assertEqual(stats["total_ddos"], 2)

                ddos_page = module.load_page_data("ddos")
                ssh_page = module.load_page_data("ssh")
                self.assertEqual(ddos_page["total_flows"], 5)
                self.assertEqual(ssh_page["total_flows"], 0)
                self.assertEqual(ssh_page["ssh_auth"]["failed_passwords"], 1)
                self.assertIsNone(ddos_page["ssh_auth"])

                request.json = {"model": "lightgbm", "attack_type": "ssh"}
                module.set_model()
                self.assertEqual(module.detector.model_key_for("ddos"), "random_forest")
                self.assertEqual(module.detector.model_key_for("ssh"), "lightgbm")
                request.json = {"model": "random_forest", "attack_type": "ssh"}
                module.set_model()

                for index in range(2, 11):
                    event["event_key"] = f"s=demo;i={index}"
                    self.assertEqual(module.ssh_auth_event(), {"recorded": True})
                stats = module.load_dashboard_data()
                self.assertEqual(stats["ssh_auth"]["failed_passwords"], 10)
                self.assertTrue(stats["ssh_auth"]["log_alert"])
                self.assertEqual(stats["ssh_auth"]["last_log_alert"]["source_ip"], "192.168.247.10")
                self.assertEqual(stats["total_ddos"], 2)

                with module.get_db() as connection:
                    connection.execute(
                        """INSERT INTO flow_logs (created_at, batch_no, input_source, model_name,
                        attack_type, batch_total, attack_count, benign_count, attack_rate, status,
                        level, source_ip, destination_ip, message)
                        VALUES ('2026-10-26 10:01:00', 2, 'live_sensor', 'Random Forest',
                        'ssh', 3, 1, 2, 33.3, 'SSH Brute Force Detected', 'MEDIUM',
                        '192.168.247.10', '192.168.247.20', 'SSH model test')"""
                    )
                self.assertEqual(module.load_page_data("ssh")["total_attacks"], 1)
                self.assertEqual(module.load_page_data("ddos")["total_attacks"], 2)
                self.assertEqual(len(module.load_page_data("ddos")["alerts"]), 1)
                self.assertEqual(len(module.load_page_data("ssh")["alerts"]), 1)

                request.json = {"action": "reset", "attack_type": "ssh"}
                module.control()
                self.assertEqual(module.load_page_data("ssh")["ssh_auth"]["failed_passwords"], 0)
                self.assertEqual(module.load_page_data("ssh")["total_attacks"], 0)
                self.assertEqual(module.load_page_data("ddos")["total_attacks"], 2)

                request.get_json = lambda silent=True: {"action": "reset"}
                request.json = {"action": "reset"}
                reset_stats = module.control()
                self.assertEqual(reset_stats["ssh_auth"]["failed_passwords"], 0)
                self.assertIsNone(reset_stats["ssh_auth"]["last_log_alert"])
                self.assertEqual(reset_stats["total_ddos"], 0)


if __name__ == "__main__":
    unittest.main()
