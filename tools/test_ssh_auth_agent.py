import unittest

from tools.ssh_auth_agent import parse_event


class SshAuthAgentTests(unittest.TestCase):
    def test_failed_password_event_keeps_only_network_metadata(self):
        record = {
            "__CURSOR": "s=demo;i=1",
            "MESSAGE": "Failed password for victim from 192.168.247.10 port 32936 ssh2",
        }
        self.assertEqual(
            parse_event(record),
            {"event_key": "s=demo;i=1", "source_ip": "192.168.247.10", "source_port": 32936},
        )

    def test_invalid_user_and_non_failure(self):
        record = {
            "__CURSOR": "s=demo;i=2",
            "MESSAGE": "Failed password for invalid user guest from 192.168.247.10 port 48904 ssh2",
        }
        self.assertEqual(parse_event(record)["source_port"], 48904)
        record["MESSAGE"] = "Accepted password for victim from 192.168.247.10 port 48904 ssh2"
        self.assertIsNone(parse_event(record))

    def test_rejects_invalid_address_or_missing_cursor(self):
        record = {"__CURSOR": "s=demo;i=3", "MESSAGE": "Failed password for victim from not-an-ip port 22 ssh2"}
        self.assertIsNone(parse_event(record))
        record["MESSAGE"] = "Failed password for victim from 192.168.247.10 port 22 ssh2"
        record.pop("__CURSOR")
        self.assertIsNone(parse_event(record))


if __name__ == "__main__":
    unittest.main()
