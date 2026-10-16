"""
Unit tests for Check 3: Selected TCP Ports & Services.
"""

import unittest
from unittest.mock import patch, MagicMock
from modules.port_checker import PortChecker
from database import init_db, seed_initial_lab_data


class TestPortChecker(unittest.TestCase):
    def setUp(self):
        init_db()
        seed_initial_lab_data()
        self.checker = PortChecker(timeout=0.5)

    def test_closed_port_detection(self):
        # Localhost on an unused high port should return CLOSED
        res = self.checker.check_single_port("127.0.0.1", 49876)
        self.assertEqual(res["state"], "CLOSED")
        self.assertEqual(res["port"], 49876)

    def test_unexpected_port_flagging(self):
        # 10.0.1.15 only has 443 and 8443 in baseline
        # Port 8888 must be flagged as unexpected
        self.checker.baseline_matrix = {"10.0.1.15": [443, 8443]}
        with patch.object(self.checker, "_grab_banner", return_value=("HTTP/1.1 200 OK", "HTTP")):
            with patch("socket.socket.connect_ex", return_value=0):
                res = self.checker.check_single_port("10.0.1.15", 8888)
                self.assertEqual(res["state"], "OPEN")
                self.assertEqual(res["is_unexpected"], 1)

    def test_approved_port_not_unexpected(self):
        self.checker.baseline_matrix = {"10.0.1.15": [443, 8443]}
        with patch.object(self.checker, "_grab_banner", return_value=("", "HTTPS")):
            with patch("socket.socket.connect_ex", return_value=0):
                res = self.checker.check_single_port("10.0.1.15", 443)
                self.assertEqual(res["state"], "OPEN")
                self.assertEqual(res["is_unexpected"], 0)

    def test_runtime_settings_loading_and_propagation(self):
        """Verifies database settings load, parse correctly, and propagate to checker instances."""
        from modules.scheduler import BackgroundMonitor
        from database import get_db_connection
        from config import DEFAULT_SOCKET_TIMEOUT, DEFAULT_APPROVED_PORTS

        conn = get_db_connection()
        cursor = conn.cursor()

        # 1. Update settings in database with custom values
        cursor.execute("UPDATE settings SET value = '4.5' WHERE key = 'socket_timeout_seconds'")
        cursor.execute("UPDATE settings SET value = '80, 443, 8080' WHERE key = 'allowed_ports'")
        conn.commit()

        # Load settings via BackgroundMonitor.load_runtime_settings
        cfg = BackgroundMonitor.load_runtime_settings(cursor)
        self.assertEqual(cfg["socket_timeout"], 4.5)
        self.assertEqual(cfg["allowed_ports"], [80, 443, 8080])

        # Verify checker initialized with loaded timeout
        checker = PortChecker(timeout=cfg["socket_timeout"])
        self.assertEqual(checker.timeout, 4.5)

        # Verify checker port inspection receives the custom allowed_ports list
        with patch.object(checker, "check_single_port") as mock_check:
            mock_check.return_value = {"port": 80, "state": "CLOSED"}
            checker.inspect_host_ports("127.0.0.1", port_list=cfg["allowed_ports"])
            inspected_ports = [call[0][1] for call in mock_check.call_args_list]
            self.assertEqual(inspected_ports, [80, 443, 8080])

        # 2. Test fallback when database settings are invalid or empty
        cursor.execute("UPDATE settings SET value = 'invalid_timeout' WHERE key = 'socket_timeout_seconds'")
        cursor.execute("UPDATE settings SET value = 'invalid, non_numeric' WHERE key = 'allowed_ports'")
        conn.commit()

        fallback_cfg = BackgroundMonitor.load_runtime_settings(cursor)
        self.assertEqual(fallback_cfg["socket_timeout"], DEFAULT_SOCKET_TIMEOUT)
        self.assertEqual(fallback_cfg["allowed_ports"], DEFAULT_APPROVED_PORTS)

        # 3. Test load_runtime_settings without passing cursor (using internal connection)
        standalone_cfg = BackgroundMonitor.load_runtime_settings()
        self.assertEqual(standalone_cfg["socket_timeout"], DEFAULT_SOCKET_TIMEOUT)
        self.assertEqual(standalone_cfg["allowed_ports"], DEFAULT_APPROVED_PORTS)

        # Clean up database settings back to defaults
        cursor.execute("UPDATE settings SET value = ? WHERE key = 'socket_timeout_seconds'", (str(DEFAULT_SOCKET_TIMEOUT),))
        cursor.execute("UPDATE settings SET value = ? WHERE key = 'allowed_ports'", (", ".join(str(p) for p in DEFAULT_APPROVED_PORTS),))
        conn.commit()
        conn.close()


if __name__ == "__main__":
    unittest.main()
