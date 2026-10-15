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


if __name__ == "__main__":
    unittest.main()
