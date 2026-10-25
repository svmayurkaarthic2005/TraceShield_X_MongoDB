"""Regression tests for failed sudo password classification."""

import unittest

from ingestion.services import log_parser


class PrivilegeEscalationRegexTests(unittest.TestCase):
    def setUp(self):
        log_parser.reset_state()

    def tearDown(self):
        log_parser.reset_state()

    def test_failed_sudo_password_is_not_privilege_escalation(self):
        parsed = log_parser.parse_log_line(
            "sudo: admin : 1 incorrect password attempt"
        )
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed["failed_login"], 1)
        self.assertEqual(parsed["privilege_escalation"], 0)

    def test_sudo_password_phrase_in_sudo_log_is_detected_as_failed_login(self):
        result = log_parser.ingest_logs_for_ip(
            "192.0.2.10",
            ["sudo: admin : 1 incorrect password attempt"],
        )
        self.assertEqual(result["failed_logins"], 1)
        self.assertEqual(result["privilege_escalations"], 0)

    def test_actual_sudo_root_shell_remains_privilege_escalation(self):
        parsed = log_parser.parse_log_line(
            "host sudo: admin : TTY=pts/0 ; PWD=/tmp ; USER=root ; COMMAND=/bin/bash"
        )
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed["privilege_escalation"], 1)

    def test_su_failure_remains_privilege_escalation(self):
        parsed = log_parser.parse_log_line("su: FAILED su for root by admin")
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed["privilege_escalation"], 1)


if __name__ == "__main__":
    unittest.main()
