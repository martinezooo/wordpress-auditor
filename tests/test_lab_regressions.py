"""Regressions found by scanning the local Docker lab (lab/), not by mocks.

Each case mirrors a real mismatch between scanner output and the lab's
actual configuration.
"""
import unittest
from types import SimpleNamespace

from wordpress_auditor.assessment import assess
from wordpress_auditor.check_catalog import coverage
from wordpress_auditor.core_scenarios import operation_matrix
from wordpress_auditor.wp_permissions import summarize_xmlrpc_policy
from wordpress_auditor.wp_policy import classify


def row(name, status, visibility="not-confirmed", detail=""):
    return SimpleNamespace(name=name, url="http://lab/", status=status,
                           visibility=visibility, detail=detail)


class LabRegressionTests(unittest.TestCase):
    def test_application_passwords_disabled_501_is_not_review(self):
        # WordPress answers 501 application_passwords_disabled on plain HTTP/off.
        self.assertEqual(assess("WP REST app-password list (anonymous)", 501,
                                "feature-disabled", "disabled")[0], "INFO")
        # Unknown 5xx must still need review.
        self.assertEqual(assess("WP REST app-password list (anonymous)", 500,
                                "unverified", "")[0], "REVIEW")

    def test_open_registration_is_review_not_info(self):
        body = (b'<form id="registerform" action="x"><input name="user_login">'
                b'<input name="user_email"></form>')
        verdict, _ = classify("register", 200, body)
        self.assertEqual(assess("WP registration form", 200, verdict, "")[0], "REVIEW")

    def test_matrix_reports_most_severe_probe_not_last(self):
        rows = [
            row("WordPress artifact config", 200,
                "confirmed-public-config-backup", "bak exposed"),
            row("WordPress artifact config", 404),  # later probe, e.g. .swp
        ]
        auditor = SimpleNamespace(results=rows)
        matrix = operation_matrix(auditor)
        config = next(m for m in matrix if m["operation"] == "config.read")
        channel = next(c for c in config["channels"]
                       if c["channel"] == "WordPress config backup")
        self.assertEqual(channel["status"], "CONFIRMED")
        self.assertIn("confirmed-public-config-backup", channel["evidence"])

    def test_xmlrpc_policy_uses_engine_probe_name(self):
        results = [row("XML-RPC endpoint GET", 405),
                   row("XML-RPC system.listMethods", 200)]
        verdict, _ = summarize_xmlrpc_policy(results)
        self.assertNotEqual(verdict, "not-evaluated")

    def test_derived_channel_comparison_is_not_an_error(self):
        rows = [row("WP REST channel comparison private posts", None,
                    "channel-comparison", "Both routes denied anonymous access")]
        auditor = SimpleNamespace(results=rows, phase_stats=[], ajax_actions=set())
        item = next(i for i in coverage(auditor) if i["id"] == "WP-68")
        self.assertNotEqual(item["status"], "ERROR")


if __name__ == "__main__":
    unittest.main()
