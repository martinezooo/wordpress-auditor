"""No off-site traffic: severity and ANSI behavior against a local WordPress mock."""
import contextlib
import io
import json
import os
import re
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from unittest.mock import patch

from wordpress_auditor.assessment import assess
from wordpress_auditor.auditor import Auditor
from wordpress_auditor.cli import main
from wordpress_auditor.console import LivePrinter, color_summary, supports_color
from wordpress_auditor.reporting import format_terminal
from wordpress_auditor.wp_checks import check_exposures


EXAMPLE_SECRET = "TEST_ONLY_DUMMY_PASS_NEVER_REAL"


class WordPressArtifacts(BaseHTTPRequestHandler):
    requests = []

    def log_message(self, *_):
        return

    def do_GET(self):
        self.__class__.requests.append(self.path)
        status, content = 404, b"Not found"
        if self.path == "/wp-config.php.bak":
            status = 200
            content = (b"<?php define('DB_NAME', 'test'); define('DB_PASSWORD', '" +
                       EXAMPLE_SECRET.encode() + b"');")
        elif self.path == "/wp-content/debug.log":
            status = 200
            content = b"[20-Oct-2026] PHP Fatal error: Uncaught Error in /wp-content"
        elif self.path == "/wp-content/uploads/":
            status = 200
            content = b"<html><title>Index of /wp-content/uploads/</title></html>"
        elif self.path == "/wp-config.php~":
            status = 200
            content = b"<html><h1>WordPress homepage</h1></html>"
        elif self.path == "/wp-config.php.save":
            status = 403
            content = b"Access denied"
        self.send_response(status)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(content)


class TestSeverityPresentation(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = HTTPServer(("127.0.0.1", 0), WordPressArtifacts)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.url = "http://127.0.0.1:%d" % cls.server.server_port

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=2)

    def setUp(self):
        WordPressArtifacts.requests = []

    def test_signature_confirmed_high_medium_low_and_no_leaks(self):
        a = Auditor(self.url, limit=12, delay=0)
        self.assertEqual(check_exposures(a), 6)
        verified = {r.severity: r for r in a.results if r.confidence == "confirmed"}
        self.assertEqual(set(verified), {"HIGH", "MEDIUM", "LOW"})
        self.assertEqual(verified["HIGH"].visibility, "confirmed-public-config-backup")
        self.assertEqual(verified["MEDIUM"].visibility, "confirmed-public-debug-log")
        self.assertEqual(verified["LOW"].visibility, "confirmed-public-directory-listing")
        self.assertEqual(a.results[0].severity, "INFO")
        self.assertNotIn(EXAMPLE_SECRET, json.dumps([r.__dict__ for r in a.results]))
        self.assertNotIn(EXAMPLE_SECRET, format_terminal(a, [r.__dict__ for r in a.results]))

    def test_soft404_and_access_denied_do_not_make_severity(self):
        a = Auditor(self.url, limit=12)
        check_exposures(a)
        r = [r for r in a.results if r.url.endswith("/wp-config.php~")][0]
        self.assertEqual(r.severity, "INFO")
        forbidden = [r for r in a.results if r.url.endswith("/wp-config.php.save")][0]
        self.assertEqual(forbidden.severity, "INFO")

    def test_ordinary_wp_statuses_and_metadata_are_not_high(self):
        for name, status, vis, detail in [
            ("admin-ajax.php", 200, "response-observed", ""),
            ("WP REST users", 401, "auth-required", ""),
            ("XML-RPC endpoint", 405, "not-evaluated", ""),
            ("HTTP method HEAD", 501, "method-not-supported", ""),
            ("AJAX test", 200, "response-observed", "response-observed/requires-review"),
        ]:
            severity, _ = assess(name, status, vis, detail)
            self.assertNotIn(severity, ("HIGH", "MEDIUM", "LOW"))
        self.assertEqual(assess("SSRF", 200, "requires-oast-correlation", "")[0],
                         "REVIEW")

    def test_live_printer_shows_colored_confirmed_finding(self):
        a = Auditor(self.url, limit=9)
        sink = io.StringIO()
        live = LivePrinter(enabled=True, color=True, every=2, stream=sink)
        a.finding_callback = live.finding
        a.request_progress_callback = live.request
        check_exposures(a)
        data = sink.getvalue()
        self.assertIn("\033[1;31m", data)  # HIGH red
        self.assertIn("\033[1;33m", data)  # MEDIUM yellow
        self.assertIn("\033[1;36m", data)  # LOW cyan
        self.assertIn("[PROGRESS]", data)
        self.assertIn("/wp-config.php.bak", data)
        self.assertNotIn(EXAMPLE_SECRET, data)

    def test_no_ansi_from_plain_markdown_and_json(self):
        a = Auditor(self.url, limit=9)
        check_exposures(a)
        from wordpress_auditor.reporting import format_markdown
        rows = [r.__dict__ for r in a.results]
        self.assertNotIn("\033[", format_terminal(a, rows))
        self.assertNotIn("\033[", format_markdown(a, rows))
        self.assertNotIn("\033[", json.dumps(rows))
        self.assertIn("HIGH:1", format_terminal(a, rows))

    def test_color_policy_auto_no_color_always(self):
        with patch.dict(os.environ, {"TERM": "xterm-256color"}, clear=True):
            self.assertFalse(supports_color(io.StringIO(), "auto"))
            self.assertTrue(supports_color(io.StringIO(), "always"))
            self.assertFalse(supports_color(io.StringIO(), "never"))
        with patch.dict(os.environ, {"NO_COLOR": "1"}):
            self.assertFalse(supports_color(io.StringIO(), "always"))
        sample = "SEVERITY: HIGH:1 MEDIUM:2 LOW:3 REVIEW:1 INFO:5"
        result = color_summary(sample, True)
        self.assertIn("\033[1;31mHIGH:1", result)
        self.assertIn("\033[1;33mMEDIUM:2", result)
        self.assertIn("\033[1;36mLOW:3", result)
        self.assertEqual(color_summary(sample, False), sample)

    def test_cli_no_color_override_and_clean_json(self):
        with tempfile.TemporaryDirectory() as d:
            source = io.StringIO()
            with contextlib.redirect_stdout(source):
                main(["--url", self.url, "--max-requests", "9", "--delay", "0",
                      "--color", "always", "--no-color", "--wordlist-out",
                      os.path.join(d, "wordlist.txt")])
            self.assertNotIn("\033[", source.getvalue())
            self.assertIn("SEVERITY:", source.getvalue())
            machine = io.StringIO()
            with contextlib.redirect_stdout(machine):
                main(["--url", self.url, "--max-requests", "9", "--delay", "0",
                      "--format", "json", "--color", "always", "--wordlist-out",
                      os.path.join(d, "wordlist.txt")])
            self.assertNotIn("\033[", machine.getvalue())
            data = json.loads(machine.getvalue())
            self.assertTrue(all("severity" in item for item in data))

    def test_xmlrpc_single_get_explains_early_stop(self):
        from wordpress_auditor.reporting import observations
        a = Auditor(self.url, limit=2)
        rows = [{"name": "XML-RPC endpoint", "url": self.url + "/xmlrpc.php",
                 "status": 403, "visibility": "auth-required", "detail": "",
                 "severity": "INFO", "confidence": "observed"}]
        notes, _ = observations(a, rows)
        self.assertTrue(any("further method probes were skipped" in n for n in notes))

    def test_progress_callback_is_finite_and_does_not_echo_query(self):
        a = Auditor(self.url, limit=5)
        sink = io.StringIO()
        p = LivePrinter(color=False, enabled=True, every=2, stream=sink)
        a.request_progress_callback = p.request
        a.request("/wp-config.php.bak?token=TOP_SECRET")
        a.request("/wp-content/debug.log")
        self.assertEqual(sink.getvalue().count("[PROGRESS]"), 1)
        self.assertNotIn("TOP_SECRET", sink.getvalue())


if __name__ == "__main__":
    unittest.main()
