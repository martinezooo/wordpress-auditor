"""Local-only integration verification of adaptive discovery and readable reporting."""
import contextlib
import io
import json
import os
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer

from wordpress_auditor.auditor import Auditor
from wordpress_auditor.cli import main
from wordpress_auditor.reporting import format_terminal, format_markdown


class LargeSite(BaseHTTPRequestHandler):
    calls = []
    def log_message(self, *a):
        pass

    def respond(self, status, body=b"", mime="text/plain"):
        self.send_response(status)
        self.send_header("Content-Type", mime)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        self.__class__.calls.append(("GET", self.path))
        if self.path == "/":
            links = "".join('<a href="/content/%03d">Article</a>' % i
                            for i in range(85))
            links += '<script src="/wp-content/plugins/fixture-plugin/app.js"></script>'
            links += '<link href="/wp-content/themes/fixture-theme/style.css" rel="stylesheet">'
            self.respond(200, links.encode(), "text/html")
        elif self.path == "/wp-json/":
            routes = {
                "/wp/v2/test-%03d" % i:
                    {"methods": ["GET"], "endpoints": [{"methods": ["GET"]}]}
                for i in range(25)
            }
            routes["/wc/store/v1/cart"] = {"methods": ["GET"]}
            routes["/wp/v2/posts/(?P<id>[\\d]+)"] = {"methods": ["GET"]}
            routes["/wp/v2/administration"] = {"methods": ["POST"]}
            self.respond(200, json.dumps({"routes": routes}).encode(),
                         "application/json")
        elif self.path == "/xmlrpc.php":
            self.respond(405)
        elif self.path == "/wp-admin/":
            self.respond(403, b"Forbidden")
        elif self.path.startswith("/content/") or "/test-" in self.path:
            self.respond(200, b"<h1>Article</h1>")
        else:
            self.respond(404, b"Not found")

    def do_POST(self):
        self.__class__.calls.append(("POST", self.path))
        if self.path == "/xmlrpc.php":
            self.respond(200, (b"<methodResponse><fault><value><struct><member>"
                               b"<name>faultCode</name><value><int>-32601</int></value>"
                               b"</member></struct></value></fault></methodResponse>"))
        else:
            self.respond(405)


class ExplainScanTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.http = HTTPServer(("127.0.0.1", 0), LargeSite)
        cls.thread = threading.Thread(target=cls.http.serve_forever, daemon=True)
        cls.thread.start()
        cls.url = "http://127.0.0.1:%s" % cls.http.server_port

    @classmethod
    def tearDownClass(cls):
        cls.http.shutdown()
        cls.http.server_close()
        cls.thread.join(timeout=2)

    def setUp(self):
        LargeSite.calls = []

    def test_85_plus_discoveries_are_not_limited_to_8_checks(self):
        a = Auditor(self.url, limit=180, delay=0)
        a.discover(full=True, payload_limit=35)
        self.assertGreaterEqual(len(a.wordlist), 85)
        self.assertGreater(a.discovered_checks, 8)
        self.assertGreater(len(a.wordlist & a.requested_urls), 8)
        self.assertLessEqual(a.request_count, 180)
        self.assertTrue(any(phase["name"].startswith("New and previously")
                            for phase in a.phase_stats))

    def test_rest_discovery_does_not_probe_stateful_or_variable_routes(self):
        a = Auditor(self.url, limit=150)
        a.discover(full=True, payload_limit=16)
        routes = "\n".join(a.wordlist)
        self.assertIn("/wp-json/wp/v2/test-001", routes)
        self.assertNotIn("/wc/store/v1/cart", routes)
        self.assertNotIn("(?P", routes)
        self.assertNotIn("/administration", routes)

    def test_plugin_theme_assets_discovered_without_version_checks(self):
        a = Auditor(self.url, limit=85, delay=0)
        a.discover(full=True, payload_limit=2)
        self.assertIn("fixture-plugin", a.plugin_slugs)
        self.assertIn("fixture-theme", a.theme_slugs)
        names = [r.name for r in a.results]
        self.assertIn("WP plugin asset discovery", names)
        self.assertIn("WP theme asset discovery", names)
        self.assertFalse(any("CVE" in r.detail for r in a.results))

    def test_console_is_explanatory_and_evidence_scoped(self):
        a = Auditor(self.url, limit=70)
        a.discover(full=True, payload_limit=8)
        rows = [r.__dict__ for r in a.results]
        summary = format_terminal(a, rows)
        for fragment in (
            "WHAT THE ENGINE ACTUALLY DID", "OBSERVATIONS",
            "COVERAGE & LIMITATIONS", "Discovered URLs",
            "XML-RPC protocol diagnostics", "No vulnerability",
        ):
            self.assertIn(fragment, summary)
        self.assertNotIn('"name":', summary)
        self.assertIn("Methodology", format_markdown(a, rows))
        self.assertIn("403 examples:", summary)
        self.assertIn("RECORDED CHECK RESPONSES", summary)
        self.assertNotIn("confirmed-bypass", summary)

    def test_quick_remains_opt_in_and_refrains_from_xmlrpc_calls(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                main(["--url", self.url, "--quick", "--max-requests", "12",
                      "--delay", "0", "--wordlist-out",
                      os.path.join(tmp, "wordlist.txt")])
            self.assertIn("QUICK SCAN", out.getvalue())
            self.assertFalse(any(method == "POST" for method, path in LargeSite.calls))

    def test_default_cli_uses_smart_report_and_writes_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                main(["--url", self.url, "--max-requests", "65",
                      "--delay", "0", "--wordlist-out",
                      os.path.join(tmp, "wordlist.txt")])
            self.assertIn("SMART SCAN", out.getvalue())
            self.assertIn("Detailed JSON:", out.getvalue())
            self.assertTrue(os.path.isfile(os.path.join(tmp, "scan-summary.md")))
            report_path = os.path.join(tmp, "latest-report.json")
            with open(report_path) as f:
                data = json.load(f)
            self.assertTrue(isinstance(data, list))
            self.assertTrue(any(r["name"].startswith("XML-RPC") for r in data))

    def test_progress_reports_real_phase_counts_to_stderr(self):
        with tempfile.TemporaryDirectory() as tmp:
            out, err = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                main(["--url", self.url, "--progress", "--max-requests", "55",
                      "--delay", "0", "--wordlist-out",
                      os.path.join(tmp, "wordlist.txt")])
            self.assertIn("XML-RPC protocol diagnostics", err.getvalue())
            self.assertIn("budget", err.getvalue())
            self.assertIn("WHAT THE ENGINE ACTUALLY DID", out.getvalue())


if __name__ == "__main__":
    unittest.main()
