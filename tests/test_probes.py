"""Regression checks for payload importer, endpoint probing, OAST opt-in, and scope."""
import contextlib
import io
import json
import os
import tempfile
import unittest
import zipfile

from wordpress_auditor.auditor import Auditor
from wordpress_auditor.cli import main
from wordpress_auditor.probes import (
    ProbeSuite, get_payloads, safe_candidate, ssrf_oast_probe,
)
from test_cli import Fixture
import test_cli as fixture_module


class TestPayloadProbes(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        fixture_module.TestAuditor.setUpClass()
        cls.url = fixture_module.TestAuditor.url

    @classmethod
    def tearDownClass(cls):
        fixture_module.TestAuditor.tearDownClass()

    def setUp(self):
        Fixture.requests = []
        Fixture.public_marker = ""
        Fixture.private_marker = ""
        Fixture.require_auth = False

    def test_seed_payloads_are_deduplicated_and_scope_limited(self):
        a = Auditor(self.url)
        paths, headers = get_payloads(a)
        self.assertGreater(len(paths), 25)
        self.assertGreater(len(headers), 5)
        self.assertEqual(len(paths), len(set(paths)))
        self.assertIn("/%2e/wp-admin/", paths)
        self.assertFalse(any(p.startswith("//") for p in paths))

    def test_import_previous_zip_and_filter_untrusted_lines(self):
        a = Auditor(self.url)
        with tempfile.TemporaryDirectory() as tmp:
            name = os.path.join(tmp, "intruder.zip")
            with zipfile.ZipFile(name, "w") as z:
                z.writestr("02_urls.txt", (
                    "/wp-admin/%2e/\n"
                    "/wp-admin/%2e/\n"
                    "//evil.invalid/wp-admin\n"
                    "/logout\n"
                    "/?add-to-cart=1\n"
                    "/wp-json/wp/v2/users?per_page=1\n"
                ))
                z.writestr("01_headers.txt", (
                    "X-Original-URL: /wp-admin/\n"
                    "X-HTTP-Method-Override: DELETE\n"
                    "X-Forwarded-For: 127.0.0.1\n"
                    "Cookie: secrets\n"
                ))
            paths, headers = get_payloads(a, name)
            self.assertIn("/wp-admin/%2e/", paths)
            self.assertIn("/wp-json/wp/v2/users?per_page=1", paths)
            self.assertFalse(any(x.startswith("//") or x.startswith("/logout") for x in paths))
            self.assertNotIn("/?add-to-cart=1", paths)
            self.assertNotIn(("X-HTTP-Method-Override", "DELETE"), headers)
            self.assertNotIn(("Cookie", "secrets"), headers)

    def test_raw_dot_segments_are_not_normalized_before_http(self):
        from wordpress_auditor.auditor import safe_url
        self.assertTrue(safe_url(self.url, "/wp-admin/../wp-admin/").endswith(
            "/wp-admin/../wp-admin/"))
        self.assertTrue(safe_url(self.url, "/./wp-admin/").endswith("/./wp-admin/"))

    def test_reject_unsafe_discovery_paths(self):
        a = Auditor(self.url)
        for candidate in ("//evil.invalid/x", "/logout", "/cart/?add-to-cart=1",
                          "/wp-json/?action=delete", "/wp-admin/\nInjected: x"):
            self.assertIsNone(safe_candidate(a, candidate))
        self.assertEqual(safe_candidate(a, "/wp-admin/%2e/"), "/wp-admin/%2e/")

    def test_payload_scan_includes_path_and_header_variants(self):
        a = Auditor(self.url, limit=40)
        suite = ProbeSuite(a)
        tried = suite.access_variants(max_cases=18)
        self.assertGreaterEqual(tried, 12)
        self.assertTrue(any(r.name == "path payload" for r in a.results))
        self.assertTrue(any(r.name.startswith("header payload") for r in a.results))
        self.assertLessEqual(a.request_count, 20)
        self.assertTrue(all(r.visibility != "confirmed-bypass" for r in a.results))
        self.assertTrue(all(req[0] == "GET" for req in Fixture.requests))

    def test_payload_soft404_avoids_false_bypass(self):
        a = Auditor(self.url, limit=18)
        ProbeSuite(a).access_variants(max_cases=10)
        self.assertFalse(any(r.visibility == "confirmed-bypass" for r in a.results))
        self.assertTrue(any("soft-404" in r.detail for r in a.results))

    def test_spoofed_header_probes_do_not_send_session_cookie(self):
        a = Auditor(self.url, limit=40, authorized=True, headers={"Cookie": "secret=TOP"})
        ProbeSuite(a).access_variants(max_cases=18)
        self.assertTrue(any(
            ("x-forwarded-for" in {k.lower() for k in headers}
             or "x-original-url" in {k.lower() for k in headers})
            for _, _, headers, *rest in Fixture.requests))
        self.assertTrue(all(
            "Cookie" not in headers for _, _, headers, *rest in Fixture.requests
        ))

    def test_discovered_urls_get_checked_under_budget(self):
        a = Auditor(self.url, limit=30)
        a.discover()
        self.assertGreaterEqual(a.discovered_checks, 1)
        self.assertTrue(any("discovered URL check" in r.name for r in a.results))
        self.assertLessEqual(a.request_count, 30)

    def test_no_discovered_probing_option(self):
        a = Auditor(self.url, limit=30)
        a.discover(probe_discovered=False)
        self.assertEqual(a.discovered_checks, 0)
        self.assertFalse(any("discovered URL check" in r.name for r in a.results))

    def test_full_scan_uses_payload_variants(self):
        a = Auditor(self.url, limit=130, delay=0)
        a.discover(full=True, payload_limit=25)
        self.assertGreaterEqual(a.payload_cases, 20)
        self.assertTrue(any(x.name == "path payload" for x in a.results))
        self.assertTrue(any(x.name.startswith("header payload") for x in a.results))
        self.assertLessEqual(a.request_count, 130)

    def test_oast_exactly_one_in_scope_injection_only(self):
        a = Auditor(self.url, limit=1, delay=0)
        status = ssrf_oast_probe(
            a, "/wp-admin/admin-ajax.php", "url",
            "https://test-token.oast.invalid/callback", action="thumbnail_preview")
        self.assertEqual(status, 200)
        self.assertEqual(len(Fixture.requests), 1)
        self.assertEqual(a.request_count, 1)
        self.assertIn("test-token.oast.invalid", Fixture.requests[0][1])
        self.assertNotIn("test-token.oast.invalid", str(a.results))
        self.assertEqual(a.results[0].visibility, "requires-oast-correlation")

    def test_oast_requires_explicit_safe_configuration(self):
        a = Auditor(self.url, limit=5)
        for endpoint, param, collab in (
            ("//offsite.invalid/", "url", "https://oast.invalid"),
            ("/logout", "url", "https://oast.invalid"),
            ("/wp-admin/admin-ajax.php", "bad\r\nname", "https://oast.invalid"),
            ("/wp-admin/admin-ajax.php", "url", "http://127.0.0.1/a"),
        ):
            with self.assertRaises(ValueError):
                ssrf_oast_probe(a, endpoint, param, collab)
        self.assertEqual(a.request_count, 0)

    def test_full_negotiates_only_head_and_options(self):
        a = Auditor(self.url, limit=100, delay=0)
        a.discover(full=True, payload_limit=10)
        methods = [r.name for r in a.results if r.name.startswith("HTTP method ")]
        self.assertEqual(len(methods), min(12, max(2, a.limit // 12)))
        self.assertTrue(all(name in ("HTTP method HEAD", "HTTP method OPTIONS")
                            for name in methods))
        self.assertEqual(a.method_checks, len(methods))

    def test_oast_rejects_direct_private_ip_callback(self):
        a = Auditor(self.url)
        with self.assertRaises(ValueError):
            ssrf_oast_probe(a, "/wp-admin/admin-ajax.php", "url",
                            "https://127.0.0.1/callback")
        self.assertEqual(a.request_count, 0)

    def test_cli_ssrf_requires_three_explicit_inputs(self):
        with self.assertRaises(SystemExit):
            with contextlib.redirect_stderr(io.StringIO()):
                main(["--url", self.url, "--ssrf"])

    def test_wordlist_persists_and_rechecks_old_same_origin_urls(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            filename = os.path.join(tmp, "wordlist.txt")
            with open(filename, "w") as f:
                f.write(self.url + "/previously-found\n")
                f.write("https://unrelated.invalid/admin\n")
                f.write(self.url + "/logout\n")
                f.write(self.url + "/?token=hidden\n")
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                main(["--url", self.url, "--max-requests", "30", "--delay", "0",
                      "--wordlist-out", filename])
            with open(filename, encoding="utf-8") as saved:
                content = saved.read()
            self.assertIn("/previously-found", content)
            self.assertNotIn("unrelated.invalid", content)
            self.assertNotIn("/logout", content)
            self.assertNotIn("token=hidden", content)
            self.assertTrue(any("/previously-found" in r[1] for r in Fixture.requests))

    def test_unsupported_head_options_are_informational_in_summary(self):
        from wordpress_auditor.cli import summarize
        a = Auditor(self.url)
        records = [{
            "name": "HTTP method HEAD",
            "url": self.url + "/wp-admin/",
            "status": 501,
            "visibility": "method-not-supported",
            "detail": "method-not-supported",
        }]
        rendered = summarize(a, records)
        self.assertNotIn("Needs review", rendered)
        self.assertIn("501:1", rendered)

    def test_cli_default_summary_counts_payloads(self):
        captured = io.StringIO()
        with contextlib.redirect_stdout(captured):
            main(["--url", self.url, "--max-requests", "40", "--delay", "0"])
        self.assertIn("Payload variants", captured.getvalue())
        self.assertIn("Discovered-URL checks", captured.getvalue())
        self.assertNotIn('"name":', captured.getvalue())

    def test_cli_ssrf_single_request_is_prioritized(self):
        captured = io.StringIO()
        with contextlib.redirect_stdout(captured):
            main([
                "--url", self.url, "--ssrf",
                "--collaborator-url", "https://marker.oast.invalid",
                "--ssrf-path", "/wp-admin/admin-ajax.php",
                "--ssrf-param", "url",
                "--max-requests", "1", "--delay", "0",
            ])
        self.assertEqual(len(Fixture.requests), 1)
        self.assertIn("marker.oast.invalid", Fixture.requests[0][1])


if __name__ == "__main__":
    unittest.main()
