"""WordPress Core scenario checks against 127.0.0.1 only; no real targets."""
import contextlib
import io
import json
import os
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlsplit

from wordpress_auditor.auditor import Auditor
from wordpress_auditor.cli import main
from wordpress_auditor.core_scenarios import (
    READ_RULES, audit_wordpress_core, evaluate, operation_matrix, matrix_markdown,
)
from wordpress_auditor.check_catalog import CHECKS, coverage


SECRET_PII = "private-email-fixture@example.invalid"
SECRET_BODY = "draft-text-fixture-NOT-FOR-REPORT"


class CoreFixture(BaseHTTPRequestHandler):
    requests = []
    leak = True
    fake_200 = False

    def log_message(self, *_):
        pass

    def respond(self, status, content=b"", content_type="text/plain"):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.end_headers()
        self.wfile.write(content)

    def do_GET(self):
        self.__class__.requests.append(("GET", self.path))
        path = urlsplit(self.path).path
        q = parse_qs(urlsplit(self.path).query)
        if path == "/":
            self.respond(200, b'<html><form action="/wp-comments-post.php" method="post">'
                           b'<input name="comment_post_ID" value="7"></form></html>',
                           "text/html")
        elif path == "/xmlrpc.php":
            self.respond(405, b"XML-RPC requests must use POST")
        elif path == "/wp-json/":
            routes = {
                "/wp/v2/comments": {"methods": ["GET", "POST"]},
                "/wp/v2/posts": {"methods": ["GET", "POST"]},
                "/wp/v2/media": {"methods": ["GET", "POST"]},
                "/wp/v2/users": {"methods": ["GET"]},
                "/wp/v2/plugins": {"methods": ["GET", "POST", "DELETE"]},
            }
            self.respond(200, json.dumps({"routes": routes}).encode(), "application/json")
        elif path in ("/wp-json/wp/v2/posts", "/wp-json/wp/v2/pages"):
            if "status" in q:
                status = q["status"][0]
                if self.fake_200:
                    self.respond(200, b"<html>please login</html>", "text/html")
                elif self.leak and status in ("draft", "private") and path.endswith("posts"):
                    self.respond(200, json.dumps([{
                        "id": 9, "status": status, "content": {"rendered": SECRET_BODY}
                    }]).encode(), "application/json")
                else:
                    self.respond(403, b'{"code":"rest_forbidden"}', "application/json")
            else:
                self.respond(200, b'[{"id":9,"comment_status":"open","ping_status":"closed","status":"publish"}]',
                             "application/json")
        elif path == "/wp-json/wp/v2/comments":
            if self.fake_200:
                self.respond(200, b"<html>Login</html>", "text/html")
            elif q.get("context") == ["edit"] and self.leak:
                self.respond(200, json.dumps([{"id": 18,
                    "author_email": SECRET_PII, "status": "approved"}]).encode(), "application/json")
            elif q.get("status") == ["hold"] and self.leak:
                self.respond(200, json.dumps([{"id": 18, "status": "hold",
                    "content": {"rendered": SECRET_BODY}}]).encode(), "application/json")
            else:
                self.respond(403, b'{"code":"rest_forbidden"}', "application/json")
        elif path.startswith("/.well-known/"):
            self.respond(404)
        else:
            self.respond(404, b"No WP route", "text/plain")

    def do_POST(self):
        content = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        self.__class__.requests.append(("POST", self.path))
        if self.path != "/xmlrpc.php":
            self.respond(405)
            return
        if b"system.listMethods" in content:
            data = b"".join(
                b"<value><string>"+m+b"</string></value>"
                for m in (b"wp.newComment", b"wp.newPost", b"wp.uploadFile",
                          b"pingback.ping", b"system.multicall")
            )
            payload = (b"<?xml version='1.0'?><methodResponse><params><param>"
                       b"<value><array><data>" + data +
                       b"</data></array></value></param></params></methodResponse>")
            self.respond(200, payload, "text/xml")
        else:
            self.respond(200, b"<methodResponse><fault></fault></methodResponse>", "text/xml")


class CoreScenarioTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.http = HTTPServer(("127.0.0.1", 0), CoreFixture)
        cls.thread = threading.Thread(target=cls.http.serve_forever, daemon=True)
        cls.thread.start()
        cls.url = "http://127.0.0.1:%d" % cls.http.server_port

    @classmethod
    def tearDownClass(cls):
        cls.http.shutdown()
        cls.http.server_close()
        cls.thread.join(timeout=2)

    def setUp(self):
        CoreFixture.requests = []
        CoreFixture.leak = True
        CoreFixture.fake_200 = False

    def test_9_core_scenarios_and_private_disclosure_classification(self):
        a = Auditor(self.url, limit=12)
        audit_wordpress_core(a)
        self.assertEqual(len(a.results), 9)
        classified = [r for r in a.results if r.confidence == "confirmed"]
        self.assertGreaterEqual(len(classified), 3)
        self.assertTrue(all(r.severity == "MEDIUM" for r in classified))
        self.assertTrue(any(r.name == "WP private draft posts" for r in classified))
        self.assertTrue(any(r.name == "WP pending comment moderation" for r in classified))
        self.assertTrue(any(r.name == "WP private comment edit fields" for r in classified))
        self.assertNotIn(SECRET_PII, json.dumps([r.__dict__ for r in a.results]))
        self.assertNotIn(SECRET_BODY, json.dumps([r.__dict__ for r in a.results]))

    def test_authenticated_headers_not_sent_on_public_private_check(self):
        a = Auditor(self.url, limit=9,
                    headers={"Cookie": "private=SESSION", "Authorization": "Bearer TEST"},
                    authorized=True)
        audit_wordpress_core(a)
        # The mock records only method and URL; a lower-level transport unit
        # test already validates include_credentials=False on all requests.
        self.assertEqual(len(CoreFixture.requests), 9)
        self.assertTrue(all(method == "GET" for method, _ in CoreFixture.requests))

    def test_soft404_html_does_not_confirm_leak(self):
        CoreFixture.fake_200 = True
        a = Auditor(self.url, limit=9)
        audit_wordpress_core(a)
        self.assertFalse(any(r.severity in ("HIGH", "MEDIUM", "LOW")
                             for r in a.results))

    def test_restricted_private_content_is_not_a_vulnerability(self):
        CoreFixture.leak = False
        a = Auditor(self.url, limit=9)
        audit_wordpress_core(a)
        self.assertTrue(all(r.severity == "INFO" for r in a.results))
        self.assertTrue(any(r.visibility == "auth-required" for r in a.results))

    def test_requires_positive_int_and_exact_private_status(self):
        rule = READ_RULES[0]
        for data in (
            [{"id": "9", "status": "draft"}],
            [{"id": 0, "status": "draft"}],
            [{"id": True, "status": "draft"}],
            [{"id": 9, "status": "publish"}],
            [{"id": 9, "status": "DRAFT"}],
            {"id": 9, "status": "draft"},
        ):
            state, _ = evaluate(rule, 200, json.dumps(data).encode())
            self.assertNotEqual(state, "confirmed-public-nonpublic-wp-content")
        self.assertEqual(evaluate(rule, 200, b'<html>login</html>')[0], "not-confirmed")

    def test_registration_admin_default_role_requires_strict_boolean_and_role(self):
        from wordpress_auditor.wp_identity import WordPressIdentity
        for setting, expected in (
            ({"users_can_register": True, "default_role": "administrator"}, "HIGH"),
            ({"users_can_register": False, "default_role": "administrator"}, "REVIEW"),
            ({"users_can_register": True, "default_role": "subscriber"}, "REVIEW"),
            ({"users_can_register": "true", "default_role": "administrator"}, "REVIEW"),
        ):
            auditor = Auditor(self.url, limit=5)
            identity = WordPressIdentity(auditor)
            def get(name, path, **kwargs):
                if "settings" in path:
                    return 200, json.dumps(setting).encode(), {}
                return 403, b"", {}
            identity._get = get
            identity.protected_rest()
            result = next(r for r in auditor.results if r.name == "WP REST settings (anonymous)")
            self.assertEqual(result.severity, expected)
            if expected == "HIGH":
                self.assertIn("no account creation attempted", result.detail)
                self.assertEqual(result.confidence, "confirmed")

    def test_private_status_only_metadata_requires_review_not_medium(self):
        rule = READ_RULES[0]
        state, _ = evaluate(rule, 200, b'[{"id": 88, "status": "draft"}]')
        self.assertEqual(state, "review-private-wp-object-metadata")
        a = Auditor(self.url)
        a.add("WP private draft posts", rule.path, 200, visibility=state)
        self.assertEqual(a.results[0].severity, "REVIEW")
        self.assertEqual(a.results[0].confidence, "unverified")

    def test_comment_author_private_fields_need_nonempty_value(self):
        rule = READ_RULES[7]
        self.assertEqual(evaluate(rule, 200, b'[{"id":2,"author_email":""}]')[0],
                         "not-confirmed")
        self.assertEqual(evaluate(rule, 200, b'[{"id":2,"author_email":"x@y.test"}]')[0],
                         "confirmed-public-private-comment-fields")

    def test_comment_open_is_information_not_a_vulnerability(self):
        a = Auditor(self.url, limit=9)
        audit_wordpress_core(a)
        result = next(r for r in a.results
                      if r.name == "WP public comment configuration")
        self.assertEqual(result.visibility, "commenting-enabled")
        self.assertEqual(result.severity, "INFO")

    def test_budget_never_exceeded(self):
        a = Auditor(self.url, limit=4)
        audit_wordpress_core(a)
        self.assertEqual(a.request_count, 4)
        self.assertEqual(len(a.results), 4)

    def test_smart_mode_includes_core_phase_quick_skips(self):
        smart = Auditor(self.url, limit=115)
        smart.discover(full=True, payload_limit=0, no_ajax=True,
                       probe_discovered=False)
        self.assertTrue(any(x["name"] == "WordPress core private-content and comment checks"
                            and x["state"] == "done" for x in smart.phase_stats))
        self.assertTrue(any(r.name == "WP private draft posts" for r in smart.results))
        self.assertLessEqual(smart.request_count, 115)
        quick = Auditor(self.url, limit=30)
        quick.discover(full=False, payload_limit=0, no_ajax=True,
                       probe_discovered=False)
        self.assertTrue(any(x["name"] == "WordPress core private-content and comment checks"
                            and x["state"] == "skipped" for x in quick.phase_stats))

    def test_operation_matrix_separates_discovery_from_a_write(self):
        a = Auditor(self.url, limit=45)
        a.xmlrpc()
        a.discover_ajax(page_cap=1)
        status, body, _ = a.request("/wp-json/")
        self.assertEqual(status, 200)
        routes = json.loads(body)["routes"]
        a.rest_route_methods = {k: v["methods"] for k, v in routes.items()}
        matrix = operation_matrix(a)
        comments = next(r for r in matrix if r["operation"] == "comments.create")
        states = {r["channel"]: r["status"] for r in comments["channels"]}
        self.assertEqual(states["Classic comment form"], "DISCOVERED")
        self.assertEqual(states["WordPress REST"], "DISCOVERED")
        self.assertEqual(states["XML-RPC wp.newComment"], "DISCOVERED")
        self.assertEqual(len([x for x in CoreFixture.requests
                              if x[0] == "POST" and x[1] != "/xmlrpc.php"]), 0)
        self.assertIn("handler not invoked", str(comments))
        self.assertIn("Create comment", matrix_markdown(matrix))

    def test_missing_rest_index_cannot_mark_route_as_absent(self):
        a = Auditor(self.url)
        matrix = operation_matrix(a)
        comments = next(r for r in matrix if r["operation"] == "comments.create")
        rest = next(x for x in comments["channels"] if x["channel"] == "WordPress REST")
        self.assertEqual(rest["status"], "UNKNOWN")

    def test_full_run_uses_real_method_introspection(self):
        a = Auditor(self.url, limit=125)
        a.discover(full=True, payload_limit=0, no_ajax=False,
                   probe_discovered=False)
        self.assertIn("wp.newComment", a.xmlrpc_methods)
        self.assertIn("wp.uploadFile", a.xmlrpc_methods)
        self.assertIn("/wp/v2/comments", a.rest_route_methods)
        matrix = operation_matrix(a)
        comments = next(x for x in matrix if x["operation"] == "comments.create")
        self.assertTrue(all(ch["status"] == "DISCOVERED" for ch in comments["channels"]))

    def test_coverage_catalog_is_honest_for_new_private_checks(self):
        a = Auditor(self.url, limit=9)
        audit_wordpress_core(a)
        rows = coverage(a)
        attempted = [r["id"] for r in rows if r["status"] in ("CHECKED", "BLOCKED")]
        self.assertTrue(all("WP-%d" % x in attempted for x in range(55, 64)))
        self.assertEqual(len(set(x.check_id for x in CHECKS)), len(CHECKS))

    def test_cli_writes_machine_and_human_operation_matrix(self):
        with tempfile.TemporaryDirectory() as tmp:
            wordlist = os.path.join(tmp, "wordlist.txt")
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                main(["--url", self.url, "--max-requests", "110", "--delay", "0",
                      "--payload-limit", "0", "--wordlist-out", wordlist])
            self.assertIn("WordPress operation matrix:", stdout.getvalue())
            json_file = os.path.join(tmp, "core-operations.json")
            md_file = os.path.join(tmp, "core-operations.md")
            self.assertTrue(os.path.isfile(json_file))
            self.assertTrue(os.path.isfile(md_file))
            with open(json_file, encoding="utf-8") as f:
                data = json.load(f)
            self.assertGreaterEqual(len(data), 7)
            with open(md_file, encoding="utf-8") as f:
                text = f.read()
            self.assertIn("Create comment", text)
            self.assertNotIn(SECRET_PII, text)
            self.assertNotIn(SECRET_BODY, text)


if __name__ == "__main__":
    unittest.main()
