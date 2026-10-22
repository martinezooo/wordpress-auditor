import contextlib
import io
import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlsplit

from wordpress_auditor.auditor import Auditor, parse_burp, parse_xmlrpc_response, safe_url
from wordpress_auditor.cli import main


class Fixture(BaseHTTPRequestHandler):
    requests = []
    public_marker = ""
    private_marker = ""
    require_auth = False

    def reply(self, status, body=b"", headers=None):
        self.send_response(status)
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_):
        pass

    def track(self, method):
        self.__class__.requests.append((method, self.path, dict(self.headers)))

    def do_GET(self):
        self.track("GET")
        path = urlsplit(self.path).path
        if path == "/":
            self.reply(200, b'''<html><script src="/assets/app.js"></script>
              <form action="/wp-admin/admin-ajax.php"><input type="hidden" name="action" value="form_lookup"></form>
              <div data-action="inline_lookup"></div><a href="/local-page?token=omit">page</a></html>''')
        elif path == "/local-page":
            self.reply(200, b'<script>var ajaxurl="/wp-admin/admin-ajax.php"; jQuery.post(ajaxurl,{action:"page_lookup"});</script>')
        elif path == "/assets/app.js":
            self.reply(200, b'const endpoint="/wp-admin/admin-ajax.php"; fetch(endpoint,{action: "asset_lookup"});')
        elif path in ("/wp-json/", "/wp-sitemap.xml", "/sitemap.xml"):
            self.reply(200, b'<url><loc>/from-index?secret=omit</loc></url>')
        elif path == "/wp-admin/admin-ajax.php":
            query = parse_qs(urlsplit(self.path).query)
            if query.get("action") == ["login_lookup"]:
                self.reply(200, b'<form id="loginform">Log in</form>')
            elif query.get("action"):
                self.reply(200, ("handled-" + query["action"][0]).encode())
            else:
                self.reply(200, b"baseline")
        elif path == "/redirect":
            self.reply(302, headers={"Location": "http://evil.invalid/leak"})
        elif path == "/xmlrpc.php":
            self.reply(405)
        elif path == "/wp-admin/":
            if self.headers.get("X-Original-URL"):
                self.reply(200, b'<form id="loginform">Log in</form>')
            else:
                self.reply(403)
        elif path.startswith("/.well-known/wp-auditor-control-"):
            self.reply(404)
        elif path == "/wp-json/wp/v2/comments":
            if self.require_auth and not self.headers.get("Cookie"):
                self.reply(401, b'{"code":"rest_not_authorized"}')
                return
            marker = self.public_marker or (self.private_marker if self.headers.get("Cookie") else "")
            body = json.dumps([{"id": 44, "content": {"rendered": marker}}] if marker else []).encode()
            self.reply(200, body)
        elif path == "/wp-json/wc/store/v1/products/reviews":
            marker = self.public_marker
            self.reply(200, json.dumps([{"review": marker}] if marker else []).encode())
        elif path in ("/comments/feed/", "/"):
            self.reply(200, ("<item><description>" + self.public_marker + "</description></item>").encode())
        else:
            self.reply(200, b"public-page")

    def do_POST(self):
        self.track("POST")
        content = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        self.__class__.requests[-1] += (content,)
        if self.path == "/xmlrpc.php":
            if b"system.listMethods" in content:
                self.reply(200, b"<methodResponse><params><param><value><array><data>"
                    b"<value><string>pingback.ping</string></value>"
                    b"<value><string>system.multicall</string></value>"
                    b"</data></array></value></param></params></methodResponse>")
            elif b"system.getCapabilities" in content:
                self.reply(200, b"<methodResponse><params><param><value><struct><member>"
                    b"<name>xmlrpc</name><value><string>1.0</string></value>"
                    b"</member></struct></value></param></params></methodResponse>")
            elif b"wordpressAuditor.unknownReadOnlyMethod" in content:
                self.reply(200, b"<methodResponse><fault><value><struct><member>"
                    b"<name>faultCode</name><value><int>-32601</int></value>"
                    b"</member></struct></value></fault></methodResponse>")
            else:
                self.reply(400, b"<methodResponse><fault><value><struct><member>"
                    b"<name>faultCode</name><value><int>-32700</int></value>"
                    b"</member></struct></value></fault></methodResponse>")
        elif self.path == "/wp-comments-post.php":
            self.reply(302, headers={"Location": "/post/9/#comment-44"})
        elif self.path == "/wp-json/wp/v2/comments":
            self.reply(201, b'{"id":44,"status":"hold"}')
        else:
            self.reply(404)


class TestAuditor(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = HTTPServer(("127.0.0.1", 0), Fixture)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.url = f"http://127.0.0.1:{cls.server.server_port}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=2)

    def setUp(self):
        Fixture.requests = []
        Fixture.public_marker = ""
        Fixture.private_marker = ""
        Fixture.require_auth = False

    def test_burp_strict_and_filter(self):
        raw = "POST /orders HTTP/1.1\r\nHost: localhost\r\nCookie: a=secret\r\nTransfer-Encoding: chunked\r\nAccept: text/html\r\n\r\nbody"
        url, headers, body = parse_burp(raw)
        self.assertEqual(url, "https://localhost/orders")
        self.assertEqual(headers, {"accept": "text/html", "cookie": "a=secret"})
        self.assertEqual(body, b"")
        for invalid in ["GET / HTTP/1.1\nHost: x\n\n", "GET / HTTP/1.1\r\nHost: x\r\n X: 1\r\n\r\n"]:
            with self.assertRaises(ValueError):
                parse_burp(invalid)

    def test_no_cross_origin_and_encoding_preserved(self):
        a = Auditor(self.url)
        with self.assertRaises(ValueError):
            a.request("https://elsewhere.invalid/")
        self.assertEqual(a.request_count, 0)
        self.assertTrue(safe_url(self.url, "/%2e/wp-admin").endswith("/%2e/wp-admin"))

    def test_allow_legitimate_configured_origin_without_contacting(self):
        a = Auditor("https://example.invalid")
        self.assertEqual(a.request_count, 0)

    def test_redirect_not_followed_and_redaction(self):
        a = Auditor(self.url, headers={"Cookie": "a=secret"}, authorized=True)
        status, _, _ = a.request("/redirect")
        self.assertEqual(status, 302)
        self.assertEqual(len(Fixture.requests), 1)
        a.add("test", "/?token=secret", 200, b"must not leak", "token=secret")
        self.assertNotIn("secret", str(a.results))
        self.assertNotIn("must not leak", str(a.results))

    def test_authorized_headers_retained_and_unsafe_headers_removed(self):
        h = {"Cookie": "a=secret", "Authorization": "Bearer testing",
             "Content-Length": "999", "Host": "evil.invalid",
             "Accept-Encoding": "gzip", "X-Forwarded-For": "10.0.0.1"}
        a = Auditor(self.url, headers=h, authorized=True)
        a.request("/")
        observed = {k.lower(): v for k, v in Fixture.requests[0][2].items()}
        self.assertEqual(observed.get("cookie"), "a=secret")
        self.assertEqual(observed.get("authorization"), "Bearer testing")
        self.assertNotEqual(observed.get("host"), "evil.invalid")
        self.assertNotIn("x-forwarded-for", observed)
        self.assertNotEqual(observed.get("content-length"), "999")

    def test_no_credentials_without_explicit_authorized(self):
        a = Auditor(self.url, headers={"Cookie": "a=secret", "Authorization": "Bearer token"})
        a.request("/")
        observed = {k.lower(): v for k, v in Fixture.requests[0][2].items()}
        self.assertNotIn("cookie", observed)
        self.assertNotIn("authorization", observed)

    def test_comment_search_standalone_all_public_sources(self):
        Fixture.public_marker = "LokalnyZnak123"
        a = Auditor(self.url, limit=12)
        a.search_comment("LokalnyZnak123")
        self.assertTrue(any(x.visibility == "found" and "/wp/v2/comments" in x.url for x in a.results))
        self.assertTrue(any(x.visibility == "found" and "/store/v1/products/reviews" in x.url for x in a.results))
        self.assertFalse(any(r[0] == "POST" and r[1] != "/xmlrpc.php"
                             for r in Fixture.requests))

    def test_xmlrpc_fault_codes(self):
        raw = (b"<methodResponse><fault><value><struct><member>"
               b"<name>faultCode</name><value><int>405</int></value>"
               b"</member></struct></value></fault></methodResponse>")
        self.assertEqual(parse_xmlrpc_response(raw), "XML-RPC fault code 405")

    def test_language_paths_have_bounded_safe_prefixes(self):
        a = Auditor(self.url, limit=10)
        a.search_comment("marker", languages=["en", "fr", "../secret", "xx:evil"])
        observed = [urlsplit(r[1]).path for r in Fixture.requests]
        self.assertIn("/en/", observed)
        self.assertIn("/fr/", observed)
        self.assertNotIn("/secret", observed)

    def test_search_does_not_mistake_reflected_metadata_for_comment(self):
        self.assertFalse(Auditor._comment_record_contains(
            {"message": "search marker reflected"}, "marker"))
        self.assertTrue(Auditor._comment_record_contains(
            [{"content": {"rendered": "<p>marker</p>"}}], "marker"))

    def test_comment_search_401(self):
        Fixture.require_auth = True
        a = Auditor(self.url, limit=8)
        a.search_comment("test")
        self.assertTrue(any(x.visibility == "auth-required" for x in a.results))

    def test_post_private_readback_has_distinct_credentials(self):
        Fixture.private_marker = "private-unique-777"
        a = Auditor(self.url, headers={"Cookie": "logged_in=1"}, authorized=True, limit=4)
        a.comment(9, "private-unique-777", "Security", "test@example.invalid")
        self.assertEqual([r[0] for r in Fixture.requests], ["POST", "GET", "GET"])
        self.assertNotIn("Cookie", Fixture.requests[1][2])
        self.assertIn("Cookie", Fixture.requests[2][2])
        self.assertEqual(a.results[-2].visibility, "not-publicly-observed")
        self.assertEqual(a.results[-1].visibility, "confirmed-authenticated")

    def test_post_public_readback(self):
        Fixture.public_marker = "public-unique-777"
        a = Auditor(self.url, limit=3)
        a.comment(9, "public-unique-777", "Security", "test@example.invalid")
        self.assertEqual(a.results[-1].visibility, "confirmed-public")

    def test_classic_form_writes_only_once(self):
        a = Auditor(self.url, limit=4)
        a.comment(9, "form-unique-222", "Audit", "test@example.invalid", mode="form")
        posts = [r for r in Fixture.requests if r[0] == "POST"]
        self.assertEqual(len(posts), 1)
        self.assertEqual(posts[0][1], "/wp-comments-post.php")
        body = parse_qs(posts[0][3].decode())
        self.assertEqual(body["comment_post_ID"], ["9"])
        self.assertEqual(body["comment"], ["form-unique-222"])

    def test_xmlrpc_get_405_post_list(self):
        a = Auditor(self.url, limit=6)
        a.xmlrpc()
        self.assertEqual([r[0] for r in Fixture.requests], ["GET", "POST", "POST", "POST", "POST"])
        self.assertTrue(any("pingback.ping" in r.detail for r in a.results))
        self.assertTrue(any("system.multicall" in r.detail for r in a.results))
        self.assertTrue(any("fault code -32601" in r.detail for r in a.results))
        self.assertTrue(any("fault code -32700" in r.detail for r in a.results))
        self.assertEqual(parse_xmlrpc_response(b"<!DOCTYPE x><x/>"), "rejected unsafe XML")

    def test_comparison_login_page_is_not_bypass(self):
        a = Auditor(self.url, limit=4)
        result = a.compare_403("/wp-admin/")
        self.assertEqual(result["classification"], "inconclusive")

    def test_explicit_xmlrpc_first_under_small_request_budget(self):
        a = Auditor(self.url, limit=2)
        a.discover(xmlrpc=True)
        self.assertEqual([r[1] for r in Fixture.requests], ["/xmlrpc.php", "/xmlrpc.php"])

    def test_explicit_comment_search_first_under_small_request_budget(self):
        a = Auditor(self.url, limit=1)
        a.discover(search_comment="user-marker")
        self.assertEqual(len(Fixture.requests), 1)
        self.assertIn("search=user-marker", Fixture.requests[0][1])

    def test_budget_and_cli_no_automatic_writes(self):
        a = Auditor(self.url, limit=2)
        a.search_comment("marker")
        self.assertEqual(a.request_count, 2)
        self.assertEqual(len(Fixture.requests), 2)
        Fixture.requests.clear()
        with contextlib.redirect_stdout(io.StringIO()):
            main(["--url", self.url, "--max-requests", "2"])
        self.assertFalse(any(r[0] == "POST" and r[1] != "/xmlrpc.php"
                             for r in Fixture.requests))

    def test_summary_is_default_and_no_json_dump(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            main(["--url", self.url, "--max-requests", "3"])
        value = out.getvalue()
        self.assertIn("Requests 3/3", value)
        self.assertIn("AJAX actions", value)
        self.assertNotIn('"name":', value)
        self.assertIn("WHAT THE ENGINE ACTUALLY DID", value)
        self.assertIn("COVERAGE & LIMITATIONS", value)

    def test_explicit_json_details(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            main(["--url", self.url, "--max-requests", "2", "--format", "json"])
        rows = json.loads(out.getvalue())
        self.assertTrue(rows)
        self.assertIn("visibility", rows[0])

    def test_report_json_saved_but_terminal_is_summary(self):
        import tempfile
        import os
        with tempfile.TemporaryDirectory() as tmp:
            output = os.path.join(tmp, "nested", "report.json")
            terminal = io.StringIO()
            with contextlib.redirect_stdout(terminal):
                main(["--url", self.url, "--max-requests", "3", "--output", output])
            self.assertIn("Saved full report", terminal.getvalue())
            self.assertNotIn('"name":', terminal.getvalue())
            with open(output, encoding="utf-8") as f:
                rows = json.load(f)
            self.assertIsInstance(rows, list)
            self.assertTrue(os.path.isfile(os.path.join(tmp, "nested", "wordlist.txt")))

    def test_full_scans_more_surface_and_read_only_xmlrpc(self):
        a = Auditor(self.url, limit=180)
        a.discover(full=True)
        observed = [urlsplit(row[1]).path for row in Fixture.requests]
        for endpoint in ("/wp-json/wp/v2/users", "/wp-json/oembed/1.0/",
                         "/robots.txt", "/wp-sitemap.xml", "/wp-login.php",
                         "/wp-json/wc/store/v1/products"):
            self.assertIn(endpoint, observed)
        posts = [row for row in Fixture.requests if row[0] == "POST"]
        self.assertTrue(posts)
        self.assertTrue(all(row[1] == "/xmlrpc.php" for row in posts))
        self.assertLessEqual(a.request_count, a.limit)
        self.assertGreater(len(a.results), 15)

    def test_xmlrpc_budget_does_not_overrun(self):
        a = Auditor(self.url, limit=2)
        a.xmlrpc()
        self.assertEqual(a.request_count, 2)
        self.assertEqual(len(Fixture.requests), 2)

    def test_xmlrpc_404_does_not_post(self):
        a = Auditor(self.url, limit=4)
        a.request = lambda path, method="GET", data=None, headers=None, **kwargs: (404, b"", {})
        a.xmlrpc()
        self.assertEqual(len(a.results), 1)
        self.assertNotEqual(a.results[0].status, 200)

    def test_summary_scrubs_query_tokens(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            main(["--url", self.url + "/?token=very-secret", "--max-requests", "1"])
        self.assertNotIn("very-secret", out.getvalue())
        self.assertNotIn("token=", out.getvalue())

    def test_full_keeps_ajax_discovery_and_budget(self):
        a = Auditor(self.url, limit=60)
        a.discover(full=True)
        self.assertIn("form_lookup", a.ajax_actions)
        self.assertLessEqual(a.request_count, a.limit)
        self.assertTrue(any(r.name.startswith("XML-RPC") for r in a.results))

    def test_csv_and_markdown_explicit_formats(self):
        for fmt, expected in (("csv", "name,url,status"), ("md", "| Name | URL |")):
            captured = io.StringIO()
            with contextlib.redirect_stdout(captured):
                main(["--url", self.url, "--max-requests", "2", "--format", fmt])
            self.assertIn(expected, captured.getvalue())

    def test_invalid_budget_rejected(self):
        for value in ("0", "-1"):
            with self.assertRaises(SystemExit):
                with contextlib.redirect_stderr(io.StringIO()):
                    main(["--url", self.url, "--max-requests", value])

    def test_cli_write_requires_post_id(self):
        with self.assertRaises(SystemExit) as cm:
            with contextlib.redirect_stderr(io.StringIO()):
                main(["--url", self.url, "--post-comment"])
        self.assertEqual(cm.exception.code, 2)

    def test_ajax_extraction_and_persistent_wordlists(self):
        a = Auditor(self.url, limit=12)
        a.discover_ajax()
        self.assertTrue({"form_lookup", "inline_lookup", "page_lookup", "asset_lookup"} <= a.ajax_actions)
        self.assertIn(self.url + "/from-index", a.wordlist)
        self.assertNotIn("secret=omit", "\n".join(a.wordlist))
        self.assertFalse(any("admin-ajax.php?action=" in r.url for r in a.results))

    def test_ajax_probe_is_opt_in_and_classifies_login(self):
        a = Auditor(self.url, limit=12)
        a.discover_ajax(probe=True)
        ajax_requests = [r[1] for r in Fixture.requests if "admin-ajax.php?action=" in r[1]]
        self.assertTrue(ajax_requests)
        self.assertTrue(all(r[0] == "GET" for r in Fixture.requests))
        self.assertTrue(any("requires-review" in x.detail for x in a.results))

    def test_ajax_extraction_rejects_unrelated_action(self):
        self.assertEqual(Auditor.extract_ajax_actions('<form action="login"></form>'), set())


if __name__ == "__main__":
    unittest.main()
