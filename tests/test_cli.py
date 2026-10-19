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
        if path == "/redirect":
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
            self.reply(200, b"<methodResponse><params><param><value><array><data>"
                b"<value><string>pingback.ping</string></value>"
                b"<value><string>system.multicall</string></value>"
                b"</data></array></value></param></params></methodResponse>")
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
        self.assertFalse(any(r[0] == "POST" for r in Fixture.requests))

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
        a = Auditor(self.url, limit=4)
        a.xmlrpc()
        self.assertEqual([r[0] for r in Fixture.requests], ["GET", "POST"])
        self.assertIn("pingback.ping", a.results[-1].detail)
        self.assertIn("system.multicall", a.results[-1].detail)
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
        self.assertFalse(any(r[0] == "POST" for r in Fixture.requests))

    def test_cli_write_requires_post_id(self):
        with self.assertRaises(SystemExit) as cm:
            with contextlib.redirect_stderr(io.StringIO()):
                main(["--url", self.url, "--post-comment"])
        self.assertEqual(cm.exception.code, 2)


if __name__ == "__main__":
    unittest.main()
