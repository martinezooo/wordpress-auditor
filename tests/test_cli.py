import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer

from wordpress_auditor.auditor import Auditor, parse_burp


class H(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/redirect":
            self.send_response(302); self.send_header("Location", "http://evil.invalid/leak"); self.end_headers()
        elif self.path == "/xmlrpc.php":
            self.send_response(405); self.end_headers()
        elif self.path.startswith("/wp-json/wp/v2/comments"):
            self.send_response(200); self.end_headers(); self.wfile.write(b"[]")
        else:
            self.send_response(200); self.end_headers(); self.wfile.write(b"public marker")

    def do_POST(self):
        if self.path == "/xmlrpc.php":
            self.send_response(200); self.end_headers()
            self.wfile.write(b"<methodResponse><array><data/></array></methodResponse>")
        elif self.path.startswith("/wp-json/wp/v2/comments"):
            self.send_response(201); self.end_headers(); self.wfile.write(b'{"id": 4}')
        else:
            self.send_response(200); self.end_headers()

    def log_message(self, *args):
        pass


class Test(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.s = HTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=cls.s.serve_forever, daemon=True).start()
        cls.url = f"http://127.0.0.1:{cls.s.server_port}"

    @classmethod
    def tearDownClass(cls):
        cls.s.shutdown()

    def test_burp_is_strict_and_https_by_default(self):
        u, h, b = parse_burp("GET / HTTP/1.1\r\nHost: 127.0.0.1:80\r\n\r\n")
        self.assertTrue(u.startswith("https://"))
        with self.assertRaises(ValueError):
            parse_burp("GET / HTTP/1.1\nHost: x\n\n")
        with self.assertRaises(ValueError):
            parse_burp("GET / HTTP/1.1\r\nHost: x\r\n X: folded\r\n\r\n")

    def test_redirect_not_followed_and_report_redacted(self):
        a = Auditor(self.url, headers={"Cookie": "private=secret"}, authorized=True, limit=2)
        status, _, _ = a.request("/redirect")
        self.assertEqual(status, 302)
        a.add("private", "/?token=secret", 200, b"body must not be echoed", "token=secret")
        self.assertNotIn("body must", a.results[-1].detail)
        self.assertNotIn("secret", a.results[-1].detail)
        self.assertNotIn("token=secret", a.results[-1].url)

    def test_xmlrpc_get_405_then_post(self):
        a = Auditor(self.url, limit=4)
        a.xmlrpc()
        self.assertTrue(any("system.listMethods" in r.name for r in a.results))

    def test_comment_accepted_but_not_visible_and_budget(self):
        a = Auditor(self.url, limit=2)
        a.comment(9, "unique-marker", "Auditor", "a@example.invalid", False)
        self.assertEqual(a.request_count, 2)
        self.assertEqual(a.results[-1].visibility, "moderated")
        b = Auditor(self.url, limit=1)
        b.discover(xmlrpc=True)
        self.assertLessEqual(b.request_count, 1)

    def test_public_and_authenticated_classification(self):
        self.assertEqual(Auditor(self.url).add("x", "/", 200), None)
        self.assertEqual(Auditor(self.url, authorized=True).authorized, True)


if __name__ == "__main__":
    unittest.main()
