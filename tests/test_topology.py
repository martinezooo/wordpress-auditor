"""Realistic mounted-WordPress topology discovery regressions."""
from __future__ import annotations

import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlsplit

from wordpress_auditor.auditor import Auditor
from wordpress_auditor.topology import discover_topology


class MountedWordPress(BaseHTTPRequestHandler):
    requests = []

    def log_message(self, *args):
        pass

    def reply(self, status, body=b"", headers=None):
        self.send_response(status)
        for name, value in (headers or {}).items():
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        type(self).requests.append(self.path)
        parsed = urlsplit(self.path)
        path, query = parsed.path, parse_qs(parsed.query)
        origin = f"http://127.0.0.1:{self.server.server_port}"
        if path == "/blog/":
            body = (f"""<html><head><link rel="https://api.w.org/"
                href="{origin}/blog/wp-json/"></head><body>
                <a href="/blog/menu-post/">menu</a>
                <script src="/blog/app.js"></script>
                <script>window.hidden = "/blog/js-only-post/";
                window.rule = "/wp-admin/*";</script>
                </body></html>""").encode()
            self.reply(200, body, {"Link":
                f'<{origin}/blog/wp-json/>; rel="https://api.w.org/"'})
        elif path == "/blog/app.js":
            self.reply(200, b'const route = "/blog/bundle-only/";')
        elif path == "/blog/robots.txt":
            self.reply(200, f"Sitemap: {origin}/blog/custom-index.xml\n".encode())
        elif path in ("/blog/wp-sitemap.xml", "/blog/custom-index.xml"):
            self.reply(200, (f"""<?xml version="1.0"?>
                <sitemapindex xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
                <sitemap><loc>{origin}/blog/wp-sitemap-posts-post-1.xml</loc></sitemap>
                </sitemapindex>""").encode())
        elif path == "/blog/wp-sitemap-posts-post-1.xml":
            self.reply(200, (f"""<?xml version="1.0"?>
                <urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
                <url><loc>{origin}/blog/sitemap-only-post/</loc></url>
                </urlset>""").encode())
        elif path in ("/blog/sitemap.xml", "/blog/sitemap_index.xml"):
            self.reply(404)
        elif path == "/blog/wp-json/wp/v2/types":
            self.reply(200, json.dumps({
                "post": {"rest_base": "posts", "rest_namespace": "wp/v2",
                         "viewable": True},
                "page": {"rest_base": "pages", "rest_namespace": "wp/v2",
                         "viewable": True},
                "book": {"rest_base": "books", "rest_namespace": "wp/v2",
                         "viewable": True},
            }).encode())
        elif path == "/blog/wp-json/wp/v2/posts":
            page = int(query.get("page", ["1"])[0])
            self.reply(200, json.dumps([
                {"id": page, "link": f"{origin}/blog/rest-post-{page}/"}
            ]).encode(), {"X-WP-TotalPages": "2"})
        elif path == "/blog/wp-json/wp/v2/pages":
            self.reply(200, json.dumps([
                {"id": 3, "link": f"{origin}/blog/unlinked-page/"}
            ]).encode(), {"X-WP-TotalPages": "1"})
        elif path == "/blog/wp-json/wp/v2/books":
            self.reply(200, json.dumps([
                {"id": 4, "link": f"{origin}/blog/hidden-book/"}
            ]).encode(), {"X-WP-TotalPages": "1"})
        else:
            self.reply(404)


class TopologyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = HTTPServer(("127.0.0.1", 0), MountedWordPress)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.origin = f"http://127.0.0.1:{cls.server.server_port}"
        cls.url = cls.origin + "/blog/"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=2)

    def setUp(self):
        MountedWordPress.requests = []

    def test_internal_probes_resolve_under_wordpress_mount(self):
        auditor = Auditor(self.url, limit=3)
        self.assertEqual(auditor.resolve_url("/wp-json/"),
                         self.origin + "/blog/wp-json/")
        self.assertEqual(auditor.resolve_url("/blog/wp-json/"),
                         self.origin + "/blog/wp-json/")
        self.assertEqual(auditor.resolve_url(self.origin + "/shared/legal"),
                         self.origin + "/shared/legal")
        status, _, _ = auditor.request("/wp-json/wp/v2/types")
        self.assertEqual(status, 200)
        self.assertEqual(MountedWordPress.requests, ["/blog/wp-json/wp/v2/types"])

    def test_recursive_sitemap_rest_pagination_and_custom_types(self):
        auditor = Auditor(self.url, limit=20)
        summary = discover_topology(auditor, max_sitemaps=6, max_rest_pages=6)
        expected = {
            self.origin + "/blog/sitemap-only-post/",
            self.origin + "/blog/rest-post-1/",
            self.origin + "/blog/rest-post-2/",
            self.origin + "/blog/unlinked-page/",
            self.origin + "/blog/hidden-book/",
        }
        self.assertTrue(expected <= auditor.wordlist)
        self.assertGreaterEqual(summary["new_urls"], len(expected))
        self.assertIn("/blog/wp-json/wp/v2/posts?per_page=20&page=2", "\n".join(
            MountedWordPress.requests))
        self.assertFalse(any(path.startswith("/wp-json") for path in
                             MountedWordPress.requests))
        self.assertIn("rest:book", auditor.discovery_sources[
            self.origin + "/blog/hidden-book/"])
        self.assertTrue(any(source.startswith("sitemap:") for source in
            auditor.discovery_sources[self.origin + "/blog/sitemap-only-post/"]))

    def test_html_and_javascript_urls_keep_provenance(self):
        auditor = Auditor(self.url, limit=8)
        auditor.discover_ajax(page_cap=1, asset_cap=2)
        for path in ("/blog/menu-post/", "/blog/js-only-post/",
                     "/blog/bundle-only/"):
            self.assertIn(self.origin + path, auditor.wordlist)
        self.assertNotIn(self.origin + "/wp-admin/*", auditor.wordlist)
        self.assertTrue(any(label.startswith("javascript:") for label in
            auditor.discovery_sources[self.origin + "/blog/bundle-only/"]))
        self.assertTrue(any(result.name ==
            "WP topology embedded HTML/JS URL discovery" for result in auditor.results))


if __name__ == "__main__":
    unittest.main()
