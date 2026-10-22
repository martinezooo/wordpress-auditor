"""Local-only object authorization and impact-proof regressions."""
from __future__ import annotations

import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlsplit

from wordpress_auditor.auditor import Auditor
from wordpress_auditor.object_access import (
    anonymous_object_boundaries,
    audit_future_content,
    audit_low_role_objects,
)

SECRET_FUTURE = "FIXTURE-FUTURE-CONTENT-NEVER-REPORT"
SECRET_REVISION = "FIXTURE-REVISION-CONTENT-NEVER-REPORT"
SECRET_PROTECTED = "FIXTURE-PROTECTED-CONTENT-NEVER-REPORT"
SECRET_MEDIA = "FIXTURE-MEDIA-PRIVATE-NEVER-REPORT"


class ObjectAccessFixture(BaseHTTPRequestHandler):
    leak_anonymous = False
    leak_low_role = False

    def log_message(self, *_):
        pass

    def send_json(self, status, value):
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(value).encode())

    def do_GET(self):
        parsed = urlsplit(self.path)
        path, query = parsed.path, parse_qs(parsed.query)
        low_role = "low_session=1" in self.headers.get("Cookie", "")
        if path in ("/wp-json/wp/v2/posts", "/wp-json/wp/v2/pages"):
            base = "posts" if path.endswith("posts") else "pages"
            if query.get("status") == ["future"]:
                if type(self).leak_anonymous:
                    self.send_json(200, [{
                        "id": 31 if base == "posts" else 32,
                        "status": "future",
                        "content": {"rendered": SECRET_FUTURE},
                    }])
                else:
                    self.send_json(400, {
                        "code": "rest_invalid_param",
                        "data": {"details": {"status": {
                            "code": "rest_forbidden_status",
                            "data": {"status": 401},
                        }}},
                    })
                return
            if query.get("context") == ["edit"]:
                if low_role and type(self).leak_low_role:
                    self.send_json(200, [{
                        "id": 41, "status": "draft", "author": 99,
                        "content": {"raw": SECRET_FUTURE},
                    }])
                else:
                    self.send_json(400, {
                        "code": "rest_invalid_param",
                        "data": {"details": {"status": {
                            "code": "rest_forbidden_status",
                            "data": {"status": 403},
                        }}},
                    })
                return
            if base == "posts":
                content = ({"protected": True, "rendered": SECRET_PROTECTED}
                           if type(self).leak_anonymous else
                           {"protected": True,
                            "rendered": '<form class="post-password-form">Password</form>'})
                self.send_json(200, [{
                    "id": 10, "status": "publish", "author": 99,
                    "content": content,
                }])
            else:
                self.send_json(200, [{
                    "id": 20, "status": "publish", "author": 99,
                    "content": {"protected": False, "rendered": "Public page"},
                }])
        elif path in (
                "/wp-json/wp/v2/posts/10/revisions",
                "/wp-json/wp/v2/pages/20/revisions"):
            if type(self).leak_anonymous or (low_role and type(self).leak_low_role):
                self.send_json(200, [{
                    "id": 101, "parent": 10,
                    "content": {"raw": SECRET_REVISION},
                }])
            else:
                self.send_json(401, {"code": "rest_cannot_read"})
        elif path in (
                "/wp-json/wp/v2/posts/10/autosaves",
                "/wp-json/wp/v2/pages/20/autosaves"):
            if type(self).leak_anonymous:
                self.send_json(200, [{
                    "id": 102, "parent": 10,
                    "content": {"raw": SECRET_REVISION},
                }])
            else:
                self.send_json(401, {"code": "rest_cannot_read"})
        elif path == "/wp-json/wp/v2/media" and query.get("context") == ["edit"]:
            if type(self).leak_anonymous:
                self.send_json(200, [{
                    "id": 50, "caption": {"raw": SECRET_MEDIA},
                    "description": {"raw": ""}, "meta": {},
                }])
            else:
                self.send_json(401, {"code": "rest_cannot_read"})
        elif path == "/wp-json/wp/v2/media" and query.get("context") == ["view"]:
            self.send_json(200, [{
                "id": 50, "caption": {"rendered": "Public caption"},
                "description": {"rendered": ""}, "meta": {},
            }])
        else:
            self.send_json(404, {"code": "rest_no_route"})


class ObjectAccessTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = HTTPServer(("127.0.0.1", 0), ObjectAccessFixture)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.url = f"http://127.0.0.1:{cls.server.server_port}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=2)

    def setUp(self):
        ObjectAccessFixture.leak_anonymous = False
        ObjectAccessFixture.leak_low_role = False

    def test_normal_wordpress_boundaries_are_not_findings(self):
        auditor = Auditor(self.url, limit=20)
        audit_future_content(auditor)
        anonymous_object_boundaries(auditor)
        self.assertFalse(any(result.proof == "PROVED" for result in auditor.results))
        self.assertTrue(any(result.visibility == "auth-required"
                            for result in auditor.results))
        protected = next(result for result in auditor.results
                         if result.name == "WP password-protected posts")
        self.assertEqual(protected.severity, "INFO")

    def test_anonymous_object_content_exposures_are_exercised_and_redacted(self):
        ObjectAccessFixture.leak_anonymous = True
        auditor = Auditor(self.url, limit=20)
        audit_future_content(auditor)
        anonymous_object_boundaries(auditor)
        proved = [result for result in auditor.results if result.proof == "PROVED"]
        states = {result.visibility for result in proved}
        self.assertTrue({
            "confirmed-public-nonpublic-wp-content",
            "confirmed-public-revision-content",
            "confirmed-public-autosave-content",
            "confirmed-public-password-protected-content",
            "confirmed-public-media-edit-fields",
        } <= states)
        self.assertEqual({result.severity for result in proved}, {"MEDIUM", "LOW"})
        report = json.dumps([result.__dict__ for result in auditor.results])
        for secret in (SECRET_FUTURE, SECRET_REVISION, SECRET_PROTECTED, SECRET_MEDIA):
            self.assertNotIn(secret, report)

    def test_confirmed_subscriber_other_author_access_is_proved(self):
        ObjectAccessFixture.leak_low_role = True
        auditor = Auditor(self.url, limit=8, authorized=True)
        audit_low_role_objects(
            auditor, "subscriber", "subscriber", 5,
            headers={"Cookie": "low_session=1"})
        proved = [result for result in auditor.results if result.proof == "PROVED"]
        self.assertEqual({result.visibility for result in proved}, {
            "confirmed-low-priv-nonpublic-content",
            "confirmed-low-priv-revision-content",
        })
        self.assertNotIn(SECRET_FUTURE, json.dumps(
            [result.__dict__ for result in auditor.results]))
        self.assertNotIn(SECRET_REVISION, json.dumps(
            [result.__dict__ for result in auditor.results]))

    def test_low_role_forbidden_status_is_recorded_as_protection(self):
        auditor = Auditor(self.url, limit=8, authorized=True)
        audit_low_role_objects(
            auditor, "subscriber", "subscriber", 5,
            headers={"Cookie": "low_session=1"})
        collection = next(result for result in auditor.results
                          if result.name.startswith("WP low-role object boundary"))
        self.assertEqual(collection.status, 400)
        self.assertEqual(collection.visibility, "role-restricted")
        self.assertEqual(collection.proof, "OBSERVED")


if __name__ == "__main__":
    unittest.main()
