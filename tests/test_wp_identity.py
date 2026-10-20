"""WordPress-native auth and identity regression tests: localhost ONLY."""
from __future__ import annotations

import base64
import contextlib
import io
import json
import os
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlsplit
from unittest.mock import patch

from wordpress_auditor.auditor import Auditor
from wordpress_auditor.cli import main
from wordpress_auditor.wp_identity import Credentials, WordPressIdentity
from wordpress_auditor.check_catalog import CHECKS, coverage, summary, describe_plan

LOGIN_PASSWORD = "LOCAL_FIXTURE_ONLY_LOGIN_SECRET"
APPLICATION_PASSWORD = "LOCAL_FIXTURE_ONLY_APP_SECRET"
USER_NAME = "fixturetestaccount"
PRIVATE_EMAIL = "private-admin-email@example.invalid"


class WPHandler(BaseHTTPRequestHandler):
    calls = []
    allow_sensitive = False

    def log_message(self, *_):
        pass

    def send(self, status, body=b"", headers=None):
        self.send_response(status)
        for k,v in (headers or {}).items():
            self.send_header(k,v)
        self.end_headers()
        self.wfile.write(body)

    def track(self, method, body=b""):
        type(self).calls.append((method, self.path, dict(self.headers), body))

    def _authed(self):
        value = self.headers.get("Authorization", "")
        expected = "Basic " + base64.b64encode(
            (USER_NAME + ":" + APPLICATION_PASSWORD).encode()).decode()
        session = (
            ("wordpress_logged_in_abc=fixture_session"
             in self.headers.get("Cookie","")
             or "wp_subscriber_session=fixture"
             in self.headers.get("Cookie",""))
            and self.headers.get("X-WP-Nonce") == "fixture-nonce")
        return value == expected or session

    def do_GET(self):
        self.track("GET")
        path, query = urlsplit(self.path).path, parse_qs(urlsplit(self.path).query)
        if path == "/xmlrpc.php":
            self.send(403, b"Forbidden GET")
        elif path == "/wp-json/":
            self.send(200, b'{"routes":{"/wp/v2/users":{"methods":["GET"]}}}')
        elif path == "/wp-json/wp/v2/users" and query.get("context") == ["edit"]:
            if self._authed() or self.allow_sensitive:
                data = [{"id":1, "username":"internal-user", "email":PRIVATE_EMAIL,
                         "roles":["administrator"]}]
                self.send(200, json.dumps(data).encode())
            else:
                self.send(403, b'{"code":"rest_forbidden_context"}')
        elif path == "/wp-json/wp/v2/users":
            data = [{"id":5, "slug":"published-author", "name":"Public Author"}]
            self.send(200, json.dumps(data).encode())
        elif path == "/wp-json/wp/v2/users/me":
            if self._authed():
                role = "subscriber" if "wp_subscriber_session=fixture" in (
                    self.headers.get("Cookie","")) else "editor"
                self.send(200, json.dumps({
                    "id": 5, "name": "Authenticated Example", "roles": [role],
                }).encode())
            else:
                self.send(401, b'{"code":"rest_not_logged_in"}')
        elif path == "/wp-json/wp/v2/settings":
            self.send(200, b'{"siteurl":"https://fixture.invalid","default_role":"subscriber"}') if self.allow_sensitive else (
                self.send(200, b'{"siteurl":"https://fixture.invalid"}') if self._authed() else self.send(401))
        elif path == "/wp-json/wp/v2/plugins":
            if self._authed():
                self.send(200, b'[{"plugin":"my-plugin","status":"active"}]')
            else:
                self.send(403)
        elif path == "/wp-json/wp/v2/themes":
            self.send(403)
        elif path == "/wp-json/wp/v2/users/me/application-passwords":
            if self.allow_sensitive:
                self.send(200, b'[{"uuid":"000-111","name":"Automation"}]')
            else:
                self.send(401)
        elif path == "/wp-login.php":
            self.send(200, b'<form id="loginform" action="wp-login.php" method="post"></form>')
        elif path == "/wp-admin/profile.php":
            if "wordpress_logged_in_abc=fixture_session" in self.headers.get("Cookie",""):
                self.send(200, b'<div id="wp-admin">Profile</div>')
            else:
                self.send(302, headers={"Location":"/wp-login.php"})
        elif path == "/wp-admin/install.php":
            self.send(200, b"<p>Already Installed</p>")
        elif path == "/wp-admin/maint/repair.php":
            self.send(200, b"<p>Repair feature is disabled</p>")
        elif path == "/":
            self.send(200, b"<html>WordPress demo</html>")
        elif path == "/wp-admin/":
            self.send(302, headers={"Location":"/wp-login.php"})
        elif path == "/wp-admin/admin-ajax.php":
            self.send(400, b"0")
        elif path == "/wp-signup.php" or path == "/wp-activate.php":
            self.send(403)
        elif path == "/" and "author" in query:
            self.send(302, headers={"Location":"/author/public-author/"})
        elif "author" in query and path == "/":
            self.send(302, headers={"Location":"/author/public-author/"})
        else:
            self.send(404, b"not found")

    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length","0")))
        self.track("POST",body)
        path = urlsplit(self.path).path
        if path == "/xmlrpc.php":
            if b"<methodName>system.listMethods</methodName>" in body:
                self.send(200, b"<methodResponse><params><param><value><array><data>"
                     b"<value><string>system.listMethods</string></value>"
                     b"<value><string>system.multicall</string></value>"
                     b"<value><string>pingback.ping</string></value>"
                     b"</data></array></value></param></params></methodResponse>")
            elif b"<methodName>wp.getUsersBlogs</methodName>" in body:
                valid = APPLICATION_PASSWORD.encode() in body and USER_NAME.encode() in body
                if valid:
                    self.send(200,b"<methodResponse><params><param><value><array><data>"
                          b"<value><struct><member><name>blogid</name><value>"
                          b"<string>1</string></value></member></struct></value>"
                          b"</data></array></value></param></params></methodResponse>")
                else:
                    self.send(200,b"<methodResponse><fault><value><struct><member>"
                          b"<name>faultCode</name><value><int>403</int></value>"
                          b"</member></struct></value></fault></methodResponse>")
            else:
                self.send(200,b"<methodResponse><fault><value><struct><member>"
                          b"<name>faultCode</name><value><int>-32601</int></value>"
                          b"</member></struct></value></fault></methodResponse>")
        elif path == "/wp-login.php":
            params = parse_qs(body.decode())
            good = (params.get("log") == [USER_NAME] and
                    params.get("pwd") == [LOGIN_PASSWORD])
            if good:
                self.send(302,headers={
                    "Location": "/wp-admin/",
                    "Set-Cookie": "wordpress_logged_in_abc=fixture_session; Secure; HttpOnly",
                })
            else:
                self.send(200,b'<form id="loginform"><p>Try again</p></form>')
        else:
            self.send(404)


class WordPressIdentityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server=HTTPServer(("127.0.0.1",0),WPHandler)
        cls.thread=threading.Thread(target=cls.server.serve_forever,daemon=True)
        cls.thread.start()
        cls.url="http://127.0.0.1:%s" % cls.server.server_port

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=2)

    def setUp(self):
        WPHandler.calls=[]
        WPHandler.allow_sensitive=False

    def _audit(self, *, limit=220, credentials=None):
        a=Auditor(self.url,limit=limit,delay=0,
                  authorized=bool(credentials and (credentials.application_password
                                                   or credentials.login_password)))
        a.discover(full=True, payload_limit=8, identity_credentials=credentials)
        return a

    def test_default_runs_wordpress_specific_identity_and_login_checks(self):
        a=self._audit()
        names={r.name for r in a.results}
        for label in (
            "WP users public REST listing",
            "WP users private edit context (anonymous)",
            "WP REST current user (anonymous)",
            "WP registration form",
            "WP password reset form",
            "WP REST settings (anonymous)",
            "WP REST app-password list (anonymous)",
        ):
            self.assertIn(label,names)
        self.assertTrue(any(n.startswith("WP author archive ID") for n in names))
        self.assertTrue(any(n=="XML-RPC system.listMethods" for n in names))
        self.assertFalse(any(method=="POST" and path=="/wp-login.php"
                             for method,path,*_ in WPHandler.calls))
        self.assertTrue(any(p["name"]=="WordPress public users / author archives"
                            for p in a.phase_stats))
        self.assertLessEqual(a.request_count,a.limit)

    def test_xmlrpc_get403_still_attempts_one_safe_post_then_introspects(self):
        a=Auditor(self.url,limit=10)
        a.xmlrpc()
        self.assertEqual(a.results[0].status,403)
        self.assertEqual(WPHandler.calls[0][:2],("GET","/xmlrpc.php"))
        self.assertEqual(WPHandler.calls[1][:2],("POST","/xmlrpc.php"))
        names=[r.name for r in a.results]
        self.assertIn("XML-RPC system.listMethods",names)
        self.assertTrue(any("pingback.ping" in r.detail for r in a.results))
        self.assertFalse(any(b"<methodName>pingback.ping</methodName>" in row[3]
                             for row in WPHandler.calls if row[0]=="POST"))
        self.assertFalse(any(b"<methodName>system.multicall</methodName>" in row[3]
                             for row in WPHandler.calls if row[0]=="POST"))

    def test_public_authors_are_info_not_a_vulnerability(self):
        a=Auditor(self.url,limit=15)
        WordPressIdentity(a).public_users()
        r=[r for r in a.results if r.name=="WP users public REST listing"][0]
        self.assertEqual(r.severity,"INFO")
        self.assertIn("1 public author profiles",r.detail)
        self.assertNotIn("published-author",r.detail)

    def test_private_users_edit_context_exposed_is_evidence_based(self):
        WPHandler.allow_sensitive=True
        a=Auditor(self.url,limit=15)
        WordPressIdentity(a).public_users()
        exposed=[r for r in a.results if r.visibility=="confirmed-public-user-private-fields"]
        self.assertEqual(len(exposed),1)
        self.assertEqual(exposed[0].severity,"MEDIUM")
        self.assertNotIn(PRIVATE_EMAIL,json.dumps([r.__dict__ for r in a.results]))

    def test_public_application_password_metadata_is_redacted(self):
        WPHandler.allow_sensitive=True
        a=Auditor(self.url,limit=8)
        WordPressIdentity(a).protected_rest()
        r=[r for r in a.results if "app-password" in r.name][0]
        self.assertEqual(r.severity,"MEDIUM")
        self.assertNotIn("Automation",r.detail)
        self.assertNotIn("uuid",r.detail)

    def test_authenticated_rest_confirms_identity_and_role_differences(self):
        c=Credentials(username=USER_NAME,application_password=APPLICATION_PASSWORD)
        a=Auditor(self.url,limit=45,authorized=True)
        identity=WordPressIdentity(a,c)
        identity.authenticated_rest()
        self.assertTrue(identity.authenticated)
        self.assertTrue(any(r.visibility=="expected-role-boundary" for r in a.results))
        self.assertNotIn(APPLICATION_PASSWORD,json.dumps([r.__dict__ for r in a.results]))
        get_credentials=[row[2].get("Authorization") for row in WPHandler.calls
                         if row[2].get("Authorization")]
        self.assertTrue(get_credentials)
        self.assertTrue(all(row[1].startswith("/wp-json/") for row in WPHandler.calls
                            if row[2].get("Authorization")))
        self.assertTrue(any(row[1].startswith("/wp-json/wp/v2/users/me") and
                            "Authorization" not in row[2] for row in WPHandler.calls) is False
                            or identity.authenticated)

    def test_cookie_nonce_session_can_be_authenticated_and_compared(self):
        a=Auditor(self.url,limit=38,authorized=True,headers={
            "Cookie":"wordpress_logged_in_abc=fixture_session",
            "X-WP-Nonce":"fixture-nonce",
        })
        identity=WordPressIdentity(a)
        identity.authenticated_rest()
        self.assertTrue(identity.authenticated)
        self.assertTrue(any(r.visibility=="expected-role-boundary" for r in a.results))
        self.assertTrue(any("Cookie" not in row[2] and
                            row[1].startswith("/wp-json/wp/v2/settings")
                            for row in WPHandler.calls))
        self.assertNotIn("fixture_session",json.dumps([r.__dict__ for r in a.results]))

    def test_false_http200_without_user_id_is_not_login(self):
        a=Auditor(self.url,limit=3)
        self.assertFalse(WordPressIdentity(a).authenticated)
        self.assertFalse(a.results)
        from wordpress_auditor.wp_identity import _has_identity
        self.assertFalse(_has_identity({"id":"1","name":"any"}))
        self.assertFalse(_has_identity({"id":0}))
        self.assertTrue(_has_identity({"id":2,"name":"test"}))

    def test_role_matrix_requires_confirmed_wp_role_and_isolates_sessions(self):
        from wordpress_auditor.wp_identity import RoleSession
        creds = Credentials(role_sessions=[
            RoleSession("subscriber", {
                "Cookie": "wp_subscriber_session=fixture",
                "X-WP-Nonce": "fixture-nonce",
            }),
            RoleSession("editor", {
                "Cookie": "wordpress_logged_in_abc=fixture_session",
                "X-WP-Nonce": "fixture-nonce",
            }),
        ])
        a = Auditor(self.url, limit=40, headers={"Cookie": "original-secret-cookie"},
                    authorized=True)
        WordPressIdentity(a, creds).role_matrix()
        names = [r.name for r in a.results]
        self.assertIn("WP role-session identity subscriber", names)
        self.assertIn("WP role-session identity editor", names)
        candidates = [r for r in a.results if r.name.startswith(
            "WP role-session permission subscriber settings")]
        self.assertEqual(len(candidates), 1)
        self.assertEqual(candidates[0].visibility, "review-low-priv-admin-read")
        self.assertEqual(candidates[0].severity, "REVIEW")
        self.assertFalse(any("original-secret-cookie" in str(headers)
                             for _, _, headers, _ in WPHandler.calls))
        self.assertFalse(any("wp_subscriber_session=fixture" in str(headers)
                             and "wordpress_logged_in_abc=fixture_session" in str(headers)
                             for _, _, headers, _ in WPHandler.calls))
        self.assertNotIn("fixture-nonce",json.dumps([r.__dict__ for r in a.results]))

    def test_cli_role_request_uses_burp_headers_and_no_secret_report_leaks(self):
        with tempfile.TemporaryDirectory() as d:
            burp = os.path.join(d,"subscriber.burp")
            target = urlsplit(self.url)
            with open(burp,"w",encoding="utf-8") as f:
                f.write("GET /wp-json/wp/v2/users/me HTTP/1.1\r\n"
                        + "Host: %s\r\n" % target.netloc
                        + "Cookie: wp_subscriber_session=fixture\r\n"
                        + "X-WP-Nonce: fixture-nonce\r\n\r\n")
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                main(["--url",self.url,"--role-request","subscriber:"+burp,
                      "--max-requests","140","--delay","0",
                      "--payload-limit","4",
                      "--wordlist-out",os.path.join(d,"wordlist.txt")])
            report = os.path.join(d,"latest-report.json")
            with open(report,encoding="utf-8") as f:
                results = json.load(f)
            self.assertTrue(any(x["name"]=="WP role-session identity subscriber"
                                for x in results))
            self.assertNotIn("wp_subscriber_session",json.dumps(results))
            self.assertNotIn("fixture-nonce",output.getvalue())
            self.assertTrue(any("role-session" in line
                                for line in [x["name"] for x in results]))

    def test_role_labels_are_not_trusted_without_rest_role_evidence(self):
        from wordpress_auditor.wp_identity import RoleSession
        creds = Credentials(role_sessions=[RoleSession("subscriber", {
            "Cookie": "wordpress_logged_in_abc=fixture_session",
            "X-WP-Nonce": "fixture-nonce",
        })])
        a=Auditor(self.url,limit=17,authorized=True)
        WordPressIdentity(a,creds).role_matrix()
        self.assertFalse(any(x.visibility=="review-low-priv-admin-read" for x in a.results))
        self.assertTrue(any("role label not independently confirmed" in x.detail
                            for x in a.results))

    def test_app_password_does_not_inherit_unrelated_burp_session(self):
        creds = Credentials(username=USER_NAME,application_password=APPLICATION_PASSWORD)
        auditor = Auditor(self.url, limit=34, authorized=True, headers={
            "Cookie": "unrelated_session=secret",
            "Authorization": "Bearer WRONG_SESSION",
            "X-WP-Nonce": "other-user-nonce",
        })
        identity = WordPressIdentity(auditor,creds)
        identity.authenticated_rest()
        self.assertTrue(identity.authenticated)
        for method, path, headers, _ in WPHandler.calls:
            if headers.get("Authorization", "").startswith("Basic "):
                self.assertNotIn("Cookie", headers)
                self.assertNotIn("X-WP-Nonce", headers)
                self.assertNotIn("WRONG_SESSION",str(headers))
            if "Authorization" not in headers:
                self.assertNotIn("Cookie", headers)
                self.assertNotIn("X-WP-Nonce", headers)
        self.assertNotIn("other-user-nonce",json.dumps(
            [r.__dict__ for r in auditor.results]))

    def test_one_real_test_login_only_one_post_and_private_cookie(self):
        c=Credentials(login_user=USER_NAME,login_password=LOGIN_PASSWORD)
        a=Auditor(self.url,limit=7,authorized=True)
        WordPressIdentity(a,c).single_login()
        posts=[row for row in WPHandler.calls if row[0]=="POST"]
        self.assertEqual(len(posts),1)
        self.assertEqual(posts[0][1],"/wp-login.php")
        self.assertEqual([r.name for r in a.results],
                         ["WP single test-account login","WP login session verification"])
        self.assertEqual(a.results[-1].visibility,"authenticated-identity-confirmed")
        self.assertNotIn(LOGIN_PASSWORD,json.dumps([r.__dict__ for r in a.results]))
        self.assertNotIn("fixture_session",json.dumps([r.__dict__ for r in a.results]))

    def test_failed_login_is_not_retried_or_marked_confirmed(self):
        c=Credentials(login_user=USER_NAME,login_password="wrong-password")
        a=Auditor(self.url,limit=12,authorized=True)
        WordPressIdentity(a,c).single_login()
        posts=[row for row in WPHandler.calls if row[0]=="POST"]
        self.assertEqual(len(posts),1)
        self.assertEqual(a.results[0].severity,"INFO")
        self.assertFalse(any(r.confidence=="confirmed" for r in a.results))

    def test_xmlrpc_fake_success_response_is_not_authentication(self):
        from wordpress_auditor.wp_identity import _xmlrpc_blogs_confirmed
        self.assertFalse(_xmlrpc_blogs_confirmed(b"<html><array><struct>ok</struct></array></html>"))
        self.assertFalse(_xmlrpc_blogs_confirmed(
            b"<methodResponse><fault><value><struct><member><name>blogid</name>"
            b"</member></struct></value></fault></methodResponse>"))
        self.assertFalse(_xmlrpc_blogs_confirmed(
            b"<!DOCTYPE foo><methodResponse><params/></methodResponse>"))
        self.assertTrue(_xmlrpc_blogs_confirmed(
            b"<methodResponse><params><param><value><array><data><value><struct>"
            b"<member><name>blogid</name><value><string>1</string></value></member>"
            b"</struct></value></data></array></value></param></params></methodResponse>"))

    def test_xmlrpc_test_account_valid_credentials_once(self):
        c=Credentials(username=USER_NAME,application_password=APPLICATION_PASSWORD)
        a=Auditor(self.url,limit=4,authorized=True)
        WordPressIdentity(a,c).xmlrpc_test_account()
        posts=[x for x in WPHandler.calls if x[0]=="POST"]
        self.assertEqual(len(posts),1)
        self.assertIn(b"<methodName>wp.getUsersBlogs</methodName>",posts[0][3])
        self.assertEqual(a.results[-1].visibility,"authenticated-identity-confirmed")
        self.assertNotIn(APPLICATION_PASSWORD,json.dumps([r.__dict__ for r in a.results]))

    def test_cli_only_environment_secrets_and_explicit_app_user(self):
        env={"WPAUDITOR_APP_PASSWORD":APPLICATION_PASSWORD}
        with tempfile.TemporaryDirectory() as d, patch.dict(os.environ,env):
            out=io.StringIO()
            with contextlib.redirect_stdout(out):
                main(["--url",self.url,"--auth-user",USER_NAME,
                      "--max-requests","125","--payload-limit","5",
                      "--delay","0","--wordlist-out",os.path.join(d,"wordlist.txt")])
            result=out.getvalue()
            self.assertIn("WORDPRESS TECHNIQUE COVERAGE",result)
            self.assertNotIn(APPLICATION_PASSWORD,result)
            self.assertNotIn(PRIVATE_EMAIL,result)
            with open(os.path.join(d,"latest-report.json")) as f:
                raw=f.read()
            self.assertNotIn(APPLICATION_PASSWORD,raw)
            self.assertNotIn(PRIVATE_EMAIL,raw)
            self.assertIn("WP REST authenticated identity",raw)

    def test_cli_login_user_env_performs_single_post(self):
        with tempfile.TemporaryDirectory() as d, patch.dict(os.environ,{"WPAUDITOR_LOGIN_PASSWORD":LOGIN_PASSWORD}):
            with contextlib.redirect_stdout(io.StringIO()):
                main(["--url",self.url,"--login-user",USER_NAME,
                      "--max-requests","95","--payload-limit","4",
                      "--delay","0","--wordlist-out",os.path.join(d,"wordlist.txt")])
            posts=[x for x in WPHandler.calls if x[0]=="POST" and x[1]=="/wp-login.php"]
            self.assertEqual(len(posts),1)
            with open(os.path.join(d,"latest-report.json"),encoding="utf-8") as f:
                raw = f.read()
            self.assertNotIn(LOGIN_PASSWORD,raw)

    def test_login_or_api_secrets_require_https_for_nonloopback(self):
        for args,env in [
            (["--auth-user",USER_NAME],{"WPAUDITOR_APP_PASSWORD":APPLICATION_PASSWORD}),
            (["--login-user",USER_NAME],{"WPAUDITOR_LOGIN_PASSWORD":LOGIN_PASSWORD}),
        ]:
            with patch.dict(os.environ,env),contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit):
                    main(["--url","http://example.invalid"]+args)

    def test_skips_with_small_request_budget_are_reported(self):
        a=self._audit(limit=30)
        names=[r["name"] for r in a.phase_stats if r["state"]=="skipped"]
        self.assertIn("WordPress public users / author archives",names)
        self.assertLessEqual(a.request_count,30)

    def test_list_checks_no_url_no_requests(self):
        out=io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(main(["--list-checks"]),0)
        self.assertGreaterEqual(len(CHECKS),45)
        self.assertIn("WP-19",out.getvalue())
        self.assertIn("manual",out.getvalue())
        self.assertFalse(WPHandler.calls)

    def test_catalog_identifiers_are_unique_and_source_backed(self):
        ids = [c.check_id for c in CHECKS]
        self.assertEqual(len(ids),len(set(ids)))
        self.assertGreaterEqual(len(ids),50)
        self.assertTrue(all(c.mode in ("automatic","opt-in","manual") for c in CHECKS))
        self.assertTrue(all(c.source.startswith("https://") for c in CHECKS))

    def test_passive_asset_discoveries_are_not_counted_as_errors(self):
        a=Auditor(self.url,limit=20)
        a.discover_plugin_theme_assets()
        matches=[x for x in coverage(a) if x["id"] in ("WP-52","WP-53")]
        self.assertEqual([x["status"] for x in matches],["CHECKED","CHECKED"])
        from wordpress_auditor.reporting import format_terminal
        message=format_terminal(a,[r.__dict__ for r in a.results])
        self.assertIn("PASSIVE:2",message)
        self.assertNotIn("ERR:2",message)

    def test_coverage_matrix_does_not_claim_all_checked(self):
        a=self._audit(limit=140)
        items=coverage(a)
        self.assertEqual(len(items),len(CHECKS))
        self.assertTrue(any(r["status"]=="CHECKED" for r in items))
        self.assertTrue(any(r["status"]=="MANUAL" for r in items))
        self.assertTrue(any(r["status"]=="OPT-IN" for r in items))
        self.assertIn("MANUAL:",summary(items))
        self.assertEqual([r for r in items if r["id"]=="WP-26"][0]["status"],"MANUAL")
        self.assertEqual([r for r in items if r["id"]=="WP-17"][0]["status"],"MANUAL")
        self.assertFalse(any(r["reason"].startswith("vulnerable") for r in items))

if __name__ == "__main__":
    unittest.main()
