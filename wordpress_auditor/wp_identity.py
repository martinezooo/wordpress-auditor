"""WordPress-specific identity, REST permissions and one-shot authentication checks.

Default is read-only, anonymous. Valid operator-provided credentials enable
only bounded API profile checks or a single WP login form submission.
No guessing, user/password enumeration attacks or brute force.
"""
from __future__ import annotations

import base64
import json
import re
import urllib.parse
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from urllib.parse import urlsplit
from xml.sax.saxutils import escape

from .auditor import parse_xmlrpc_response

# Real WordPress admin profile uses form#your-profile. Generic HTTP 200 and
# "wp-admin" strings in navigation or soft-404 content are not proof of login.
WP_PROFILE_FORM = re.compile(
    rb"<form\b[^>]*\bid\s*=\s*['\"](?:your-profile|profile-page)['\"]",
    re.I,
)
WP_LOGIN_FORM = re.compile(
    rb"<form\b[^>]*\bid\s*=\s*['\"]loginform['\"]", re.I,
)


def _json(body):
    try:
        return json.loads(body.decode("utf-8"))
    except (UnicodeError, ValueError):
        return None


def _has_identity(obj):
    return isinstance(obj, dict) and type(obj.get("id")) is int and obj["id"] > 0


def _has_private_fields(records):
    if isinstance(records, dict):
        records = [records]
    return isinstance(records, list) and any(
        isinstance(x, dict) and any(k in x for k in (
            "email", "username", "roles", "capabilities", "extra_capabilities",
        )) for x in records[:10]
    )


def _has_password_metadata(items):
    return isinstance(items, list) and any(
        isinstance(x, dict) and ("uuid" in x or "app_id" in x)
        and "name" in x for x in items[:10]
    )


def _xmlrpc_blogs_confirmed(raw):
    """Require XML-RPC params containing blog structs, never just HTTP 200."""
    if len(raw) > 512 * 1024 or re.search(rb"<!DOCTYPE|<!ENTITY", raw, re.I):
        return False
    try:
        root = ET.fromstring(raw)
    except (ET.ParseError, ValueError):
        return False
    if root.tag != "methodResponse" or root.find("fault") is not None:
        return False
    records = root.findall("./params/param/value/array/data/value/struct")
    return any(record.find("./member/name[.='blogid']") is not None
               or record.find("./member/name[.='blogName']") is not None
               for record in records[:10])


@dataclass
class RoleSession:
    label: str
    headers: dict[str, str]


@dataclass
class Credentials:
    username: str | None = None
    application_password: str | None = None
    login_user: str | None = None
    login_password: str | None = None
    role_sessions: list[RoleSession] = field(default_factory=list)

    def app_header(self):
        if not self.username or not self.application_password:
            return None
        pair = (self.username + ":" + self.application_password).encode()
        return "Basic " + base64.b64encode(pair).decode("ascii")


class WordPressIdentity:
    def __init__(self, auditor, credentials=None):
        self.a = auditor
        self.credentials = credentials or Credentials()
        self.public_profiles = 0
        self.authenticated = False
        self.login_attempted = False

    def _get(self, name, path, *, anonymous=True, headers=None):
        a = self.a
        status, body, response = a.request(
            path, "GET", headers=headers,
            include_credentials=False if anonymous else None,
        )
        return status, body, response

    def _record(self, name, path, status, verdict, detail):
        self.a.add(name, path, status, detail=detail, visibility=verdict)

    def public_users(self, max_authors=3):
        a = self.a
        path = "/wp-json/wp/v2/users?per_page=5"
        status, body, _ = self._get("Public author listing", path)
        users = _json(body)
        valid = users if isinstance(users, list) else []
        public = [x for x in valid if _has_identity(x)]
        self.public_profiles = len(public)
        self._record("WP users public REST listing", path, status, "public-author-info"
                     if status == 200 and public else "observed",
                     "%d public author profiles listed (expected for published authors); "
                     "identifiers withheld" % len(public)
                     if status == 200 else "Public users endpoint returned HTTP %s" % status)

        path = "/wp-json/wp/v2/users?context=edit&per_page=1"
        status, body, _ = self._get("Anonymous edit-context users", path)
        sensitive = status == 200 and _has_private_fields(_json(body))
        self._record("WP users private edit context (anonymous)", path, status,
                     "confirmed-public-user-private-fields" if sensitive else "auth-required"
                     if status in (401, 403) else "unverified",
                     "Private user attributes exposed to anonymous request; values withheld"
                     if sensitive else
                     "No private fields verified (HTTP %s)" % status)

        path = "/wp-json/wp/v2/users/me"
        status, body, _ = self._get("Anonymous current user", path)
        identity = status == 200 and _has_identity(_json(body))
        self._record("WP REST current user (anonymous)", path, status,
                     "confirmed-public-current-user" if identity else "auth-required"
                     if status in (401, 403) else "unverified",
                     "Authenticated identity returned without any credentials; values withheld"
                     if identity else "Anonymous current-user endpoint HTTP %s" % status)

        for author_id in range(1, min(max_authors, 5) + 1):
            if a.request_count >= a.limit:
                break
            path = "/?author=%d" % author_id
            status, body, resp = self._get("Author archive", path)
            destination = resp.get("Location", "") or resp.get("location", "")
            redirected_to_author = bool(
                status in (301, 302, 303, 307, 308)
                and "/author/" in urlsplit(destination).path
            )
            self._record("WP author archive ID %d" % author_id, path, status,
                         "public-author-info" if redirected_to_author else "observed",
                         "Author archive redirect observed; does not prove login name"
                         if redirected_to_author else
                         "Author archive HTTP %s; cannot infer identity solely from status" % status)

    def protected_rest(self):
        a = self.a
        routes = [
            ("WP REST settings (anonymous)", "/wp-json/wp/v2/settings", "settings"),
            ("WP REST plugin administration (anonymous)", "/wp-json/wp/v2/plugins", "plugins"),
            ("WP REST themes administration (anonymous)", "/wp-json/wp/v2/themes", "themes"),
            ("WP REST app-password list (anonymous)",
             "/wp-json/wp/v2/users/me/application-passwords", "app-passwords"),
        ]
        for name, path, kind in routes:
            if a.request_count >= a.limit:
                break
            status, body, _ = self._get(name, path)
            data = _json(body)
            if kind == "app-passwords":
                confirmed = status == 200 and _has_password_metadata(data)
                disabled = (status == 501 and isinstance(data, dict)
                            and data.get("code") == "application_passwords_disabled")
                verdict = ("confirmed-public-app-password-metadata" if confirmed else
                           "feature-disabled" if disabled else
                           "auth-required" if status in (401, 403) else "unverified")
                detail = ("Application password metadata returned anonymously (values withheld)" if confirmed else
                          "Application Passwords are disabled on this site (WordPress HTTP 501); "
                          "authenticated Application Password checks are not applicable" if disabled else
                          "Read restricted (HTTP %s)" % status)
            elif kind == "settings":
                confirmed = status == 200 and isinstance(data, dict) and (
                    "siteurl" in data or "default_role" in data or "users_can_register" in data)
                registration_open = (
                    confirmed and data.get("users_can_register") is True
                    and data.get("default_role") == "administrator")
                if registration_open:
                    verdict = "confirmed-unsafe-wp-registration-default-role"
                    detail = ("Anonymous WP settings indicate registration enabled with administrator "
                              "as the default role; no account creation attempted")
                else:
                    verdict = "review-public-wp-settings" if confirmed else (
                        "auth-required" if status in (401, 403) else "unverified")
                    detail = "Administrative site settings returned anonymously; review access policy" if confirmed else (
                        "Private settings not verified (HTTP %s)" % status)
            else:
                private_collection = status == 200 and isinstance(data, list) and any(
                    isinstance(x, dict) and
                    ("plugin" in x and "status" in x if kind == "plugins"
                     else "stylesheet" in x and "status" in x)
                    for x in data[:5]
                )
                verdict = "review-public-wp-admin-list" if private_collection else (
                    "auth-required" if status in (401, 403) else "unverified")
                detail = "Administrative %s list visible anonymously; examine policy" % kind if private_collection else (
                    "Administrative list not proven accessible (HTTP %s)" % status)
            self._record(name, path, status, verdict, detail)

    def login_surfaces(self, max_checks=7):
        routes = [
            ("WP login form", "/wp-login.php", "login"),
            ("WP registration form", "/wp-login.php?action=register", "register"),
            ("WP password reset form", "/wp-login.php?action=lostpassword", "lostpassword"),
            ("WP network signup", "/wp-signup.php", "signup"),
            ("WP account activation", "/wp-activate.php", "activation"),
            ("WP installation wizard", "/wp-admin/install.php", "install"),
            ("WP database repair interface", "/wp-admin/maint/repair.php", "repair"),
        ]
        from .wp_policy import classify
        for name, path, kind in routes[:max_checks]:
            if self.a.request_count >= self.a.limit:
                break
            status, body, _ = self._get(name, path)
            verdict, detail = classify(kind, status, body)
            self._record(name, path, status, verdict, detail)

    def authenticated_rest(self):
        a = self.a
        auth = self.credentials.app_header()
        # Supplied session cookies/nonce may work, but are never considered
        # proof of identity unless /users/me returns a real WP user id.
        # --login-user makes the scan credential-aware, but no REST
        # Authorization or cookie has been established until the later
        # single_login phase. Do not send a fake authenticated REST request.
        supplied_session = any(k.lower() in ("cookie", "authorization", "x-wp-nonce")
                               for k in a.headers)
        if not auth and not (a.authorized and supplied_session):
            return
        path = "/wp-json/wp/v2/users/me?context=edit"
        extra = {"Authorization": auth} if auth else {}
        status, body, _ = a.request(path, headers=extra,
                                    include_credentials=True,
                                    isolate_headers=bool(auth))
        data = _json(body)
        confirmed = status == 200 and _has_identity(data)
        self.authenticated = confirmed
        self._record("WP REST authenticated identity", path, status,
                     "authenticated-identity-confirmed" if confirmed else "auth-not-confirmed",
                     "Valid WordPress REST identity confirmed; identifying values withheld"
                     if confirmed else "Identity not verified (HTTP %s). "
                     "Cookie REST requests may require X-WP-Nonce." % status)
        if not confirmed:
            return
        routes = [
            ("/wp-json/wp/v2/users?context=edit&per_page=1",
             "WP role boundary: users edit"),
            ("/wp-json/wp/v2/settings",
             "WP role boundary: settings"),
            ("/wp-json/wp/v2/plugins",
             "WP role boundary: plugins"),
            ("/wp-json/wp/v2/themes",
             "WP role boundary: themes"),
            ("/wp-json/wc/v3/orders?per_page=1",
             "WooCommerce role boundary: orders"),
        ]
        for path, name in routes:
            if a.request_count + 2 > a.limit:
                break
            anon_status, anon_body, _ = a.request(path, include_credentials=False)
            auth_status, auth_body, _ = a.request(
                path, headers=extra, include_credentials=True,
                isolate_headers=bool(auth))
            if anon_status in (401, 403) and auth_status == 200:
                verdict = "expected-role-boundary"
                detail = "Anonymous access denied, authenticated request accepted; "
                detail += "check role policy, not automatically a flaw"
            elif anon_status == 200 and auth_status == 200:
                verdict = "review-role-boundary"
                detail = "Both anonymous/authenticated HTTP 200; "
                detail += "compare permission-sensitive fields manually"
            elif auth_status in (401, 403):
                verdict = "role-restricted"
                detail = "Logged-in user lacks this capability, or REST nonce missing"
            else:
                verdict = "unverified"
                detail = "Anonymous HTTP %s, authenticated HTTP %s" % (
                    anon_status, auth_status)
            self._record(name, path, auth_status, verdict, detail)
        roles = data.get("roles", []) if isinstance(data, dict) else []
        if isinstance(roles, list) and len(roles) == 1 and roles[0] in (
                "subscriber", "customer", "contributor", "author"):
            from .object_access import audit_low_role_objects
            audit_low_role_objects(
                a, "application-password", roles[0], data["id"],
                headers=extra, isolate_headers=bool(auth))

    def role_matrix(self):
        """Read-only comparison using explicit operator-provided WordPress sessions.

        Never fabricates a session or assumes a caller-provided role label is
        cryptographic proof of permissions; /users/me must resolve first.
        """
        if not self.credentials.role_sessions:
            return
        a = self.a
        routes = [
            ("/wp-json/wp/v2/users?context=edit&per_page=1", "users"),
            ("/wp-json/wp/v2/settings", "settings"),
            ("/wp-json/wp/v2/plugins", "plugins"),
            ("/wp-json/wp/v2/themes", "themes"),
            ("/wp-json/wc/v3/orders?per_page=1", "orders"),
        ]
        baselines = {}
        for path, key in routes:
            if a.request_count >= a.limit:
                return
            status, body, _ = a.request(path, include_credentials=False)
            baselines[key] = status

        original_headers = a.headers
        original_authorized = a.authorized
        try:
            for session in self.credentials.role_sessions[:5]:
                if a.request_count >= a.limit:
                    break
                # Isolate the supplied test role: do not mix prior Burp cookies
                # or global authorization headers with this session.
                a.headers = dict(session.headers)
                a.authorized = True
                profile = "/wp-json/wp/v2/users/me?context=edit"
                status, body, _ = a.request(profile, include_credentials=True)
                data = _json(body)
                verified = status == 200 and _has_identity(data)
                self._record("WP role-session identity " + session.label, profile,
                             status, "authenticated-identity-confirmed"
                             if verified else "auth-not-confirmed",
                             "Role-labeled test session identity confirmed; values withheld"
                             if verified else
                             "Identity not confirmed: cookies may require X-WP-Nonce")
                if not verified:
                    continue
                declared_role = session.label.lower()
                reported_roles = data.get("roles", []) if isinstance(data, dict) else []
                role_confirmed = (isinstance(reported_roles, list)
                                  and declared_role in reported_roles)
                for path, key in routes:
                    if a.request_count >= a.limit:
                        break
                    role_status, role_body, _ = a.request(
                        path, include_credentials=True)
                    public_status = baselines[key]
                    low_role = role_confirmed and declared_role in (
                        "subscriber", "customer", "contributor", "author")
                    admin_route = key in ("settings", "plugins", "themes")
                    if low_role and admin_route and role_status == 200:
                        verdict = "review-low-priv-admin-read"
                        message = "Low-privilege test session received 200 on admin REST data; "
                        message += "inspect returned permissions before reporting"
                    elif public_status in (401, 403) and role_status == 200:
                        verdict = "expected-role-boundary"
                        message = "Anonymous denied; this test session accepted for %s" % key
                        if not role_confirmed:
                            message += "; supplied role label not independently confirmed"
                    elif role_status in (401, 403):
                        verdict = "role-restricted"
                        message = "Test session denied access to %s" % key
                    else:
                        verdict = "unverified"
                        message = "Anonymous HTTP %s; role HTTP %s, no privilege inference" % (
                            public_status, role_status)
                    self._record(
                        "WP role-session permission %s %s" % (session.label, key),
                        path, role_status, verdict, message)
                if role_confirmed and declared_role in (
                        "subscriber", "customer", "contributor", "author"):
                    from .object_access import audit_low_role_objects
                    audit_low_role_objects(
                        a, session.label, declared_role, data["id"])
        finally:
            a.headers = original_headers
            a.authorized = original_authorized

    def single_login(self):
        """Exactly one username/password POST with operator-provided test credentials."""
        a = self.a
        if not (self.credentials.login_user and self.credentials.login_password):
            return
        self.login_attempted = True
        path = "/wp-login.php"
        # One prior safe GET obtains test cookie behavior without following redirects.
        code, _, _ = a.request(path, include_credentials=False)
        if code not in (200, 302):
            self._record("WP login test account", path, code, "auth-not-confirmed",
                         "Login form not accessible; no password submission attempted")
            return
        cookie = "wordpress_test_cookie=WP%20Cookie%20check"
        body = urllib.parse.urlencode({
            "log": self.credentials.login_user,
            "pwd": self.credentials.login_password,
            "wp-submit": "Log In",
            "redirect_to": a.base + "/wp-admin/",
            "testcookie": "1",
        }).encode()
        status, response, headers = a.request(
            path, "POST", body,
            {"Content-Type": "application/x-www-form-urlencoded", "Cookie": cookie},
            include_credentials=True,
        )
        # Do not store session tokens, passwords, user names or response content.
        raw_cookie = headers.get("Set-Cookie", "") or headers.get("set-cookie", "")
        logged_in = re.findall(
            r"(?:^|\n)\s*(wordpress_logged_in_[A-Za-z0-9_]+=[^;\s\n]{1,1800})",
            raw_cookie, re.I)
        admin_secure = re.findall(
            r"(?:^|\n)\s*(wordpress_sec_[A-Za-z0-9_]+=[^;\s\n]{1,1800})",
            raw_cookie, re.I)
        has_logged_in = bool(logged_in)
        if has_logged_in:
            verdict = "login-cookie-observed"
            detail = "WordPress login cookie returned; session not independently verified"
        elif status in (301, 302, 303, 307, 308):
            verdict = "login-challenge"
            detail = "Redirect after one login submission; MFA/session state inconclusive"
        elif status == 200:
            verdict = "login-challenge"
            detail = "Login form/challenge returned; credentials not confirmed"
        else:
            verdict = "auth-not-confirmed"
            detail = "Login returned HTTP %s; no further attempts" % status
        self._record("WP single test-account login", path, status, verdict, detail)
        if has_logged_in and a.request_count < a.limit:
            # Do not reuse a response token as an implicit authenticator in the
            # global scan; one scoped profile GET can confirm wp-admin access.
            values = logged_in[:1] + admin_secure[:1]
            if values:
                st, b, _ = a.request(
                    "/wp-admin/profile.php",
                    headers={"Cookie": cookie + "; " + "; ".join(values)},
                    include_credentials=True)
                ok = (st == 200 and bool(WP_PROFILE_FORM.search(b))
                      and not WP_LOGIN_FORM.search(b))
                self._record("WP login session verification", "/wp-admin/profile.php", st,
                             "authenticated-identity-confirmed" if ok else "auth-not-confirmed",
                             "Profile page reached with test session; session cookie suppressed"
                             if ok else "Not enough evidence that login session is active")

    def xmlrpc_test_account(self):
        """One valid-account introspection request, never multicall or guessing."""
        a = self.a
        if not self.credentials.app_header() or a.request_count >= a.limit:
            return
        # XML-RPC may accept application passwords where enabled. Treat faults
        # as diagnostic only, never echo method return data.
        user = escape(self.credentials.username)
        password = escape(self.credentials.application_password)
        payload = ("<?xml version='1.0'?><methodCall>"
                   "<methodName>wp.getUsersBlogs</methodName><params>"
                   "<param><value><string>" + user + "</string></value></param>"
                   "<param><value><string>" + password + "</string></value></param>"
                   "</params></methodCall>").encode("utf-8")
        status, body, _ = a.request("/xmlrpc.php", "POST", payload,
                                    {"Content-Type": "text/xml"},
                                    include_credentials=False)
        fault = parse_xmlrpc_response(body)
        success = status == 200 and _xmlrpc_blogs_confirmed(body)
        self._record("WP XML-RPC test-account authentication", "/xmlrpc.php", status,
                     "authenticated-identity-confirmed" if success else "auth-not-confirmed",
                     "One valid test-account XML-RPC request accepted; response values withheld"
                     if success else "XML-RPC test-account login not confirmed (%s)" % fault)
