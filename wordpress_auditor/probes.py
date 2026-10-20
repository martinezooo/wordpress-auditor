"""Bounded, non-destructive WordPress probes using curated or user-supplied payloads.

Every probe shares the parent Auditor's rate limiter and same-origin transport.
No known state-changing paths, POST fuzzing, authentication attempts, or callbacks.
"""
from __future__ import annotations

import hashlib
import ipaddress
import os
import re
import urllib.parse
import zipfile

from .auditor import report_url, safe_url

# Representative samples derived from the user's WordPress/Burp Intruder wordlists.
# Full corpus can be supplied via --payloads <zip-or-directory>.
SEED_PATHS = (
    "/wp-admin", "/wp-admin/.", "/wp-admin/./", "/wp-admin//",
    "/./wp-admin/", "/wp-admin/.;/", "/.;/wp-admin/",
    "/wp-admin/;/", "/wp-admin%2f", "/wp-admin%2F",
    "/%2e/wp-admin/", "/wp-admin/%2e/", "/wp-admin/%2E/",
    "/%252e/wp-admin/", "/wp-admin%252f", "/%77p-admin/",
    "/WP-ADMIN/", "/Wp-Admin/", "/wp-admin/index.php",
    "/wp-admin/index.php/", "/wp-admin/index.php/.",
    "/wp-login.php", "/wp-login.php/.", "/wp-login.php%2f",
    "/%2e/wp-login.php", "/login/", "/admin/", "/dashboard/",
    "/wp-admin/admin-ajax.php", "/wp-admin/admin-post.php",
    "/wp-json/", "/index.php?rest_route=/",
    "/wp-json/wp/v2/users?per_page=1",
    "/wp-json/wp/v2/comments?per_page=1",
    "/wp-json/wc/store/v1/products?per_page=1",
    "/wp-sitemap.xml", "/sitemap_index.xml",
    "/robots.txt", "/readme.html", "/license.txt",
    "/wp-content/debug.log", "/wp-config.php.bak",
    "/wp-config.php~", "/.wp-config.php.swp",
)
SEED_HEADERS = (
    ("X-Original-URL", "/wp-admin/"),
    ("X-Rewrite-URL", "/wp-admin/"),
    ("X-Original-URI", "/wp-admin/"),
    ("X-Original-URL", "/wp-login.php"),
    ("X-Rewrite-URL", "/wp-login.php"),
    ("X-HTTP-Method-Override", "GET"),
    ("X-Method-Override", "GET"),
    ("X-Requested-With", "XMLHttpRequest"),
    ("X-Forwarded-For", "127.0.0.1"),
    ("X-Real-IP", "127.0.0.1"),
)
HEADER_ALLOWLIST = frozenset({
    "x-original-url", "x-rewrite-url", "x-original-uri",
    "x-forwarded-uri", "x-http-method-override", "x-method-override",
    "x-requested-with", "x-forwarded-for", "x-real-ip",
    "x-remote-ip", "x-client-ip", "x-originating-ip",
})
ALLOWED_QUERY = frozenset({
    "rest_route", "per_page", "page", "search", "p", "author", "orderby",
    "_fields", "_", "test", "lang",
})
UNSAFE_PATH = re.compile(
    r"(?:^|[/._-])(logout|signout|delete|remove|reset|activate|"
    r"unsubscribe|purge|clear-cache|add-to-cart)(?:$|[/._?-])",
    re.I,
)
LOGIN_MARKER = re.compile(
    rb"wp-login\.php|id=['\"]loginform|name=['\"]log['\"]|"
    rb"password-reset|please log in|wp-admin-bar-login", re.I,
)
ERROR_MARKER = re.compile(
    rb"404 not found|page not found|does not exist|no route was found",
    re.I,
)


def safe_candidate(auditor, entry):
    """Return in-scope candidate GET URL, otherwise None."""
    if not isinstance(entry, str):
        return None
    entry = entry.strip()
    if not entry or "\\" in entry or any(ord(ch) < 32 for ch in entry) or len(entry) > 400:
        return None
    if not entry.startswith("/") or entry.startswith("//"):
        return None
    if UNSAFE_PATH.search(entry):
        return None
    parsed = urllib.parse.urlsplit(entry)
    if parsed.fragment:
        entry = entry.split("#", 1)[0]
    if any(k not in ALLOWED_QUERY for k in urllib.parse.parse_qs(parsed.query)):
        return None
    if not auditor._allowed(entry):
        return None
    return entry


def _read_payload_lines(file_path, basename):
    if os.path.isdir(file_path):
        candidate = os.path.join(file_path, basename)
        if not os.path.isfile(candidate):
            return []
        with open(candidate, encoding="utf-8-sig") as f:
            return f.read(100_000).splitlines()
    if not zipfile.is_zipfile(file_path):
        raise ValueError("--payloads must be a directory or zip archive")
    with zipfile.ZipFile(file_path) as f:
        candidates = [i for i in f.infolist()
                      if i.filename.rsplit("/", 1)[-1] == basename and i.file_size <= 100_000]
        if not candidates:
            return []
        return f.read(candidates[0]).decode("utf-8-sig").splitlines()


def get_payloads(auditor, location=None):
    paths = list(SEED_PATHS)
    headers = list(SEED_HEADERS)
    if location:
        if not os.path.exists(location):
            raise ValueError("--payloads path does not exist")
        paths.extend(_read_payload_lines(location, "02_urls.txt"))
        for line in _read_payload_lines(location, "01_headers.txt"):
            if ":" not in line:
                continue
            key, value = line.split(":", 1)
            key, value = key.strip(), value.strip()
            if key.lower() not in HEADER_ALLOWLIST or len(value) > 100:
                continue
            if any(ord(ch) < 32 for ch in value):
                continue
            if key.lower().endswith(("uri", "url")):
                if not safe_candidate(auditor, value):
                    continue
            if key.lower().endswith("override") and value.upper() not in ("GET", "HEAD"):
                continue
            headers.append((key, value))
    clean_paths = []
    for path in paths:
        if safe_candidate(auditor, path) and path not in clean_paths:
            clean_paths.append(path)
    clean_headers = list(dict.fromkeys(headers))
    return clean_paths, clean_headers


class ProbeSuite:
    def __init__(self, auditor, payloads=None):
        self.a = auditor
        self.paths, self.headers = get_payloads(auditor, payloads)
        self.completed = 0

    def _probe(self, name, path, baseline, control, headers=None, no_creds=True):
        if self.a.request_count >= self.a.limit:
            return
        kw = dict(include_credentials=False) if no_creds else {}
        if headers:
            kw["headers"] = headers
            kw["test_headers"] = True
        status, body, meta = self.a.request(path, **kw)
        self.completed += 1
        marker = (LOGIN_MARKER.search(body) or ERROR_MARKER.search(body))
        same_response = (status == baseline[0] and
                         hashlib.sha256(body).digest() == baseline[1])
        matches_control = (status == control[0] and
                           hashlib.sha256(body).digest() == control[1])
        if status is None:
            verdict = "not-evaluated"
        elif status in (401, 403):
            verdict = "access-denied"
        elif status in (301, 302, 303, 307, 308):
            verdict = "redirect (not access proof)"
        elif status >= 500:
            verdict = "server-error/requires-review"
        elif same_response:
            verdict = "baseline-equivalent"
        elif matches_control or marker:
            verdict = "soft-404-or-login"
        elif baseline[0] in (401, 403) and status == 200:
            verdict = "differential/requires-review"
        else:
            verdict = "response-observed"
        self.a.add(name, path, status, detail=verdict, visibility=verdict)

    def access_variants(self, max_cases=30, target="/wp-admin/"):
        """Compare benign path/header variants against a denied baseline and a random-path control."""
        a = self.a
        if a.request_count + 2 >= a.limit:
            return 0
        status, body, _ = a.request(target, include_credentials=False)
        a.add("payload baseline", target, status)
        control_path = "/.well-known/wp-audit-" + hashlib.sha256(target.encode()).hexdigest()[:14]
        control_status, control_body, _ = a.request(control_path, include_credentials=False)
        a.add("payload soft404 control", control_path, control_status)
        baseline = (status, hashlib.sha256(body).digest())
        control = (control_status, hashlib.sha256(control_body).digest())
        count = 0
        path_budget = max_cases if status not in (401, 403, 301, 302) else max(1, (max_cases * 2) // 3)
        tested = {report_url(safe_url(a.base, target))}
        for path in self.paths:
            if count >= path_budget or a.request_count >= a.limit:
                break
            if path == target or path in tested or not (
                re.search(r"wp-admin|wp-login|/admin|/login|dashboard|%2e|%2f", path, re.I)
            ):
                continue
            tested.add(path)
            self._probe("path payload", path, baseline, control)
            count += 1
        if status not in (401, 403, 302, 301):
            return count  # header spoofing only makes sense with restricted baseline
        for name, value in self.headers:
            if count >= max_cases or a.request_count >= a.limit:
                break
            # Only target-safe, read-only headers, never impersonate an external origin.
            if name.lower() not in HEADER_ALLOWLIST:
                continue
            if name.lower().endswith(("url", "uri")) and value not in (
                "/wp-admin/", "/wp-login.php", "/wp-admin/index.php"):
                continue
            self._probe("header payload " + name, target, baseline, control,
                        headers={name: value})
            count += 1
        return count

    def method_negotiation(self, max_cases=10):
        """Probe only HEAD/OPTIONS; never submit a write-capable method."""
        a = self.a
        paths = (
            "/wp-json/", "/wp-json/wp/v2/comments", "/wp-admin/",
            "/wp-admin/admin-ajax.php", "/wp-login.php", "/xmlrpc.php",
        )
        tested = 0
        for path in paths:
            for method in ("OPTIONS", "HEAD"):
                if tested >= max_cases or a.request_count >= a.limit:
                    return tested
                status, body, meta = a.request(path, method, include_credentials=False)
                if status in (401, 403):
                    state = "access-denied"
                elif status in (405, 501):
                    state = "method-not-supported"
                elif status is None:
                    state = "not-evaluated"
                elif status and status >= 500:
                    state = "server-error/requires-review"
                else:
                    state = "response-observed"
                allow = meta.get("Allow", "") or meta.get("allow", "")
                if allow:
                    tokens = re.findall(r"\b(?:GET|HEAD|OPTIONS|POST|PUT|PATCH|DELETE)\b", allow.upper())
                    if tokens:
                        state += "; Allow=" + ",".join(sorted(set(tokens)))
                a.add("HTTP method " + method, path, status, detail=state, visibility=state)
                tested += 1
        return tested

    def probe_discovered(self, max_cases=15):
        """Immediately verify fresh same-origin URLs recorded during crawl."""
        a = self.a
        audited = set(getattr(a, "requested_urls", ()))
        count = 0
        for url in sorted(a.wordlist):
            if count >= max_cases or a.request_count >= a.limit:
                break
            # Don't request URLs containing sensitive or mutation-ish paths.
            path = urllib.parse.urlsplit(url).path
            if not safe_candidate(a, path) or url in audited:
                continue
            status, body, _ = a.request(path, include_credentials=False)
            self.completed += 1
            if status in (401, 403):
                label = "auth-required"
            elif status in (301, 302, 303, 307, 308):
                label = "redirect"
            elif status == 200 and LOGIN_MARKER.search(body):
                label = "login-page"
            elif status == 200 and ERROR_MARKER.search(body):
                label = "soft-404"
            elif status and status >= 500:
                label = "server-error/requires-review"
            else:
                label = "response-observed"
            a.add("discovered URL check", path, status, detail=label, visibility=label)
            count += 1
        return count


def ssrf_oast_probe(auditor, endpoint, parameter, collaborator, method="GET", action=None):
    """One explicit same-origin OAST injection. Never request the collaborator directly."""
    if method not in ("GET", "POST"):
        raise ValueError("SSRF method must be GET or POST")
    if not safe_candidate(auditor, endpoint):
        raise ValueError("SSRF endpoint must be a safe same-origin path without query")
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,80}", parameter or ""):
        raise ValueError("invalid SSRF parameter")
    c = urllib.parse.urlsplit(collaborator)
    if c.scheme != "https" or not c.hostname or c.username or c.password or c.fragment:
        raise ValueError("Collaborator URL must be an absolute HTTPS URL without credentials")
    if not re.fullmatch(r"[A-Za-z0-9.-]+", c.hostname) or "." not in c.hostname:
        raise ValueError("invalid Collaborator host")
    try:
        ipaddress.ip_address(c.hostname)
    except ValueError:
        pass
    else:
        raise ValueError("Collaborator must be a DNS hostname, not an IP address")
    if c.hostname.endswith((".local", ".localhost", ".internal", ".test")):
        raise ValueError("Collaborator must not be an internal hostname")
    if action and not re.fullmatch(r"[A-Za-z0-9_-]{1,80}", action):
        raise ValueError("invalid action")
    pairs = {parameter: collaborator}
    if action:
        pairs["action"] = action
    body = urllib.parse.urlencode(pairs).encode()
    if method == "GET":
        path = endpoint + "?" + body.decode()
        status, _, _ = auditor.request(path)
    else:
        path = endpoint
        status, _, _ = auditor.request(
            path, "POST", body, {"Content-Type": "application/x-www-form-urlencoded"})
    auditor.add("opt-in SSRF OAST injection", endpoint, status,
                detail="Callback must be verified separately in Collaborator; not confirmed SSRF",
                visibility="requires-oast-correlation")
    return status
