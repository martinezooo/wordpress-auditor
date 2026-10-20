from __future__ import annotations

import html
import json
import hashlib
import uuid
import re
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from dataclasses import dataclass


SENSITIVE = re.compile(
    r"(?i)(authorization|proxy-authorization|cookie|set-cookie|token|secret|password|api[_-]?key)"
    r"\s*[:=]\s*[^\s,;]+"
)
METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}
HOP_HEADERS = {
    "host", "content-length", "transfer-encoding", "connection",
    "accept-encoding", "proxy-authorization", "expect", "set-cookie",
    "proxy-connection", "keep-alive", "upgrade", "te", "trailer",
}
ACTION_RE = re.compile(r"^[A-Za-z0-9_-]{1,80}$")
ACTION_PATTERNS = (
    re.compile(r"""(?:action|data-action)\s*[:=]\s*['"]([A-Za-z0-9_-]{1,80})['"]""", re.I),
    re.compile(r"""(?:action|data-action)\s*=\s*['"]([A-Za-z0-9_-]{1,80})['"]""", re.I),
)


@dataclass
class Result:
    name: str
    url: str
    status: int | None
    visibility: str
    detail: str = ""
    severity: str = "INFO"
    confidence: str = "observed"


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def sanitize_detail(value: str) -> str:
    value = SENSITIVE.sub(r"\1=[REDACTED]", value)
    value = re.sub(r"(?i)(https?://)[^\s\"'<>]+", r"\1[REDACTED-URL]", value)
    return value[:240]


def safe_url(base: str, target: str) -> str:
    # RFC 3986 urljoin() canonicalizes literal /../ and /./ segments. Preserve
    # exactly those bytes when testing web-server route normalization behavior.
    if target.startswith("/") and not target.startswith("//"):
        origin = urllib.parse.urlsplit(base)
        raw = urllib.parse.urlsplit(target)
        return urllib.parse.urlunsplit(
            (origin.scheme, origin.netloc, raw.path or "/", raw.query, ""))
    joined = urllib.parse.urljoin(base.rstrip("/") + "/", target)
    p = urllib.parse.urlsplit(joined)
    return urllib.parse.urlunsplit((p.scheme, p.netloc, p.path or "/", p.query, ""))


def report_url(url: str) -> str:
    p = urllib.parse.urlsplit(url)
    return urllib.parse.urlunsplit((p.scheme, p.netloc, p.path or "/", "", ""))


class Auditor:
    def __init__(
        self, url, headers=None, cookies=None, proxy=None, timeout=8, limit=30,
        delay=0, authorized=False, scheme=None,
    ):
        self.base = url.rstrip("/")
        p = urllib.parse.urlsplit(self.base)
        if scheme:
            if scheme not in ("http", "https"):
                raise ValueError("scheme must be http or https")
            p = p._replace(scheme=scheme)
            self.base = urllib.parse.urlunsplit(p).rstrip("/")
        if p.scheme not in ("http", "https") or not p.netloc:
            raise ValueError("url must be an absolute http(s) URL")
        if p.username or p.password or not p.hostname:
            raise ValueError("target URL must not contain embedded credentials")
        self.origin = (p.scheme.lower(), p.hostname.lower(), p.port or (443 if p.scheme == "https" else 80))
        self.headers = dict(headers or {})
        if cookies:
            self.headers["Cookie"] = cookies if isinstance(cookies, str) else "; ".join(
                f"{k}={v}" for k, v in cookies.items()
            )
        self.timeout, self.limit, self.delay = timeout, max(0, limit), max(0, delay)
        self.authorized = bool(authorized)
        self.results = []
        self.request_count = 0
        self.ajax_actions = set()
        self.wordlist = set()
        self.requested_urls = set()
        self.payload_cases = 0
        self.discovered_checks = 0
        self.method_checks = 0
        self.phase_stats = []
        self.progress_callback = None
        self.request_progress_callback = None
        self.finding_callback = None
        self.scan_mode = "quick"
        self.payload_candidates = 0
        self.opener = urllib.request.build_opener(
            _NoRedirect,
            urllib.request.ProxyHandler({"http": proxy, "https": proxy} if proxy else {}),
        )

    def _allowed(self, target):
        p = urllib.parse.urlsplit(urllib.parse.urljoin(self.base + "/", target))
        return (
            p.scheme.lower(), p.hostname.lower() if p.hostname else "", p.port or (443 if p.scheme == "https" else 80)
        ) == self.origin and p.scheme.lower() == self.origin[0]

    def request(self, path, method="GET", data=None, headers=None,
                include_credentials=None, test_headers=False):
        if self.request_count >= self.limit:
            return None, b"", {"error": "request budget exhausted"}
        url = safe_url(self.base, path)
        if not self._allowed(url):
            raise ValueError("refusing cross-origin or scheme-changing request")
        self.request_count += 1
        self.requested_urls.add(report_url(url))
        if self.delay:
            time.sleep(self.delay)
        req_headers = {**self.headers, **(headers or {})}
        req_headers = {k: v for k, v in req_headers.items()
                       if k.lower() not in HOP_HEADERS and
                       (not k.lower().startswith("x-forwarded-")
                        or (test_headers and k.lower() in
                            {"x-forwarded-for", "x-forwarded-uri"}))}
        # Credentials are only sent when explicitly authorized.
        if include_credentials is False or not self.authorized:
            req_headers = {k: v for k, v in req_headers.items()
                           if k.lower() not in ("authorization", "cookie", "proxy-authorization")}
        req = urllib.request.Request(url, data=data, method=method, headers=req_headers)
        try:
            with self.opener.open(req, timeout=self.timeout) as r:
                return r.status, r.read(512 * 1024), dict(r.headers)
        except urllib.error.HTTPError as e:
            try:
                return e.code, e.read(64 * 1024), dict(e.headers)
            finally:
                e.close()
        except Exception as e:
            return None, b"", {"error": type(e).__name__}
        finally:
            if self.request_progress_callback:
                self.request_progress_callback(self, method, report_url(url))

    def add(self, name, path, status, body=b"", detail="", visibility=None):
        if visibility:
            pass
        elif status in (401, 403):
            visibility = "auth-required"
        elif status in (301, 302, 303, 307, 308):
            visibility = "redirect"
        elif status is not None and 200 <= status < 300:
            visibility = "response-observed"
        elif status is not None and status >= 500:
            visibility = "server-error"
        else:
            visibility = "not-evaluated"
        # Response bodies are never copied into reports.
        snippet = sanitize_detail(detail)
        from .assessment import assess
        severity, confidence = assess(name, status, visibility or "unavailable", snippet)
        result = Result(name, report_url(safe_url(self.base, path)),
                        status, visibility or "unavailable", snippet,
                        severity, confidence)
        self.results.append(result)
        if self.finding_callback:
            self.finding_callback(self, result)

    def _wordlist_url(self, url):
        if self._allowed(url):
            self.wordlist.add(report_url(safe_url(self.base, url)))

    @staticmethod
    def extract_ajax_actions(text):
        actions = set()
        contextual = bool(re.search(r"\b(?:admin-ajax|ajaxurl|wp_ajax|wpApiSettings)\b", text, re.I))
        for pattern in ACTION_PATTERNS:
            for match in pattern.finditer(text):
                if "data-action" in match.group(0).lower() or contextual:
                    actions.add(match.group(1))
        if contextual:
            actions.update(re.findall(r"""\baction\s*=\s*['"]([A-Za-z0-9_-]{1,80})['"]""", text, re.I))
        return {a for a in actions if ACTION_RE.fullmatch(a)}

    @staticmethod
    def _is_login_or_nonce(body):
        return bool(re.search(rb"wp-login|loginform|name=['\"]log['\"]|nonce|_wpnonce", body, re.I))

    def discover_ajax(self, probe=False, page_cap=4, asset_cap=8):
        pending, pages, assets = ["/"], set(), set()
        while pending and len(pages) < page_cap and self.request_count < self.limit:
            path = pending.pop(0)
            if path in pages or not self._allowed(path):
                continue
            pages.add(path)
            status, body, _ = self.request(path)
            if status != 200:
                continue
            text = body.decode("utf-8", "ignore")
            self._wordlist_url(path)
            self.ajax_actions.update(self.extract_ajax_actions(text))
            for raw in re.findall(r"""(?:href|src|action)\s*=\s*['"]([^'"]+)['"]""", text, re.I):
                target = safe_url(self.base, html.unescape(raw))
                if not self._allowed(target):
                    continue
                parsed = urllib.parse.urlsplit(target)
                clean = urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", "", ""))
                self._wordlist_url(clean)
                if parsed.path.endswith(".js") and len(assets) < asset_cap:
                    assets.add(clean)
                elif not parsed.path.rsplit("/", 1)[-1].count(".") and len(pending) < page_cap:
                    pending.append(clean)
            for raw in re.findall(r"""<input[^>]+name\s*=\s*['"]action['"][^>]+value\s*=\s*['"]([^'"]+)['"]""", text, re.I):
                if ACTION_RE.fullmatch(raw) and re.search(r"admin-ajax|ajaxurl|wp_ajax", text, re.I):
                    self.ajax_actions.add(raw)
            for raw in re.findall(r"""(?:data-action|action)\s*=\s*['"]([A-Za-z0-9_-]{1,80})['"]""", text, re.I):
                if re.search(r"admin-ajax|ajaxurl|wp_ajax|data-action", text, re.I):
                    self.ajax_actions.add(raw)
            for raw in re.findall(r"""<(?:loc|url)\b[^>]*>([^<]+)""", text, re.I):
                target = safe_url(self.base, html.unescape(raw.strip()))
                if self._allowed(target):
                    self._wordlist_url(target)
            for extra in ("/wp-json/", "/wp-sitemap.xml", "/sitemap.xml"):
                if len(pages) < page_cap and extra not in pages and extra not in pending:
                    pending.append(extra)
        for asset in list(assets):
            if self.request_count >= self.limit:
                break
            status, body, _ = self.request(asset)
            if status == 200:
                self.ajax_actions.update(self.extract_ajax_actions(body.decode("utf-8", "ignore")))
                self._wordlist_url(asset)
        endpoint = "/wp-admin/admin-ajax.php"
        if probe and self.ajax_actions and self.request_count < self.limit:
            baseline_status, baseline, _ = self.request(endpoint)
            for action in sorted(self.ajax_actions):
                if self.request_count >= self.limit:
                    break
                path = endpoint + "?action=" + urllib.parse.quote(action, safe="")
                status, body, _ = self.request(path, include_credentials=False)
                self._wordlist_url(endpoint)
                if status in (401, 403) or self._is_login_or_nonce(body):
                    state = "auth-required/requires-review"
                elif status == baseline_status and hashlib.sha256(body).digest() == hashlib.sha256(baseline).digest():
                    state = "response-observed (baseline-equivalent)"
                elif status in (301, 302, 303, 307, 308):
                    state = "redirect/requires-review"
                else:
                    state = "response-observed/requires-review"
                self.add("AJAX action " + action, path, status, detail=state, visibility="response-observed")
        return sorted(self.ajax_actions)

    def _phase(self, title, function, enabled=True, reason="not enabled"):
        """Run a named scan phase and retain actual work/skip reasons."""
        before_requests = self.request_count
        before_checks = len(self.results)
        if not enabled:
            phase = {"name": title, "requests": 0, "checks": 0,
                     "state": "skipped", "reason": reason}
            self.phase_stats.append(phase)
            return
        if self.request_count >= self.limit:
            phase = {"name": title, "requests": 0, "checks": 0,
                     "state": "skipped", "reason": "request budget exhausted"}
            self.phase_stats.append(phase)
            return
        if self.progress_callback:
            self.progress_callback("start", title, self)
        try:
            function()
        finally:
            count = self.request_count - before_requests
            phase = {"name": title, "requests": count,
                     "checks": len(self.results) - before_checks,
                     "state": "done" if count else "no-requests",
                     "reason": "" if count else "no eligible candidates"}
            self.phase_stats.append(phase)
            if self.progress_callback:
                self.progress_callback("done", title, self, phase)

    def discover(
        self, marker=None, post_comment=False, comment_name="Auditor",
        comment_email="auditor@example.invalid", post_id=1, depth=1, full=False,
        xmlrpc=False, search_comment=None, comment_mode="rest", languages=None,
        ajax_probe=False, no_ajax=False,
        payloads=None, payload_limit=30, probe_discovered=True, deep=False,
    ):
        self.scan_mode = "deep" if deep else "smart" if full else "quick"
        self.phase_stats = []
        if post_comment:
            self._phase("Explicit comment submission",
                        lambda: self.comment(
                            post_id, marker or ("wp-audit-" + uuid.uuid4().hex),
                            comment_name, comment_email, mode=comment_mode),
                        enabled=post_id is not None,
                        reason="valid --comment-post-id required")
        self._phase("XML-RPC protocol diagnostics", self.xmlrpc,
                    enabled=xmlrpc or full, reason="requires --xmlrpc or smart/full mode")

        def _access_control():
            if self.request_count + 3 > self.limit:
                return
            comparison = self.compare_403("/wp-admin/")
            self.add("403 differential /wp-admin/", "/wp-admin/", comparison["comparison"],
                     detail=comparison["classification"], visibility="requires-review"
                     if "requires review" in comparison["classification"] else "inconclusive")
        self._phase("Admin access-control comparison", _access_control, enabled=full,
                    reason="requires smart/full mode")

        self._phase("Comment/review marker search",
                    lambda: self.search_comment(search_comment, languages=languages),
                    enabled=bool(search_comment), reason="no search marker supplied")

        def _core():
            paths = [
                "/wp-json/", "/wp-json/wp/v2/posts?per_page=1",
                "/wp-json/wp/v2/comments?per_page=1",
                "/wp-json/wc/v3/products?per_page=1",
                "/wp-json/wc/v3/reviews?per_page=1",
                "/?feed=comments-rss2", "/comments/feed/",
            ]
            if full or depth > 1:
                paths += [
                    "/wp-json/wp/v2/", "/wp-json/wp/v2/pages?per_page=1",
                    "/wp-json/wp/v2/users?per_page=1", "/wp-json/wp/v2/types",
                    "/wp-json/wp/v2/taxonomies", "/wp-json/wp/v2/categories?per_page=1",
                    "/wp-json/wp/v2/media?per_page=1", "/wp-json/oembed/1.0/",
                    "/wp-json/wp/v2/settings", "/wp-json/wp/v2/users/me",
                    "/wp-json/wp/v2/plugins", "/?author=1",
                    "/wp-json/wc/store/v1/", "/wp-json/wc/store/v1/products?per_page=1",
                    "/wp-json/wc/v3/orders?per_page=1",
                    "/wp-json/wc/store/v1/products/reviews?per_page=1",
                    "/wp-admin/", "/wp-login.php", "/wp-admin/admin-ajax.php",
                    "/robots.txt", "/wp-sitemap.xml", "/sitemap_index.xml",
                    "/.well-known/security.txt",
                ]
            # Adaptive phase budget: leave room for crawl, methods and payloads.
            core_cap = len(paths) if not full else min(len(paths), max(6, self.limit // 5))
            for path in paths[:core_cap]:
                if self.request_count >= self.limit:
                    break
                s, b, _ = self.request(path)
                self.add(path.split("?")[0], path, s, b)
                if path == "/wp-json/" and s == 200:
                    # WP REST root can advertise routes discovered from plugins.
                    # Only concrete, GET-capable routes without path variables.
                    try:
                        index = json.loads(b.decode("utf-8"))
                    except (ValueError, UnicodeDecodeError):
                        index = {}
                    routes = index.get("routes", {}) if isinstance(index, dict) else {}
                    if isinstance(routes, dict):
                        from .probes import safe_candidate
                        for route, info in list(routes.items())[:400]:
                            if not isinstance(route, str) or not route.startswith("/"):
                                continue
                            if any(char in route for char in ("(", ")", "{", "}")):
                                continue
                            methods = (info or {}).get("methods", []) if isinstance(info, dict) else []
                            if "GET" not in methods and "HEAD" not in methods:
                                continue
                            candidate = "/wp-json" + route
                            if safe_candidate(self, candidate):
                                self._wordlist_url(candidate)
                if marker and marker.lower().encode() in b.lower():
                    self.results[-1].detail = sanitize_detail(
                        self.results[-1].detail + " marker-found")
        self._phase("WordPress/WooCommerce REST and public surfaces", _core)

        self._phase("HTML/JavaScript crawling and AJAX discovery",
                    lambda: self.discover_ajax(
                        probe=ajax_probe,
                        page_cap=min(30, max(1, depth) *
                                     (12 if deep else min(8, max(3, self.limit // 12))
                                      if full else 4)),
                        asset_cap=20 if deep else 12 if full else 8),
                    enabled=not no_ajax, reason="disabled by --no-ajax")
        from .probes import ProbeSuite
        suite = ProbeSuite(self, payloads=payloads)
        self.payload_candidates = len(suite.paths) + len(suite.headers)
        self._phase("HTTP HEAD/OPTIONS capability checks",
                    lambda: setattr(self, "method_checks",
                                    suite.method_negotiation(
                                        max_cases=min(12, max(2, self.limit // 12)))),
                    enabled=full, reason="requires smart/full mode")

        # Reserve some traffic for authorization comparisons, then crawl every
        # eligible discovered URL left within the user-selected request budget.
        def _discovered():
            reserved = min(payload_limit + 2, max(0, self.limit // 4))
            capacity = max(0, self.limit - self.request_count - reserved)
            self.discovered_checks = suite.probe_discovered(
                max_cases=min(300 if deep else 200 if full else 8, capacity))
        self._phase("New and previously discovered URL verification", _discovered,
                    enabled=probe_discovered, reason="disabled by --no-probe-discovered")

        def _artifacts():
            from .wp_checks import check_exposures
            check_exposures(self)
        self._phase("WordPress sensitive artifacts / debug logs", _artifacts,
                    enabled=full, reason="requires smart/full mode")

        self._phase("Path/header payload comparisons",
                    lambda: setattr(self, "payload_cases",
                                    suite.access_variants(
                                        max_cases=payload_limit if (deep or full)
                                        else min(payload_limit, 6))),
                    enabled=payload_limit > 0, reason="--payload-limit 0")
        return self.results

    @staticmethod
    def _comment_record_contains(data, needle):
        """Only match actual comment/review text, not arbitrary API metadata."""
        if isinstance(data, dict):
            data = data.get("comments", data.get("reviews", []))
        if not isinstance(data, list):
            return False
        for record in data:
            if not isinstance(record, dict):
                continue
            for key in ("content", "review", "comment"):
                value = record.get(key)
                if isinstance(value, dict):
                    value = value.get("rendered", value.get("raw", ""))
                if isinstance(value, str) and needle.casefold() in value.casefold():
                    return True
        return False

    def search_comment(self, term, languages=None):
        paths = [
            "/wp-json/wp/v2/comments?search=" + urllib.parse.quote(term, safe=""),
            "/wp-json/wc/store/v1/products/reviews?search=" + urllib.parse.quote(term, safe=""),
            "/?feed=comments-rss2", "/comments/feed/",
        ]
        for path in paths:
            if self.request_count >= self.limit:
                break
            s, b, _ = self.request(path)
            found = False
            try:
                found = s == 200 and self._comment_record_contains(json.loads(b.decode("utf-8")), term)
            except (UnicodeDecodeError, json.JSONDecodeError):
                found = s == 200 and bool(re.search(r"<(?:title|description|content:encoded)[^>]*>.*?" +
                                       re.escape(term), b.decode("utf-8", "ignore"), re.I | re.S))
            state = "found" if found else ("not-found" if s == 200 else
                                           ("auth-required" if s in (401, 403) else "not-evaluated"))
            self.add("comment search " + path.split("?")[0], path, s, detail=state, visibility=state)
        html_paths = ["/"]
        for language in (languages or []):
            language = language.strip().strip("/")
            if re.fullmatch(r"[A-Za-z]{2,3}(?:-[A-Za-z]{2,4})?", language):
                html_paths.append("/" + language + "/")
        for html_path in html_paths:
            if self.request_count >= self.limit:
                break
            s, b, _ = self.request(html_path)
            found = term.casefold() in b.decode("utf-8", "ignore").casefold() if s == 200 else False
            state = "observed-in-html" if found else ("not-observed" if s == 200 else
                    ("auth-required" if s in (401, 403) else "not-evaluated"))
            self.add("HTML marker search", html_path, s, detail=state, visibility=state)

    def xmlrpc(self):
        """Bounded, read-only XML-RPC diagnostic methods. No login, pingback or multicall."""
        path = "/xmlrpc.php"
        s, b, _ = self.request(path)
        self.add("XML-RPC endpoint", path, s, b, "GET diagnostic (405 is normal)")
        if s not in (200, 405):
            return
        probes = [
            ("system.listMethods", "system.listMethods", False),
            ("system.getCapabilities", "system.getCapabilities", False),
            ("unknown method fault", "wordpressAuditor.unknownReadOnlyMethod", False),
            ("malformed XML fault", "", True),
        ]
        for label, method, malformed in probes:
            if self.request_count >= self.limit:
                break
            if malformed:
                payload = b"<methodCall><methodName>incomplete"
            else:
                payload = ("<?xml version='1.0'?><methodCall><methodName>"
                           + method + "</methodName><params/></methodCall>").encode("utf-8")
            status, body, _ = self.request(path, "POST", payload, {"Content-Type": "text/xml"})
            detail = parse_xmlrpc_response(body) if body else "empty response"
            if status in (401, 403):
                detail = "blocked by access controls"
            self.add("XML-RPC " + label, path, status, detail=detail)

    def comment(self, post_id, content, name, email, mode="rest"):
        if isinstance(mode, bool):
            mode = "rest"
        if mode not in ("rest", "form"):
            raise ValueError("comment mode must be rest or form")
        if mode == "form":
            path = "/wp-comments-post.php"
            payload = urllib.parse.urlencode({"comment": content, "author": name,
                                               "email": email, "comment_post_ID": int(post_id)}).encode()
            headers = {"Content-Type": "application/x-www-form-urlencoded"}
        else:
            path = "/wp-json/wp/v2/comments"
            payload = json.dumps({"author": name, "author_email": email,
                                  "content": content, "post": int(post_id)}).encode()
            headers = {"Content-Type": "application/json"}
        s, b, h = self.request(path, "POST", payload, headers)
        detail = "submission attempted; publication unverified"
        if mode == "rest" and s in (200, 201):
            try:
                reported = json.loads(b.decode("utf-8"))
                if reported.get("status") in ("hold", "pending", "spam", "trash"):
                    detail += "; status=" + reported["status"]
            except (ValueError, AttributeError, UnicodeDecodeError):
                pass
        self.add("opt-in comment POST", path, s, b, detail)
        if not (s and (200 <= s < 300 or s in (301, 302, 303, 307, 308))) or self.request_count >= self.limit:
            return
        query = "/wp-json/wp/v2/comments?post=" + urllib.parse.quote(str(post_id))
        query += "&search=" + urllib.parse.quote(content, safe="")
        rs, rb, _ = self.request(query, include_credentials=False)
        try:
            found = rs == 200 and self._comment_record_contains(json.loads(rb.decode("utf-8")), content)
        except (UnicodeDecodeError, json.JSONDecodeError):
            found = False
        classification = "confirmed-public" if found else (
            "auth-required" if rs in (401, 403) else
            "not-publicly-observed" if rs == 200 else "not-evaluated")
        self.add("comment unauthenticated read-back", query, rs, detail=classification,
                 visibility=classification)
        if self.authorized and self.request_count < self.limit:
            ars, arb, _ = self.request(query)
            try:
                afound = ars == 200 and self._comment_record_contains(json.loads(arb.decode("utf-8")), content)
            except (UnicodeDecodeError, json.JSONDecodeError):
                afound = False
            state = "confirmed-authenticated" if afound else (
                "auth-required" if ars in (401, 403) else "not-observed")
            self.add("comment authenticated read-back", query, ars, detail=state, visibility=state)

    def compare_403(self, path):
        a, abody, aheaders = self.request(path)
        b, bbody, bheaders = self.request(path, headers={"X-Original-URL": path})
        control_path = "/.well-known/wp-auditor-control-" + hashlib.sha256(path.encode()).hexdigest()[:12]
        c, cbody, cheaders = self.request(control_path)
        same_content = hashlib.sha256(abody).digest() == hashlib.sha256(bbody).digest()
        aloc = aheaders.get("Location", "")
        bloc = bheaders.get("Location", "")
        cloc = cheaders.get("Location", "")
        redirects_match = bool(bloc) and (bloc == aloc or bloc == cloc)
        login_page = bool(re.search(rb"wp-login|name=['\"]log['\"]|id=['\"]loginform['\"]", bbody, re.I))
        if a == 403 and b == 200 and not same_content and not redirects_match and c != 200 and not login_page:
            classification = "difference requires review (not a bypass claim)"
        else:
            classification = "inconclusive"
        return {"path": report_url(safe_url(self.base, path)), "baseline": a,
                "comparison": b, "control": c, "classification": classification}


def parse_xmlrpc_response(raw):
    try:
        if re.search(rb"<!DOCTYPE|<!ENTITY", raw, re.I):
            return "rejected unsafe XML"
        root = ET.fromstring(raw)
        fault = root.find("./fault")
        if fault is not None:
            code = fault.findtext("./value/struct/member[name='faultCode']/value/int") or "unknown"
            return "XML-RPC fault code " + re.sub(r"[^0-9-]", "", code)[:12]
        names = [x.text for x in root.findall(".//array/data/value/string") if x.text]
        notable = [n for n in names if n in {
            "system.listMethods", "system.multicall", "pingback.ping",
            "wp.getComments", "wp.newComment", "wp.getUsers", "wp.getPosts",
        }]
        return "methods: " + ", ".join(notable[:5]) if notable else "read-only response parsed"
    except (ET.ParseError, ValueError):
        return "invalid XML-RPC response"


def parse_burp(raw, scheme="https"):
    if scheme not in ("http", "https"):
        raise ValueError("scheme must be http or https")
    if "\r\n\r\n" not in raw:
        raise ValueError("Burp request requires CRLF header/body separator")
    head, body = raw.split("\r\n\r\n", 1)
    lines = head.split("\r\n")
    if not lines or len(lines[0].split()) < 2:
        raise ValueError("invalid Burp request")
    first = lines[0].split()
    if first[0] not in METHODS or len(first) != 3 or first[2] != "HTTP/1.1":
        raise ValueError("invalid Burp request line")
    headers = {}
    for line in lines[1:]:
        if not line or line[0].isspace() or ":" not in line:
            raise ValueError("folded or malformed Burp header")
        k, v = line.split(":", 1)
        if not k or k.strip() != k or not re.fullmatch(r"[!#$%&'*+\-.^_`|~0-9A-Za-z]+", k) or k.lower() in headers:
            raise ValueError("duplicate or malformed Burp header")
        headers[k.lower()] = v.strip()
    host = headers.get("host")
    if not host or "/" in host or "@" in host:
        raise ValueError("Burp request requires safe Host")
    target = urllib.parse.urlsplit(first[1])
    if target.scheme or target.netloc:
        raise ValueError("Burp target must be origin-form")
    headers = {k: v for k, v in headers.items()
               if k not in HOP_HEADERS and not k.startswith("x-forwarded-")}
    return f"{scheme}://{host}{first[1]}", headers, b""
