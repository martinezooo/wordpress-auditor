from __future__ import annotations

import html
import json
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


@dataclass
class Result:
    name: str
    url: str
    status: int | None
    visibility: str
    detail: str = ""


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def sanitize_detail(value: str) -> str:
    value = SENSITIVE.sub(r"\1=[REDACTED]", value)
    value = re.sub(r"(?i)(https?://)[^\s\"'<>]+", r"\1[REDACTED-URL]", value)
    return value[:240]


def safe_url(base: str, target: str) -> str:
    joined = urllib.parse.urljoin(base.rstrip("/") + "/", target)
    p = urllib.parse.urlsplit(joined)
    # Fragments are never sent and query values are deliberately not disclosed in reports.
    path = urllib.parse.quote(urllib.parse.unquote(p.path or "/"), safe="/:@-._~!$&'()*+,;=%")
    return urllib.parse.urlunsplit((p.scheme, p.netloc, path, p.query, ""))


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
        self.opener = urllib.request.build_opener(
            _NoRedirect,
            urllib.request.ProxyHandler({"http": proxy, "https": proxy} if proxy else {}),
        )

    def _allowed(self, target):
        p = urllib.parse.urlsplit(urllib.parse.urljoin(self.base + "/", target))
        return (
            p.scheme.lower(), p.hostname.lower() if p.hostname else "", p.port or (443 if p.scheme == "https" else 80)
        ) == self.origin and p.scheme.lower() == self.origin[0]

    def request(self, path, method="GET", data=None, headers=None):
        if self.request_count >= self.limit:
            return None, b"", {"error": "request budget exhausted"}
        url = safe_url(self.base, path)
        if not self._allowed(url):
            raise ValueError("refusing cross-origin or scheme-changing request")
        self.request_count += 1
        if self.delay:
            time.sleep(self.delay)
        req_headers = {**self.headers, **(headers or {})}
        # Credentials are only sent when explicitly authorized.
        if not self.authorized:
            req_headers = {k: v for k, v in req_headers.items()
                           if k.lower() not in ("authorization", "cookie", "proxy-authorization")}
        req = urllib.request.Request(url, data=data, method=method, headers=req_headers)
        try:
            with self.opener.open(req, timeout=self.timeout) as r:
                return r.status, r.read(512 * 1024), dict(r.headers)
        except urllib.error.HTTPError as e:
            return e.code, e.read(64 * 1024), dict(e.headers)
        except Exception as e:
            return None, b"", {"error": type(e).__name__}

    def add(self, name, path, status, body=b"", detail="", visibility=None):
        if visibility:
            pass
        elif status and 200 <= status < 300:
            visibility = "authenticated" if self.authorized else "public"
        elif status == 403:
            visibility = "forbidden"
        elif status == 202:
            visibility = "moderated"
        else:
            visibility = "unavailable"
        # Response bodies are never copied into reports.
        snippet = sanitize_detail(detail)
        self.results.append(Result(name, report_url(safe_url(self.base, path)), status, visibility or "unavailable", snippet))

    def discover(
        self, marker=None, post_comment=False, comment_name="Auditor",
        comment_email="auditor@example.invalid", post_id=1, depth=1, full=False,
        xmlrpc=False, search_comment=False,
    ):
        paths = [
            "/wp-json/", "/wp-json/wp/v2/posts?per_page=1", "/wp-json/wp/v2/comments?per_page=1",
            "/wp-json/wc/v3/products?per_page=1", "/wp-json/wc/v3/reviews?per_page=1",
            "/?feed=rss2", "/feed/",
        ]
        if full or depth > 1:
            paths += ["/wp-json/wp/v2/pages?per_page=1", "/wp-json/wc/v3/orders?per_page=1"]
        for path in paths:
            if self.request_count >= self.limit:
                break
            s, b, _ = self.request(path)
            self.add(path.split("?")[0], path, s, b)
            if marker and marker.lower().encode() in b.lower():
                self.results[-1].detail = sanitize_detail(self.results[-1].detail + " marker-found")
        if xmlrpc and self.request_count < self.limit:
            self.xmlrpc()
        if marker and self.request_count < self.limit:
            self.search_html(marker)
        if post_comment and self.request_count < self.limit:
            self.comment(post_id, marker or "wordpress-auditor benign marker", comment_name, comment_email,
                         search_comment)
        return self.results

    def search_html(self, marker):
        s, b, _ = self.request("/")
        self.add("HTML marker search", "/", s, b, "marker-found" if marker.lower().encode() in b.lower() else "marker-not-found")

    def xmlrpc(self):
        path = "/xmlrpc.php"
        s, b, _ = self.request(path)
        self.add("XML-RPC endpoint", path, s, b)
        if s in (200, 405) and self.request_count < self.limit:
            body = b"<?xml version='1.0'?><methodCall><methodName>system.listMethods</methodName><params/></methodCall>"
            xs, xb, _ = self.request(path, "POST", body, {"Content-Type": "text/xml"})
            detail = parse_xmlrpc_response(xb) if xb else "read-only"
            self.add("XML-RPC system.listMethods", path, xs, b"", detail)

    def comment(self, post_id, content, name, email, search):
        payload = json.dumps({"author": name, "author_email": email, "content": content, "post": int(post_id)}).encode()
        path = "/wp-json/wp/v2/comments"
        s, b, _ = self.request(path, "POST", payload, {"Content-Type": "application/json"})
        self.add("opt-in comment POST", path, s, b, "explicitly opted-in; read-back classified")
        if not (s and 200 <= s < 300) or self.request_count >= self.limit:
            return
        query = "?post=" + urllib.parse.quote(str(post_id))
        if search:
            query += "&search=" + urllib.parse.quote(content)
        rs, rb, _ = self.request(path + query)
        found = content.lower().encode() in rb.lower()
        if rs == 200 and found:
            classification = "authenticated" if self.authorized else "public"
        elif rs in (200, 202) and not found:
            classification = "moderated"
        else:
            classification = "unavailable"
        self.add("comment read-back", path + query, rs, b"", classification, visibility=classification)

    def compare_403(self, path):
        a, _, _ = self.request(path)
        b, _, _ = self.request(path, headers={"X-Original-URL": path})
        if a == 403 and b == 200:
            classification = "difference requires review (not a bypass claim)"
        else:
            classification = "inconclusive"
        return {"path": report_url(safe_url(self.base, path)), "baseline": a, "comparison": b, "classification": classification}


def parse_xmlrpc_response(raw):
    try:
        if re.search(rb"<!DOCTYPE|<!ENTITY", raw, re.I):
            return "rejected unsafe XML"
        root = ET.fromstring(raw)
        fault = root.find("fault")
        if fault is not None:
            return "XML-RPC fault"
        return "read-only response parsed"
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
    return f"{scheme}://{host}{first[1]}", headers, body.encode()
