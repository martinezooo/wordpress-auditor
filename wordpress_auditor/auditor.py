from __future__ import annotations
import csv, io, json, re, urllib.parse, urllib.request, urllib.error, xmlrpc.client
from dataclasses import dataclass, asdict
from html.parser import HTMLParser

@dataclass
class Result:
    name: str
    url: str
    status: int | None
    visibility: str
    detail: str = ""

class Auditor:
    def __init__(self, url, headers=None, cookies=None, proxy=None, timeout=8, limit=30):
        self.base = url.rstrip("/")
        p = urllib.parse.urlsplit(self.base)
        if p.scheme not in ("http", "https") or not p.netloc:
            raise ValueError("url must be an absolute http(s) URL")
        self.origin = (p.scheme, p.netloc)
        self.headers = dict(headers or {})
        if cookies:
            self.headers["Cookie"] = cookies if isinstance(cookies, str) else "; ".join(f"{k}={v}" for k,v in cookies.items())
        self.timeout, self.limit, self.results = timeout, limit, []
        self.authenticated = any(k.lower() in ("authorization", "cookie") for k in self.headers)
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({"http": proxy, "https": proxy} if proxy else {}))

    def _allowed(self, target):
        p = urllib.parse.urlsplit(urllib.parse.urljoin(self.base + "/", target))
        return (p.scheme, p.netloc) == self.origin

    def request(self, path, method="GET", data=None, headers=None):
        url = urllib.parse.urljoin(self.base + "/", path.lstrip("/"))
        if not self._allowed(url): raise ValueError("refusing cross-origin request")
        req = urllib.request.Request(url, data=data, method=method, headers={**self.headers, **(headers or {})})
        try:
            with self.opener.open(req, timeout=self.timeout) as r:
                return r.status, r.read(512 * 1024), dict(r.headers)
        except urllib.error.HTTPError as e:
            return e.code, e.read(64 * 1024), dict(e.headers)
        except Exception as e:
            return None, b"", {"error": str(e)}

    def add(self, name, path, status, body=b"", detail=""):
        text = body.decode("utf-8", "replace")
        visibility = ("authenticated" if self.authenticated else "public") if status and 200 <= status < 300 else ("forbidden" if status == 403 else "unavailable")
        snippet = detail or text[:160].replace("\n"," ")
        snippet = re.sub(r"(?i)(authorization|cookie|set-cookie|token|secret|password)\s*[:=]\s*\S+", r"\1=[REDACTED]", snippet)
        self.results.append(Result(name, urllib.parse.urljoin(self.base+"/", path), status, visibility, snippet))

    def discover(self, marker=None, post_comment=False, comment_name="Auditor", comment_email="auditor@example.invalid"):
        paths = ["/wp-json/", "/wp-json/wp/v2/posts?per_page=1", "/wp-json/wp/v2/comments?per_page=1",
                 "/wp-json/wc/v3/products?per_page=1", "/wp-json/wc/v3/reviews?per_page=1", "/?feed=rss2"]
        for path in paths[:self.limit]:
            s,b,_ = self.request(path); self.add(path.split("?")[0], path, s, b)
            if marker and marker.lower().encode() in b.lower(): self.results[-1].detail += " marker-found"
        self.xmlrpc()
        if marker: self.search_html(marker)
        if post_comment:
            payload = json.dumps({"author": comment_name, "author_email": comment_email, "content": marker or "wordpress-auditor benign marker", "post": 1}).encode()
            s,b,_ = self.request("/wp-json/wp/v2/comments", "POST", payload, {"Content-Type":"application/json"})
            self.add("opt-in comment POST", "/wp-json/wp/v2/comments", s, b, "explicitly opted-in; follow-up read-back attempted")
            if s and 200 <= s < 300:
                self.request("/wp-json/wp/v2/comments?search="+urllib.parse.quote(marker or comment_name))
        return self.results

    def search_html(self, marker):
        s,b,_ = self.request("/")
        self.add("HTML marker search", "/", s, b, "marker-found" if marker.lower().encode() in b.lower() else "marker-not-found")

    def xmlrpc(self):
        path="/xmlrpc.php"; s,b,_=self.request(path)
        self.add("XML-RPC endpoint", path, s, b)
        if s and 200 <= s < 300:
            body = b"<?xml version='1.0'?><methodCall><methodName>system.listMethods</methodName><params/></methodCall>"
            xs,xb,_=self.request(path, "POST", body, {"Content-Type":"text/xml"})
            self.add("XML-RPC system.listMethods", path, xs, xb, "read-only")
            unknown=b"<?xml version='1.0'?><methodCall><methodName>system.__wordpress_auditor_unknown__</methodName><params/></methodCall>"
            us,ub,_=self.request(path, "POST", unknown, {"Content-Type":"text/xml"})
            self.add("XML-RPC unknown method diagnostic", path, us, ub, "diagnostic only; no auth or pingback")

    def compare_403(self, path):
        a,_,_=self.request(path); b,_,_=self.request(path, headers={"X-Original-URL": path})
        classification = "no bypass" if a == b or (a != 403 and b != 200) else "difference requires review"
        return {"path": path, "baseline": a, "comparison": b, "classification": classification}

def parse_burp(raw):
    head, _, body = raw.partition("\r\n\r\n")
    lines=head.splitlines(); first=lines[0].split()
    if len(first)<2 or first[0] not in ("GET","POST","PUT","PATCH","DELETE","HEAD","OPTIONS"): raise ValueError("invalid Burp request")
    headers={}
    for line in lines[1:]:
        if ":" in line:
            k,v=line.split(":",1); headers[k.strip()]=v.strip()
    host=headers.get("Host")
    if not host: raise ValueError("Burp request requires Host")
    scheme="https" if headers.get("X-Forwarded-Proto")=="https" else "http"
    return scheme+"://"+host+first[1], headers, body.encode()
