"""Bounded, read-only discovery of the real WordPress content topology.

This module follows only same-origin public evidence: robots/sitemaps, REST
collection metadata and URLs embedded in already-fetched HTML/JavaScript.  It
does not guess object IDs, fetch drafts, or execute application actions.
"""
from __future__ import annotations

import html
import json
import re
import urllib.parse
import xml.etree.ElementTree as ET

WP_DISCOVERY = "https://developer.wordpress.org/rest-api/using-the-rest-api/discovery/"
WP_PAGINATION = "https://developer.wordpress.org/rest-api/using-the-rest-api/pagination/"
WP_CUSTOM_TYPES = (
    "https://developer.wordpress.org/rest-api/extending-the-rest-api/"
    "adding-rest-api-support-for-custom-content-types/"
)
WP_SITEMAPS = "https://developer.wordpress.org/reference/classes/wp_sitemaps_index/get_index_url/"

QUOTED_URL = re.compile(
    r"""(?P<quote>['"])(?P<url>https?://[^'"<>\s]{1,500}|/[^'"<>\s]{1,400})(?P=quote)""",
    re.I,
)
ATTR_URL = re.compile(
    r"""(?:href|src|action|data-url|data-src)\s*=\s*['"]([^'"]+)['"]""", re.I)
LINK_URL = re.compile(r"<([^>]+)>\s*;[^,]*\brel\s*=\s*['\"]?([^,'\";\s]+)", re.I)


def _header(headers, name):
    wanted = name.lower()
    for key, value in (headers or {}).items():
        if key.lower() == wanted:
            return value
    return ""


def _document_url(page_url, raw):
    """Resolve an application-owned link using browser URL semantics."""
    raw = html.unescape(raw.strip())
    joined = urllib.parse.urljoin(page_url, raw)
    parsed = urllib.parse.urlsplit(joined)
    return urllib.parse.urlunsplit(
        (parsed.scheme, parsed.netloc, parsed.path or "/", parsed.query, ""))


def _safe_public_url(auditor, url):
    from .probes import safe_candidate

    if not auditor._allowed(url):
        return None
    parsed = urllib.parse.urlsplit(url)
    # robots/CSS/JavaScript often contain quoted wildcard patterns such as
    # /wp-admin/*; those are rules, not fetchable application URLs.
    if any(char in (parsed.path or "") for char in "*[]{}|"):
        return None
    # The persistent topology contains path-only URLs. Query values may hold
    # tokens or search terms and are unnecessary for permalink verification.
    clean = urllib.parse.urlunsplit(
        (parsed.scheme, parsed.netloc, parsed.path or "/", "", ""))
    return clean if safe_candidate(auditor, parsed.path or "/") else None


def discover_text_urls(auditor, text, page_url, source, include_attributes=True):
    """Record safe same-origin paths visible in HTML, inline data or JS."""
    found = set()
    raw_values = []
    if include_attributes:
        raw_values.extend(ATTR_URL.findall(text))
    raw_values.extend(match.group("url") for match in QUOTED_URL.finditer(text))
    for raw in raw_values[:2000]:
        if raw.startswith(("#", "mailto:", "tel:", "javascript:", "data:")):
            continue
        candidate = _safe_public_url(auditor, _document_url(page_url, raw))
        if not candidate:
            continue
        auditor._wordlist_url(candidate, source=source)
        found.add(candidate)
    return found


def discover_header_urls(auditor, headers, source):
    """Use RFC Link advertisements, including WordPress api.w.org discovery."""
    found = set()
    for raw, relation in LINK_URL.findall(_header(headers, "Link")):
        if relation not in ("https://api.w.org/", "alternate", "canonical"):
            continue
        candidate = _safe_public_url(auditor, _document_url(auditor.base + "/", raw))
        if candidate:
            auditor._wordlist_url(candidate, source=source + ":link-header")
            found.add(candidate)
    return found


def _parse_sitemap(body):
    try:
        root = ET.fromstring(body)
    except (ET.ParseError, ValueError):
        return "invalid", []
    kind = root.tag.rsplit("}", 1)[-1].lower()
    urls = []
    for element in root.iter():
        if element.tag.rsplit("}", 1)[-1].lower() == "loc" and element.text:
            urls.append(element.text.strip())
    return kind, urls


def _sitemaps(auditor, max_documents=6, max_urls=500):
    pending = [
        # robots.txt is an origin-level convention; also check the configured
        # WP mount because subdirectory installations may expose a virtual one.
        urllib.parse.urljoin(auditor.base, "/robots.txt"),
        auditor.resolve_url("/robots.txt"),
        auditor.resolve_url("/wp-sitemap.xml"),
        auditor.resolve_url("/sitemap.xml"),
        auditor.resolve_url("/sitemap_index.xml"),
    ]
    seen = set()
    discovered = 0
    documents = 0
    while pending and documents < max_documents and auditor.request_count < auditor.limit:
        url = pending.pop(0)
        if url in seen or not auditor._allowed(url):
            continue
        seen.add(url)
        status, body, _ = auditor.request(url, include_credentials=False)
        path = urllib.parse.urlsplit(url).path
        if path.endswith("robots.txt"):
            if status == 200:
                hinted = []
                for match in re.findall(rb"(?im)^\s*Sitemap\s*:\s*(\S+)", body):
                    sitemap = _document_url(url, match.decode("utf-8", "ignore"))
                    if auditor._allowed(sitemap) and sitemap not in seen:
                        hinted.append(sitemap)
                pending[:0] = [item for item in hinted if item not in pending]
            auditor.add("WP topology robots sitemap hints", url, status,
                        detail="same-origin Sitemap directives parsed")
            continue
        documents += 1
        kind, locations = _parse_sitemap(body) if status == 200 else ("unavailable", [])
        auditor.add("WP topology sitemap document", url, status,
                    detail=f"{kind}; {min(len(locations), max_urls)} loc entries inspected",
                    reference=WP_SITEMAPS)
        child_sitemaps = []
        for raw in locations:
            if discovered >= max_urls:
                break
            candidate = _document_url(url, raw)
            if not auditor._allowed(candidate):
                continue
            if kind == "sitemapindex":
                if candidate not in seen and candidate not in pending:
                    child_sitemaps.append(candidate)
                continue
            safe = _safe_public_url(auditor, candidate)
            if safe:
                auditor._wordlist_url(safe, source="sitemap:" + path)
                discovered += 1
        pending[:0] = child_sitemaps
    auditor.add("WP topology sitemap URL discovery", "/wp-sitemap.xml", None,
                visibility="observed",
                detail=f"{documents} sitemap documents parsed; {discovered} public URLs recorded",
                reference=WP_SITEMAPS)
    return discovered


def _json_object(body):
    try:
        value = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        return None
    return value


def _rest_path(namespace, rest_base, page, alternate=False):
    route = "/" + namespace.strip("/") + "/" + rest_base.strip("/")
    params = {
        "per_page": "20",
        "page": str(page),
        "_fields": "id,link,slug,status,parent,_links",
    }
    query = urllib.parse.urlencode(params, safe=",")
    if alternate:
        return "/?" + urllib.parse.urlencode(
            {"rest_route": route, **params}, safe="/,")
    return "/wp-json" + route + "?" + query


def _rest_collections(auditor, max_types=6, max_pages=8):
    types_path = "/wp-json/wp/v2/types"
    status, body, _ = auditor.request(types_path, include_credentials=False)
    alternate = False
    if status != 200 and auditor.request_count < auditor.limit:
        alt_path = "/?rest_route=/wp/v2/types"
        alt_status, alt_body, _ = auditor.request(alt_path, include_credentials=False)
        if alt_status == 200:
            status, body, types_path, alternate = alt_status, alt_body, alt_path, True
    types = _json_object(body)
    auditor.add("WP topology REST type registry", types_path, status,
                detail="public REST content-type metadata inspected",
                reference=WP_CUSTOM_TYPES)
    if not isinstance(types, dict):
        # The ordinary core phase already samples posts/pages/media. Without a
        # real type registry there is no evidence to justify spending more of
        # the shared budget on speculative collection endpoints.
        auditor.add("WP topology REST permalink discovery", types_path, None,
                    visibility="observed",
                    detail="type registry unavailable; no collection guessing performed",
                    reference=WP_CUSTOM_TYPES)
        return 0
    collections = []
    for slug, info in types.items():
        if not isinstance(slug, str) or not isinstance(info, dict):
            continue
        rest_base = info.get("rest_base") or slug
        namespace = info.get("rest_namespace") or "wp/v2"
        if info.get("viewable") is False:
            continue
        if (isinstance(rest_base, str) and isinstance(namespace, str) and
                re.fullmatch(r"[A-Za-z0-9_.-]{1,80}", rest_base) and
                re.fullmatch(r"[A-Za-z0-9_./-]{1,100}", namespace)):
            collections.append((slug, namespace, rest_base))
    if not collections:
        collections = [(name, "wp/v2", name) for name in ("posts", "pages", "media")]
    # Public post/page types first, then custom types. Attachments are useful but
    # lower priority when the request budget is tight.
    collections.sort(key=lambda item: ({"post": 0, "posts": 0, "page": 1,
                                        "pages": 1, "attachment": 9,
                                        "media": 9}.get(item[0], 3), item[0]))
    pages_used = 0
    discovered = 0
    for slug, namespace, rest_base in collections[:max_types]:
        page = 1
        while page <= 2 and pages_used < max_pages and auditor.request_count < auditor.limit:
            path = _rest_path(namespace, rest_base, page, alternate=alternate)
            item_status, item_body, headers = auditor.request(
                path, include_credentials=False)
            pages_used += 1
            payload = _json_object(item_body)
            objects = payload if isinstance(payload, list) else []
            for item in objects[:100]:
                if not isinstance(item, dict) or not isinstance(item.get("link"), str):
                    continue
                candidate = _safe_public_url(auditor, item["link"])
                if candidate:
                    auditor._wordlist_url(candidate, source="rest:" + slug)
                    discovered += 1
            auditor.add("WP topology REST collection " + slug, path, item_status,
                        detail=f"page {page}; {len(objects)} objects; public permalinks recorded",
                        reference=WP_PAGINATION)
            try:
                total_pages = int(_header(headers, "X-WP-TotalPages") or "1")
            except ValueError:
                total_pages = 1
            if item_status != 200 or page >= min(total_pages, 2):
                break
            page += 1
    auditor.add("WP topology REST permalink discovery", "/wp-json/wp/v2/types", None,
                visibility="observed",
                detail=f"{pages_used} collection pages inspected; {discovered} public permalinks recorded",
                reference=WP_CUSTOM_TYPES)
    return discovered


def discover_topology(auditor, max_sitemaps=6, max_rest_pages=8):
    """Discover unlinked public WordPress objects within a strict request cap."""
    before = len(auditor.wordlist)
    auditor.add("WP topology installation-root routing", "/", None,
                visibility="observed",
                detail="scanner-owned probes resolved under " +
                       (auditor.wp_root_path or "/"),
                reference=WP_DISCOVERY)
    sitemap_count = _sitemaps(auditor, max_documents=max_sitemaps)
    rest_count = _rest_collections(auditor, max_pages=max_rest_pages)
    return {
        "sitemap_urls": sitemap_count,
        "rest_urls": rest_count,
        "new_urls": len(auditor.wordlist) - before,
    }
