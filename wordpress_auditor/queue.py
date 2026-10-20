"""Resume-safe, origin-bound queue of discovered safe GET URLs.

Never stores headers, cookies, request bodies, query strings or response bodies.
Only GET targets with real HTTP responses are marked verified. Previously
unverified paths are prioritized in subsequent runs, not repeatedly eclipsed by
alphabetically earlier discoveries.
"""
from __future__ import annotations

import json
import os
from urllib.parse import urlsplit

from .auditor import report_url
from .probes import safe_candidate


def _origin(auditor):
    parsed = urlsplit(auditor.base)
    return parsed.scheme + "://" + parsed.netloc


def _valid(auditor, url):
    if not isinstance(url, str) or len(url) > 500 or not auditor._allowed(url):
        return None
    parsed = urlsplit(url)
    path = parsed.path or "/"
    if parsed.query or parsed.fragment or not safe_candidate(auditor, path):
        return None
    return report_url(url)


def load_previous(auditor, path):
    """Load only same-origin, path-only entries from a bounded local JSON file."""
    auditor.prior_verified_urls = set()
    if not os.path.isfile(path):
        return 0
    try:
        if os.path.getsize(path) > 1024 * 1024:
            return 0
        with open(path, encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, UnicodeError, ValueError):
        return 0
    if not isinstance(data, dict) or data.get("origin") != _origin(auditor):
        return 0
    previous = data.get("verified_urls", [])
    if not isinstance(previous, list):
        return 0
    for url in previous[:10_000]:
        accepted = _valid(auditor, url)
        if accepted:
            auditor.prior_verified_urls.add(accepted)
    return len(auditor.prior_verified_urls)


def save(auditor, path):
    """Commit a safe queue snapshot. Atomic replacement avoids truncated files."""
    discovered = set(auditor.wordlist)
    new_checks = getattr(auditor, "successful_get_urls", set())
    previously = getattr(auditor, "prior_verified_urls", set())
    checked = {url for url in discovered if url in new_checks or url in previously}
    pending = sorted(url for url in discovered if url not in checked)
    payload = {
        "version": 1,
        "origin": _origin(auditor),
        "checked_count": len(checked),
        "pending_count": len(pending),
        "verified_urls": sorted(checked)[:10_000],
        "pending_urls": pending[:10_000],
        "note": "Verified means a real HTTP response was received for a GET, not that the path is secure.",
    }
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    tmp = path + ".tmp"
    try:
        with open(tmp, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, ensure_ascii=False, indent=2)
        os.replace(tmp, path)
    finally:
        if os.path.isfile(tmp):
            os.unlink(tmp)
    auditor.queue_checked_count = len(checked)
    auditor.queue_pending_count = len(pending)
    return payload
