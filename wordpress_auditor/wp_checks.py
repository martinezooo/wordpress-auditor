"""WordPress-specific, read-only checks for exposed configuration artifacts."""
from __future__ import annotations

import hashlib
import re

CHECKS = (
    ("/wp-config.php.bak", "config"),
    ("/wp-config.php~", "config"),
    ("/wp-config.php.save", "config"),
    ("/wp-config.php.old", "config"),
    ("/wp-content/debug.log", "debug"),
    ("/wp-content/uploads/", "listing"),
)
CONFIG_SIGNAL = re.compile(
    rb"(?:define\s*\(\s*['\"]DB_(?:PASSWORD|NAME|HOST)['\"]|"
    rb"['\"]AUTH_KEY['\"]|['\"]SECURE_AUTH_KEY['\"])", re.I,
)
DEBUG_SIGNAL = re.compile(
    rb"(?:PHP (?:Fatal error|Warning|Parse error|Notice)|"
    rb"WordPress database error|Uncaught (?:Error|Exception)|Stack trace:)",
    re.I,
)
LISTING_SIGNAL = re.compile(
    rb"<title>\s*Index of\s*/wp-content/uploads/?\s*</title>|"
    rb"<h1>\s*Index of\s*/wp-content/uploads/?\s*</h1>",
    re.I,
)

def check_exposures(auditor):
    """Require 200, WP-specific content and a nonmatching random-path response."""
    if auditor.request_count >= auditor.limit:
        return 0
    control_path = "/.well-known/wp-audit-exposure-control-85461"
    status, control_body, _ = auditor.request(control_path, include_credentials=False)
    control_hash = hashlib.sha256(control_body).digest()
    auditor.add("WP exposure control", control_path, status,
                detail="random-path baseline only")
    count = 0
    for path, kind in CHECKS:
        if auditor.request_count >= auditor.limit:
            break
        status, body, _ = auditor.request(path, include_credentials=False)
        count += 1
        if status == 200 and hashlib.sha256(body).digest() != control_hash:
            if kind == "config" and CONFIG_SIGNAL.search(body):
                state = "confirmed-public-config-backup"
                evidence = "WordPress configuration directive in public backup; content suppressed"
            elif kind == "debug" and DEBUG_SIGNAL.search(body):
                state = "confirmed-public-debug-log"
                evidence = "WordPress/PHP diagnostic log signature; content suppressed"
            elif kind == "listing" and LISTING_SIGNAL.search(body):
                state = "confirmed-public-directory-listing"
                evidence = "Uploads directory index detected; filenames suppressed"
            else:
                state = "not-confirmed"
                evidence = "HTTP 200 without matching WordPress artifact signature"
        elif status in (401, 403):
            state, evidence = "auth-required", "Access denied"
        elif status is not None and status >= 500:
            state, evidence = "requires-review", "Server returned an error; no exposure proven"
        else:
            state, evidence = "not-confirmed", "No verified WordPress artifact exposed"
        auditor.add("WordPress artifact " + kind, path, status,
                    detail=evidence, visibility=state)
    return count
