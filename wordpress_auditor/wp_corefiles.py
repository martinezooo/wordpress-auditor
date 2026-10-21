"""Read-only direct-access probe of WordPress PHP files, with plain-language meaning.

Every directory gets a CONTROL (a nonexistent .php there). Without a control a
5xx cannot be attributed to the file; with it we can say whether the file itself
is reachable and executing, or the whole area is failing.

Only GET. wp-mail.php, wp-cron.php and other files with side effects on GET are
deliberately NOT requested.
"""
from __future__ import annotations

import posixpath

import hashlib
import re

from .interpret import (
    PHP_ERROR, PHP_SOURCE, WP_DIRECT_ACCESS, WP_HARDENING,
    classify_role, interpret,
)

CORE_FILES = (
    # entry points that are safe to GET
    "/wp-comments-post.php", "/wp-trackback.php", "/wp-links-opml.php",
    "/wp-signup.php", "/wp-activate.php",
    # include-only core files that must never be requested directly
    "/wp-settings.php", "/wp-load.php", "/wp-blog-header.php",
    "/wp-includes/version.php", "/wp-includes/functions.php",
    "/wp-includes/load.php", "/wp-includes/pluggable.php",
    "/wp-includes/class-wp-hook.php",
    "/wp-admin/includes/file.php", "/wp-admin/includes/admin.php",
    "/wp-admin/menu.php", "/wp-admin/admin-header.php",
)
CONTROL_NAME = "wp-audit-control-85461.php"
MAX_PLUGIN_FILES = 6
SOURCE_SUFFIXES = (".bak", "~")
SOURCE_CONTROL_NAME = "wp-audit-source-control-85461.php.bak"
WORDPRESS_PHP = re.compile(
    rb"(?:<\?php\b.{0,4000}(?:Plugin Name:|Theme Name:|\bABSPATH\b|\badd_action\s*\())",
    re.I | re.S,
)


def _control_for(path):
    return posixpath.dirname(path).rstrip("/") + "/" + CONTROL_NAME


def candidate_paths(auditor):
    # Plugin files first: they are the largest and least uniform attack surface.
    paths = []
    for slug in sorted(getattr(auditor, "plugin_slugs", ()))[:MAX_PLUGIN_FILES]:
        # The main plugin file is conventionally <slug>/<slug>.php.
        paths.append("/wp-content/plugins/%s/%s.php" % (slug, slug))
    return paths + list(CORE_FILES)


def source_followups(path, status, body=b"", control_status=None):
    """Return bounded, read-only next probes for a source-backed observation.

    WordPress warns that direct plugin-file access is context dependent. We do
    not invoke a handler or invent an exploit. A file-specific 5xx/200 only
    opens a general deployment-misconfiguration branch: look for accidentally
    published backup copies of the same PHP source.
    """
    role = classify_role(path)
    specific = control_status is None or control_status != status
    if role not in ("plugin", "admin-page") or not specific:
        return ()
    if status not in (200, 500) and not PHP_ERROR.search(body or b""):
        return ()
    return tuple(path + suffix for suffix in SOURCE_SUFFIXES)


def _check_source_followups(auditor, original, candidates, stop_at):
    """Probe backup names, requiring PHP/WP source and a soft-404 control."""
    if not candidates or auditor.request_count >= min(stop_at, auditor.limit):
        return 0
    directory = posixpath.dirname(original).rstrip("/")
    control = directory + "/" + SOURCE_CONTROL_NAME
    c_status, c_body, _ = auditor.request(control, include_credentials=False)
    c_hash = hashlib.sha256(c_body).digest()
    auditor.add(
        "WP direct-access follow-up control", control, c_status,
        visibility="control",
        detail="nonexistent static backup baseline for the same directory",
        reference=WP_DIRECT_ACCESS,
    )
    count = 1
    for candidate in candidates:
        if auditor.request_count >= min(stop_at, auditor.limit):
            break
        status, body, _ = auditor.request(candidate, include_credentials=False)
        count += 1
        different = status == 200 and hashlib.sha256(body).digest() != c_hash
        confirmed = different and PHP_SOURCE.search(body) and WORDPRESS_PHP.search(body)
        if confirmed:
            auditor.add(
                "WP direct-access follow-up source backup", candidate, status,
                visibility="confirmed-php-source-disclosure",
                detail="WordPress-related PHP source exposed by a backup filename; content suppressed",
                meaning=("The direct-access anomaly opened a bounded follow-up and a backup "
                         "copy of WordPress PHP source was independently confirmed."),
                action=("Remove the backup from the public root, block backup suffixes, review "
                        "access logs, and rotate any secrets present in the exposed source."),
                reference=WP_HARDENING,
            )
        else:
            auditor.add(
                "WP direct-access follow-up source backup", candidate, status,
                visibility="not-confirmed",
                detail=("No WordPress PHP source signature (soft-404 controlled)" if status == 200
                        else "Backup/source variant not exposed"),
                reference=WP_DIRECT_ACCESS,
            )
    return count


def check_core_files(auditor):
    """Return number of file probes; every result carries meaning and next step."""
    controls = {}
    count = 0
    # Keep this phase to ~1/8 of the global budget so it never starves the others.
    stop_at = min(auditor.limit, auditor.request_count + max(10, auditor.limit // 8))
    for path in candidate_paths(auditor):
        if auditor.request_count >= stop_at:
            break
        control = _control_for(path)
        if control not in controls:
            if auditor.request_count >= stop_at:
                break
            c_status, _, _ = auditor.request(control, include_credentials=False)
            controls[control] = c_status
            auditor.add("WP core file control", control, c_status,
                        detail="nonexistent PHP file baseline for the same directory",
                        visibility="control")
        if auditor.request_count >= stop_at:
            break
        status, body, _ = auditor.request(path, include_credentials=False)
        count += 1
        found = interpret(path, status, body, controls[control])
        if found:
            auditor.add("WP core file direct access", path, status,
                        detail=found.meaning.split(". ")[0][:200],
                        visibility=found.verdict, meaning=found.meaning,
                        action=found.action, reference=found.reference)
        elif status in (200, 301, 302, 303, 307, 308, 404, 400, 405):
            auditor.add("WP core file direct access", path, status,
                        detail="No security-relevant behavior for HTTP %s" % status,
                        visibility="not-confirmed")
        else:
            auditor.add("WP core file direct access", path, status,
                        detail="HTTP %s; no conclusion" % status)
        followups = source_followups(path, status, body, controls[control])
        if followups:
            _check_source_followups(auditor, path, followups, stop_at)
    return count
