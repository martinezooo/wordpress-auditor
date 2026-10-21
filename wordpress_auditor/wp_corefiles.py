"""Read-only direct-access probe of WordPress PHP files, with plain-language meaning.

Every directory gets a CONTROL (a nonexistent .php there). Without a control a
5xx cannot be attributed to the file; with it we can say whether the file itself
is reachable and executing, or the whole area is failing.

Only GET. wp-mail.php, wp-cron.php and other files with side effects on GET are
deliberately NOT requested.
"""
from __future__ import annotations

import posixpath

from .interpret import interpret

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


def _control_for(path):
    return posixpath.dirname(path).rstrip("/") + "/" + CONTROL_NAME


def candidate_paths(auditor):
    # Plugin files first: they are the largest and least uniform attack surface.
    paths = []
    for slug in sorted(getattr(auditor, "plugin_slugs", ()))[:MAX_PLUGIN_FILES]:
        # The main plugin file is conventionally <slug>/<slug>.php.
        paths.append("/wp-content/plugins/%s/%s.php" % (slug, slug))
    return paths + list(CORE_FILES)


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
                        action=found.action)
        elif status in (200, 301, 302, 303, 307, 308, 404, 400, 405):
            auditor.add("WP core file direct access", path, status,
                        detail="No security-relevant behavior for HTTP %s" % status,
                        visibility="not-confirmed")
        else:
            auditor.add("WP core file direct access", path, status,
                        detail="HTTP %s; no conclusion" % status)
    return count
