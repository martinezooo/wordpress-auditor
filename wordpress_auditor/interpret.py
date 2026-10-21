"""Source-backed security meaning of HTTP observations on WordPress paths.

A status code alone says little. What it means depends on the ROLE of the file:

  entry     meant to be requested directly (wp-login.php, xmlrpc.php, wp-cron.php...)
  setup     installer/upgrade/repair scripts - should be inert on a finished site
  config    wp-config.php - must be executed, never served as text
  backup    wp-config.php.bak, ~, .swp ... - served as text unless blocked
  internal  include-only core files (wp-includes/*.php, wp-settings.php...)
  plugin    PHP inside wp-content/plugins or themes
  uploads   PHP inside wp-content/uploads (must never execute)

and on a CONTROL: the status of a certainly-nonexistent .php file in the same
directory. If the control returns the same 5xx, the error is not about this file
(server/PHP/WAF failure), so no file-specific conclusion may be drawn.

No request is made here; the module only interprets what was already observed.
Conclusions deliberately distinguish official WordPress behavior from inference.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import urlsplit

ENTRY_FILES = frozenset({
    "/wp-login.php", "/xmlrpc.php", "/wp-cron.php", "/wp-comments-post.php",
    "/wp-signup.php", "/wp-activate.php", "/wp-trackback.php", "/wp-mail.php",
    "/wp-links-opml.php", "/index.php", "/wp-admin/admin-ajax.php",
    "/wp-admin/admin-post.php", "/wp-admin/load-scripts.php",
    "/wp-admin/load-styles.php",
})
SETUP_FILES = frozenset({
    "/wp-admin/install.php", "/wp-admin/setup-config.php",
    "/wp-admin/upgrade.php", "/wp-admin/maint/repair.php",
})
CONFIG_FILES = frozenset({"/wp-config.php"})
INTERNAL_FILES = frozenset({"/wp-settings.php", "/wp-load.php", "/wp-blog-header.php"})

PHP_ERROR = re.compile(
    rb"(?:(?:Fatal error|Parse error|Warning|Notice|Deprecated)\s*(?:</b>)?\s*:.{0,300}?"
    rb"\bin\s+(?:<b>)?/[^\s<]{1,200}\.php|Uncaught\s+(?:Error|Exception|TypeError)|Stack trace:)",
    re.I | re.S)
PHP_SOURCE = re.compile(rb"<\?php\b", re.I)
WP_CRITICAL = re.compile(rb"There has been a critical error", re.I)
DB_ERROR = re.compile(rb"Error establishing a database connection", re.I)
MAINTENANCE = re.compile(rb"Briefly unavailable for scheduled maintenance", re.I)
WAF_HINT = re.compile(
    rb"(?:mod_security|modsecurity|Request blocked|Access denied \| |Attention Required"
    rb"|Sucuri Website Firewall|Wordfence|You don't have permission to access)", re.I)

WP_DIRECT_ACCESS = "https://developer.wordpress.org/plugins/wordpress-org/common-issues/#direct-file-access"
WP_HARDENING = "https://developer.wordpress.org/advanced-administration/security/hardening/"
WP_DEBUGGING = "https://developer.wordpress.org/advanced-administration/debug/debug-wordpress/"
WP_CONFIG = "https://developer.wordpress.org/apis/wp-config-php/"


@dataclass(frozen=True)
class Interpretation:
    verdict: str   # becomes Result.visibility; "review-*"/"confirmed-*" feed severity
    meaning: str   # what the status means here, in plain language
    action: str    # what the site owner / auditor should do next
    reference: str = ""  # public source supporting the rule, not the target


def classify_role(path: str) -> str:
    p = urlsplit(path).path.lower()
    if re.search(r"/wp-content/uploads/.*\.(?:php\d?|phtml|phar)$", p):
        return "uploads"
    if p in CONFIG_FILES:
        return "config"
    if re.match(r"/wp-config\.php.+", p):
        return "backup"
    if p in SETUP_FILES:
        return "setup"
    if p in ENTRY_FILES:
        return "entry"
    if p in INTERNAL_FILES or p.startswith(("/wp-includes/", "/wp-admin/includes/")):
        return "internal"
    if re.match(r"/wp-admin/[^/]+\.php$", p):
        return "admin-page"
    if p.startswith(("/wp-content/plugins/", "/wp-content/themes/",
                     "/wp-content/mu-plugins/")) and p.endswith(".php"):
        return "plugin"
    return "other"


def _server_wide(status, control_status):
    return control_status is not None and control_status == status and status >= 500


def interpret(path, status, body=b"", control_status=None):
    """Return an Interpretation for non-trivial statuses, else None."""
    if status is None:
        return None
    role = classify_role(path)
    body = body or b""

    if status == 429:
        return Interpretation(
            "rate-limited",
            "The server is throttling requests, so results after this point may be "
            "incomplete or misleading. This is not a vulnerability.",
            "Re-run with --delay 1 (or higher) and a lower --max-requests.")

    if status in (502, 503, 504):
        if MAINTENANCE.search(body):
            return Interpretation(
                "maintenance-mode",
                "WordPress is in maintenance mode (a stuck .maintenance file after a "
                "failed update is common). Not an attack path.",
                "Remove the stale .maintenance file if the update already finished.")
        return Interpretation(
            "server-unavailable",
            "The gateway/PHP backend did not answer (HTTP %d): PHP-FPM down or "
            "overloaded, proxy timeout, or the scanner is being throttled. No "
            "conclusion about this file." % status,
            "Re-run with --delay 1. If it persists, check PHP-FPM and web-server logs.")

    # HTTP 501 is only treated as a disabled WordPress feature when the caller
    # has verified the WordPress error code (for example
    # application_passwords_disabled in wp_identity.py). A bare 501 on an
    # arbitrary PHP file has no WordPress-specific meaning.
    if status == 501:
        return None

    if status >= 500:
        if _server_wide(status, control_status):
            return Interpretation(
                "server-wide-error",
                "A nonexistent .php file next to it returns the same HTTP %d, so the "
                "error is NOT specific to this file - PHP, the web server or a WAF is "
                "failing for the whole area." % status,
                "Check the web-server/PHP error log; treat as an availability problem.")
        if PHP_ERROR.search(body):
            return Interpretation(
                "confirmed-public-php-error-disclosure",
                "A raw PHP error with a server file path or stack trace is shown to "
                "anonymous visitors (display_errors is on). This leaks the install "
                "path and code structure that help later attacks.",
                "Set display_errors=Off and WP_DEBUG_DISPLAY=false; log errors outside the public root.",
                WP_DEBUGGING)
        if DB_ERROR.search(body):
            return Interpretation(
                "site-database-error",
                "WordPress cannot reach its database, so the site is down. By itself "
                "not a vulnerability, but a half-working site may expose setup pages.",
                "Restore the database connection and re-scan.")
        if WP_CRITICAL.search(body):
            critical = True
        else:
            critical = False
        if WAF_HINT.search(body):
            return Interpretation(
                "waf-blocked",
                "HTTP 500 with a firewall signature: a WAF/ModSecurity rule rejected "
                "the request. The file itself was not executed.",
                "Treat like a 403 (blocked). Nothing to fix.")
        shown = ("WordPress caught the fatal error and showed its generic page "
                 "(no technical details leaked). " if critical else "")
        if role == "entry":
            return Interpretation(
                "entrypoint-error",
                shown + "A public WordPress entry point crashes (plugin/theme conflict, "
                "PHP fatal, memory limit or DB problem). Not an attack path - a "
                "stability problem that also hides this feature from the scan.",
                "Enable WP_DEBUG_LOG and read wp-content/debug.log; disable the last "
                "changed plugin.")
        if role == "setup":
            return Interpretation(
                "review-setup-script-error",
                shown + "A WordPress setup/repair surface reached PHP but failed. The "
                "status alone does not prove that an installation or repair action is "
                "available; the scanner separately checks for the real WordPress form.",
                "Review the paired setup-form result. If no form was confirmed, treat "
                "this as availability/hardening rather than a vulnerability.",
                WP_HARDENING)
        if role == "config":
            return Interpretation(
                "config-executed",
                shown + "wp-config.php is EXECUTED by PHP, not served as text (good). "
                "A 500 only means it cannot run on its own, which is normal.",
                "None. The scanner separately tests common backup names by content signature.",
                WP_CONFIG)
        if role == "backup":
            return Interpretation(
                "review-config-backup-error",
                "A wp-config backup name produces a server error instead of 404/403: "
                "the file may exist but the server fails while delivering it.",
                "Check whether the file exists on disk and delete it.",
                WP_HARDENING)
        if role == "uploads":
            return Interpretation(
                "review-php-executable-in-uploads",
                "PHP in wp-content/uploads is being executed. Anyone who can upload a "
                "file there gets remote code execution.",
                "Disable PHP execution in uploads (web-server rule) and delete the file.",
                WP_HARDENING)
        if role in ("plugin", "internal", "admin-page", "other"):
            reach = ("an include-only core file" if role == "internal" else
                     "a plugin/theme file" if role == "plugin" else "a PHP file")
            base = (shown + "The response differs from a nonexistent sibling and is "
                    "consistent with file-specific PHP execution/failure for %s. It does "
                    "not prove exploitability or prove that an ABSPATH guard is absent." % reach)
            if role == "internal":
                return Interpretation(
                    "internal-file-executed",
                    base + " Direct responses from include-only core files are not a "
                    "security finding unless source, secrets, or diagnostic detail leaks.",
                    "No exploit flow is inferred. Fix only confirmed source/error disclosure.",
                    WP_HARDENING)
            return Interpretation(
                "review-direct-php-execution",
                base + " WordPress Plugin Review guidance says the risk of direct file "
                "access depends on whether the file contains executable code and what it does.",
                "Automatic next step: test bounded backup/source variants. Manual next "
                "step: inspect executable code for an ABSPATH guard, nonce and capability checks.",
                WP_DIRECT_ACCESS)
        return Interpretation(
            "requires-review", "Unexpected server error on this path.",
            "Check the server error log.")

    if status in (401, 403):
        if role in ("internal", "plugin", "config", "backup", "setup", "uploads"):
            hint = (" (a WAF/security plugin may be the cause)"
                    if WAF_HINT.search(body) else "")
            return Interpretation(
                "auth-required",
                "Access is denied by the server%s. This is the desired hardening for "
                "files that should not be requested directly." % hint,
                "None.")
        return None

    if status == 405 and role in ("entry",):
        return Interpretation(
            "observed",
            "The file exists and rejects this HTTP method (e.g. GET on a POST-only "
            "endpoint). Normal WordPress behavior.",
            "None.")

    if status == 200 and path.lower().split("?")[0].endswith(".php") and PHP_ERROR.search(body):
        # With display_errors=On PHP answers HTTP 200 (not 500) together with the
        # error text, so a status-only check would miss this leak completely.
        return Interpretation(
            "confirmed-public-php-error-disclosure",
            "A raw PHP error with a server file path or stack trace is shown to "
            "anonymous visitors (display_errors is on; note the status is 200, not 500). "
            "This leaks the install path and code structure that help later attacks.",
            "Set display_errors=Off and WP_DEBUG_DISPLAY=false; log errors outside the public root.",
            WP_DEBUGGING)

    if status == 200 and role in ("internal", "plugin", "admin-page"):
        if PHP_SOURCE.search(body):
            return Interpretation(
                "confirmed-php-source-disclosure",
                "PHP source code is delivered as plain text: PHP is NOT being "
                "interpreted for this file.",
                "Fix the PHP handler configuration immediately and rotate secrets.",
                WP_HARDENING)
        if not body.strip():
            return Interpretation(
                "internal-file-executes-silently",
                "Empty response: the file ran and exited quietly through its ABSPATH "
                "guard. Works as designed, but no web-server rule blocks direct access.",
                "No vulnerability is established; prioritize only content/error leaks.",
                WP_HARDENING)
        return None

    if status == 200 and role == "uploads":
        return Interpretation(
            "review-php-executable-in-uploads",
            "A PHP file in wp-content/uploads answers 200 - uploads should never run PHP.",
            "Disable PHP execution in uploads and inspect/delete the file.",
            WP_HARDENING)

    if status == 404 and role in ("entry", "setup"):
        return Interpretation(
            "observed",
            "File absent or hidden (renamed login URL, removed file, or custom "
            "routing). Not a flaw.",
            "None.")
    return None
