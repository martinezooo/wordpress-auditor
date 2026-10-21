"""Evidence-gated severity labels. Generic HTTP statuses are never vulnerabilities."""
from __future__ import annotations

LEVELS = ("HIGH", "MEDIUM", "LOW", "REVIEW", "INFO")
VERIFIED = {
    "confirmed-public-config-backup": ("HIGH", "confirmed"),
    "confirmed-public-debug-log": ("MEDIUM", "confirmed"),
    "confirmed-public-directory-listing": ("LOW", "confirmed"),
    "confirmed-public-user-private-fields": ("MEDIUM", "confirmed"),
    "confirmed-public-current-user": ("HIGH", "confirmed"),
    "confirmed-public-app-password-metadata": ("MEDIUM", "confirmed"),
    "confirmed-public-env-config": ("HIGH", "confirmed"),
    "confirmed-public-git-metadata": ("MEDIUM", "confirmed"),
    "confirmed-public-nonpublic-wp-content": ("MEDIUM", "confirmed"),
    "confirmed-public-private-comment-fields": ("MEDIUM", "confirmed"),
    "confirmed-unsafe-wp-registration-default-role": ("HIGH", "confirmed"),
}

# Statuses already explained by interpret.py: understood, not "needs review".
INTERPRETED_INFO = frozenset({
    "feature-disabled", "rate-limited", "server-unavailable", "maintenance-mode",
    "server-wide-error", "site-database-error", "waf-blocked", "entrypoint-error",
    "config-executed", "internal-file-executed", "internal-file-executes-silently",
})


def assess(name: str, status: int | None, visibility: str, detail: str):
    """Classify a test result without confusing access status with vulnerability."""
    if visibility in VERIFIED and status == 200:
        return VERIFIED[visibility]
    if visibility == "confirmed-public-php-error-disclosure":
        # Error pages arrive with 500 (or 200 when display_errors hides the status).
        return "LOW", "confirmed"
    if visibility == "confirmed-php-source-disclosure" and status == 200:
        return "HIGH", "confirmed"
    if visibility in INTERPRETED_INFO:
        # e.g. WordPress answers HTTP 501 when Application Passwords are off;
        # a 5xx explained by interpret.py is understood, not an open question.
        return "INFO", "observed"
    if visibility.startswith("review-"):
        return "REVIEW", "unverified"
    if visibility == "requires-oast-correlation":
        return "REVIEW", "unverified"
    if visibility in ("confirmed-public", "confirmed-authenticated"):
        # A marker being visible is not in itself a security defect.
        return "INFO", "observed"
    if ("requires-review" in detail or visibility in ("requires-review", "server-error")
            or status is not None and status >= 500
            and not (status == 501 and name.startswith("HTTP method "))):
        return "REVIEW", "unverified"
    return "INFO", "observed"
