"""Evidence-gated severity labels. Generic HTTP statuses are never vulnerabilities."""
from __future__ import annotations

LEVELS = ("HIGH", "MEDIUM", "LOW", "REVIEW", "INFO")
VERIFIED = {
    "confirmed-public-config-backup": ("HIGH", "confirmed"),
    "confirmed-public-debug-log": ("MEDIUM", "confirmed"),
    "confirmed-public-directory-listing": ("LOW", "confirmed"),
}

def assess(name: str, status: int | None, visibility: str, detail: str):
    """Classify a test result without confusing access status with vulnerability."""
    if visibility in VERIFIED and status == 200:
        return VERIFIED[visibility]
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
