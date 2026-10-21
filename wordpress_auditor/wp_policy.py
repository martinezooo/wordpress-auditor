"""Conservative parsing of WordPress Core setup and registration pages.

A form advertised over GET is not evidence that the corresponding POST works.
No POST or state-changing maintenance URL is ever visited here.
"""
from __future__ import annotations

import re

LOGIN_FORM = re.compile(
    r"""<form\b[^>]{0,1600}\bid\s*=\s*['"]loginform['"]""", re.I
)
REGISTER_FORM = re.compile(
    r"""<form\b[^>]{0,1600}\bid\s*=\s*['"]registerform['"]""", re.I
)
LOSTPASSWORD_FORM = re.compile(
    r"""<form\b[^>]{0,1600}\bid\s*=\s*['"]lostpasswordform['"]""", re.I
)
NETWORK_SIGNUP_FORM = re.compile(
    r"""<form\b[^>]{0,1600}\bid\s*=\s*['"]setupform['"]""", re.I
)
INSTALL_FIELDS = (
    re.compile(r"""\bname\s*=\s*['"]weblog_title['"]""", re.I),
    re.compile(r"""\bname\s*=\s*['"]user_name['"]""", re.I),
    re.compile(r"""\bname\s*=\s*['"]admin_email['"]""", re.I),
)
REPAIR_LINK = re.compile(
    r"""(?:repair\.php\?repair=(?:1|2)|\?repair=(?:1|2))(?=['"&\s<]|$)""", re.I
)
FORM_FIELDS = re.compile(
    r"""<input\b[^>]{0,750}\bname\s*=\s*['"](?:user_login|user_email)['"]""",
    re.I,
)


def classify(kind: str, status: int | None, body: bytes) -> tuple[str, str]:
    """Return an observation without returning page content or account details."""
    if status in (401, 403):
        return "auth-required", "%s page blocked (HTTP %s)" % (kind, status)
    if status != 200:
        return "not-evaluated", "%s page HTTP %s; not followed" % (kind, status)
    text = body[:64_000].decode("utf-8", "ignore")
    if kind == "login":
        if LOGIN_FORM.search(text):
            return "login-form-observed", "Standard WordPress login form present; no login attempted"
        return "not-confirmed", "No WordPress login form signature (possible soft-404 or custom login)"
    if kind == "register":
        if REGISTER_FORM.search(text) and FORM_FIELDS.search(text):
            # Open signup is often intentional, so this is REVIEW, never a confirmed flaw:
            # the resulting default role can only be verified with authorization.
            return "review-open-registration", (
                "Public WordPress registration is open; verify the default role is "
                "least-privileged. No account was registered")
        if re.search(r"registration (?:is\s+)?(?:currently\s+)?(?:disabled|not allowed)", text, re.I):
            return "registration-restricted", "WordPress registration appears disabled (page text)"
        return "not-confirmed", "No standard WordPress registration form verified"
    if kind == "lostpassword":
        if LOSTPASSWORD_FORM.search(text):
            return "reset-form-observed", "WordPress password-reset form found; no email sent"
        return "not-confirmed", "No standard WordPress password-reset form verified"
    if kind == "signup":
        if NETWORK_SIGNUP_FORM.search(text):
            return "multisite-signup-observed", (
                "Multisite signup form found; no account or site created")
        return "not-confirmed", "No WordPress multisite signup form verified"
    if kind == "activation":
        if "wp-activate.php" in text.lower() and re.search(
                r"(?:activation key|activation code|account activated)", text, re.I):
            return "multisite-activation-observed", (
                "Multisite activation page signature observed; no key submitted")
        return "not-confirmed", "Multisite activation not verified"
    if kind == "install":
        if "<form" in text.lower() and all(p.search(text) for p in INSTALL_FIELDS):
            return "review-wp-install-open", (
                "WordPress installation form found; server setup not attempted, review required")
        return "not-confirmed", "No active WordPress installation wizard verified"
    if kind == "repair":
        if REPAIR_LINK.search(text) and re.search(r"\brepair database\b", text, re.I):
            return "review-wp-repair-open", (
                "WordPress database repair action link visible; never requested or executed")
        return "not-confirmed", "No available WordPress database repair action verified"
    return "not-evaluated", "Unknown WordPress Core surface"
