"""Focused WordPress core misconfiguration checks and cross-channel operations.

No writes, credential guessing, version/CVE matching, cart or stateful endpoints.
Only content-evidenced disclosures are findings; endpoint existence is INFO.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass


@dataclass(frozen=True)
class ReadRule:
    check_id: str
    name: str
    path: str
    kind: str
    expected_status: str = ""


READ_RULES = (
    ReadRule("WP-55", "WP private draft posts", "/wp-json/wp/v2/posts?status=draft&per_page=1", "post", "draft"),
    ReadRule("WP-56", "WP private posts", "/wp-json/wp/v2/posts?status=private&per_page=1", "post", "private"),
    ReadRule("WP-57", "WP pending posts", "/wp-json/wp/v2/posts?status=pending&per_page=1", "post", "pending"),
    ReadRule("WP-58", "WP private draft pages", "/wp-json/wp/v2/pages?status=draft&per_page=1", "post", "draft"),
    ReadRule("WP-59", "WP private pages", "/wp-json/wp/v2/pages?status=private&per_page=1", "post", "private"),
    ReadRule("WP-60", "WP pending comment moderation", "/wp-json/wp/v2/comments?status=hold&per_page=1", "comment", "hold"),
    ReadRule("WP-61", "WP spam comment moderation", "/wp-json/wp/v2/comments?status=spam&per_page=1", "comment", "spam"),
    ReadRule("WP-62", "WP private comment edit fields", "/wp-json/wp/v2/comments?context=edit&per_page=1", "comment-edit"),
    ReadRule("WP-63", "WP public comment configuration", "/wp-json/wp/v2/posts?per_page=2&_fields=id,comment_status,ping_status,status", "comment-settings"),
)
PRIVATE_STATUS = frozenset({"draft", "private", "pending", "hold", "spam"})
SENSITIVE_COMMENT_KEYS = ("author_email", "author_ip", "author_user_agent")


def _records(raw):
    if len(raw) > 512 * 1024:
        return None
    try:
        data = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        return None
    if not isinstance(data, list):
        return None
    # Only accept actual WP-style entities, never arbitrary JSON echoes.
    return data[:10]


def _valid_record(obj):
    return isinstance(obj, dict) and type(obj.get("id")) is int and obj["id"] > 0


def evaluate(rule, status, body):
    """Return evidence classification; never include text, names or PII."""
    if status in (401, 403):
        return "auth-required", "Anonymous access restricted; expected for private WordPress data"
    if status != 200:
        return "not-confirmed", "Endpoint returned HTTP %s; disclosure not verified" % status
    rows = _records(body)
    if rows is None:
        return "not-confirmed", "HTTP 200 did not return a WordPress JSON object list"
    valid = [obj for obj in rows if _valid_record(obj)]
    if rule.kind in ("post", "comment"):
        leaked = [obj for obj in valid if obj.get("status") == rule.expected_status]
        if leaked:
            def has_private_text(obj):
                # A private status/id alone is metadata evidence, not proof
                # that unpublished text has actually been disclosed.
                return any(
                    isinstance(obj.get(key), dict) and any(
                        isinstance(obj[key].get(field), str)
                        and bool(obj[key][field].strip())
                        for field in ("rendered", "raw")
                    ) for key in ("content", "title", "excerpt"))
            exposed = sum(has_private_text(obj) for obj in leaked)
            if exposed:
                return "confirmed-public-nonpublic-wp-content", (
                    "%d WordPress object(s) with status %s and unpublished text exposed "
                    "anonymously; all content and IDs withheld" %
                    (exposed, rule.expected_status))
            return "review-private-wp-object-metadata", (
                "%d private-status object IDs returned anonymously, but no unpublished "
                "text verified; manual review required" % len(leaked))
        return "not-confirmed", "No matching private WordPress status found in first page"
    if rule.kind == "comment-edit":
        leaked = [obj for obj in valid if any(
            isinstance(obj.get(k), str) and obj[k].strip()
            for k in SENSITIVE_COMMENT_KEYS)]
        if leaked:
            return "confirmed-public-private-comment-fields", (
                "%d WordPress comment(s) disclosed nonempty moderator-only fields; values withheld"
                % len(leaked))
        return "not-confirmed", "No nonempty private comment moderation fields confirmed"
    if rule.kind == "comment-settings":
        open_posts = sum(1 for obj in valid
                         if obj.get("comment_status") == "open"
                         and obj.get("status", "publish") == "publish")
        if open_posts:
            return "commenting-enabled", (
                "Public posts with comments open in inspected sample: %d; this is not a vulnerability"
                % open_posts)
        if valid:
            return "commenting-not-observed", "No open comments in inspected public posts"
        return "not-confirmed", "No public posts in first page"
    return "not-confirmed", "Unsupported read-only check"


def audit_wordpress_core(auditor):
    """Read-only WordPress core behavior probes sharing the global request budget."""
    for rule in READ_RULES:
        if auditor.request_count >= auditor.limit:
            break
        status, body, _ = auditor.request(rule.path, include_credentials=False)
        state, detail = evaluate(rule, status, body)
        auditor.add(rule.name, rule.path, status, visibility=state, detail=detail)


# The matrix describes operations, not pretend extra tests.
# A discovered handler is not evidence that its authorization is correct.
@dataclass(frozen=True)
class Channel:
    name: str
    key: str
    kind: str
    action: str = ""


@dataclass(frozen=True)
class Operation:
    operation_id: str
    label: str
    channels: tuple[Channel, ...]


OPERATIONS = (
    Operation("comments.create", "Create comment", (
        Channel("Classic comment form", "form", "html"),
        Channel("WordPress REST", "/wp/v2/comments", "rest", "POST"),
        Channel("XML-RPC wp.newComment", "wp.newComment", "xmlrpc"),
    )),
    Operation("comments.moderation.read", "Read moderated comments", (
        Channel("WP REST moderation", "WP pending comment moderation", "result"),
        Channel("WP REST spam", "WP spam comment moderation", "result"),
        Channel("WP REST edit context", "WP private comment edit fields", "result"),
    )),
    Operation("posts.read_nonpublic", "Read unpublished content", (
        Channel("WP REST draft posts", "WP private draft posts", "result"),
        Channel("WP REST private posts", "WP private posts", "result"),
        Channel("WP REST draft pages", "WP private draft pages", "result"),
        Channel("WP REST private pages", "WP private pages", "result"),
    )),
    Operation("posts.create", "Create a WordPress post", (
        Channel("WP REST", "/wp/v2/posts", "rest", "POST"),
        Channel("XML-RPC wp.newPost", "wp.newPost", "xmlrpc"),
    )),
    Operation("media.upload", "Upload a file", (
        Channel("WP REST Media", "/wp/v2/media", "rest", "POST"),
        Channel("XML-RPC wp.uploadFile", "wp.uploadFile", "xmlrpc"),
    )),
    Operation("users.login", "Authenticate a WordPress user", (
        Channel("WP Login form", "WP login form", "result"),
        Channel("REST authenticated session", "WP REST authenticated identity", "result"),
        Channel("XML-RPC login", "WP XML-RPC test-account authentication", "result"),
    )),
    Operation("users.register", "Register WordPress account", (
        Channel("WP registration form", "WP registration form", "result"),
        Channel("Multisite signup", "WP network signup", "result"),
    )),
    Operation("users.reset_password", "Request WordPress password reset", (
        Channel("WP password reset form", "WP password reset form", "result"),
    )),
    Operation("comments.edit", "Edit a WordPress comment", (
        Channel("WordPress REST", "/wp/v2/comments", "rest", "POST"),
        Channel("XML-RPC wp.editComment", "wp.editComment", "xmlrpc"),
    )),
    Operation("config.read", "Read WordPress sensitive configuration", (
        Channel("WordPress config backup", "WordPress artifact config", "result"),
        Channel("Environment file", "WordPress artifact env", "result"),
        Channel("Debug log", "WordPress artifact debug", "result"),
    )),
)


def operation_matrix(auditor):
    """Describe independently observed methods; don't turn detection into a pass."""
    rows = auditor.results
    rest = getattr(auditor, "rest_route_methods", {})
    xmlrpc = getattr(auditor, "xmlrpc_methods", set())
    forms = getattr(auditor, "comment_forms", set())
    matrix = []
    for operation in OPERATIONS:
        channels = []
        for channel in operation.channels:
            label = "UNKNOWN"
            evidence = "Not inspected or no evidence observed"
            if channel.kind == "rest":
                if channel.key in rest:
                    if channel.action in rest[channel.key]:
                        label = "DISCOVERED"
                        evidence = "REST index advertises " + channel.action + "; handler not invoked"
                    else:
                        label = "NOT_ADVERTISED"
                        evidence = "REST index does not advertise " + channel.action
                else:
                    evidence = "REST route not found in inspected index (not proof of absence)"
            elif channel.kind == "xmlrpc":
                if channel.key in xmlrpc:
                    label = "DISCOVERED"
                    evidence = "XML-RPC listMethods includes method; not invoked"
            elif channel.kind == "html":
                if forms:
                    label = "DISCOVERED"
                    evidence = "%d in-scope HTML page(s) contained a comment POST form; not submitted" % len(forms)
            else:
                matches = [r for r in rows if r.name == channel.key or
                           r.name.startswith(channel.key)]
                if matches:
                    # Checked is not necessarily safe or successful.
                    label = "TESTED"
                    evidence = ("Result: " + matches[-1].visibility +
                                "; HTTP " + str(matches[-1].status))
            channels.append({
                "channel": channel.name, "status": label, "evidence": evidence,
            })
        matrix.append({
            "operation": operation.operation_id,
            "label": operation.label,
            "channels": channels,
            "interpretation": "Detection does not prove authorization or a vulnerability",
        })
    return matrix


def matrix_markdown(matrix):
    lines = [
        "# WordPress Core Operation Matrix",
        "",
        "DISCOVERED means a route/form/method exists; it has not been executed.",
        "TESTED means a check produced a result, not that the target is safe.",
        "No writing, comment posting, upload, checkout, or login is executed by this matrix.",
        "",
        "| Operation | Channel | State | Evidence |",
        "|---|---|---|---|",
    ]
    for item in matrix:
        for channel in item["channels"]:
            cols = (item["label"] + " (" + item["operation"] + ")", channel["channel"],
                    channel["status"], channel["evidence"])
            lines.append("| " + " | ".join(
                str(x).replace("|", "/").replace("\n", " ") for x in cols) + " |")
    return "\n".join(lines) + "\n"
