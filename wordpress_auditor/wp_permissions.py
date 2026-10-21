"""Read-only WordPress REST/AJAX/XML-RPC permission correlation.

Mismatch alone is not a privilege bypass. Never execute discovered plugin actions.
"""
import hashlib
import secrets

REST_COMPARISONS = (
    ("WP private posts", "WP alternate REST private posts", "private posts"),
    ("WP pending comment moderation", "WP alternate REST moderated comments", "moderated comments"),
    ("WP users private edit context (anonymous)", "WP alternate REST private user fields", "private user fields"),
    ("WP REST settings (anonymous)", "WP alternate REST administrative settings", "administrative settings"),
)
PRIVATE_EXPOSURES = frozenset((
    "confirmed-public-nonpublic-wp-content",
    "confirmed-public-private-comment-fields",
    "confirmed-public-user-private-fields",
    "confirmed-unsafe-wp-registration-default-role",
))


def compare_rest(results):
    """Correlate previously recorded checks without additional HTTP requests."""
    def field(row, key):
        return row[key] if isinstance(row, dict) else getattr(row, key)

    output = []
    for classic, alternate, label in REST_COMPARISONS:
        first = next((r for r in results if field(r, "name") == classic), None)
        second = next((r for r in results if field(r, "name") == alternate), None)
        if first is None or second is None:
            output.append((label, "not-evaluated", "One or both REST channels were not checked"))
            continue
        base_status, alt_status = field(first, "status"), field(second, "status")
        alt_evidence = field(second, "visibility")
        if base_status in (401, 403) and alt_status == 200 and alt_evidence in PRIVATE_EXPOSURES:
            output.append((label, "review-cross-channel-permission",
                           "Standard REST blocked (HTTP %s); alternative route returned verified "
                           "private-content evidence. Investigate proxy/WAF routing and permissions." % base_status))
        elif base_status in (401, 403) and alt_status in (401, 403):
            output.append((label, "access-restricted", "Both routes denied anonymous access"))
        elif base_status == alt_status:
            output.append((label, "no-status-difference",
                           "Both routes returned HTTP %s; content may still differ" % base_status))
        else:
            output.append((label, "review-cross-channel-behavior",
                           "Standard REST HTTP %s; alternative HTTP %s; bypass not confirmed" %
                           (base_status, alt_status)))
    return output


def probe_ajax_unknown(auditor):
    """No-credential GET baseline and random unregistered action; never call known handlers."""
    if auditor.request_count + 2 > auditor.limit:
        return 0
    base = "/wp-admin/admin-ajax.php"
    other = base + "?action=wp_audit_nonexistent_" + secrets.token_hex(12)
    status, body, _ = auditor.request(base, include_credentials=False)
    auditor.add("WP AJAX dispatcher baseline", base, status,
                visibility="observed", detail="No action supplied; dispatcher response observed")
    unknown_status, unknown_body, _ = auditor.request(other, include_credentials=False)
    equivalent = (status == unknown_status and
                  hashlib.sha256(body).digest() == hashlib.sha256(unknown_body).digest())
    if equivalent:
        state = "expected-ajax-unknown-action"
        detail = "Unknown action matches no-action baseline; no handler execution confirmed"
    elif unknown_status in (401, 403):
        state = "auth-required"
        detail = "Unknown action was denied; no exposure confirmed"
    else:
        state = "review-ajax-unknown-action"
        detail = "Unknown action differs from baseline; needs review, no vulnerability proven"
    auditor.add("WP AJAX unknown action", base, unknown_status,
                visibility=state, detail=detail)
    return 2


def summarize_xmlrpc_policy(results):
    """Compare recorded GET and harmless system.listMethods POST status."""
    def field(row, key):
        return row[key] if isinstance(row, dict) else getattr(row, key)
    get = next((r for r in results if field(r, "name") == "XML-RPC endpoint"), None)
    post = next((r for r in results if field(r, "name") == "XML-RPC system.listMethods"), None)
    if get is None or post is None:
        return "not-evaluated", "GET/POST XML-RPC diagnostic pair incomplete"
    if field(get, "status") in (401, 403, 405) and field(post, "status") == 200:
        return ("observed", "Read-only XML-RPC POST responded despite GET restriction; "
                "normal WordPress behavior, not an authorization bypass")
    if field(post, "status") in (401, 403):
        return "auth-required", "XML-RPC method introspection denied by server policy"
    return "observed", "XML-RPC GET/POST diagnostics recorded; method presence is not a vulnerability"
