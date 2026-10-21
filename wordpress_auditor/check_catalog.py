"""Honest WordPress-specific coverage matrix inspired by HackTricks and WP docs.

A CHECKED entry means the test ran, not that the site is vulnerable.
Manual, opt-in and skipped checks are explicitly listed, never silently claimed.
"""
from __future__ import annotations

from dataclasses import dataclass, asdict
from collections import Counter

HACKTRICKS = "https://book.hacktricks.wiki/en/network-services-pentesting/pentesting-web/wordpress.html"
WP_REST = "https://developer.wordpress.org/rest-api/reference/"
WP_AUTH = "https://developer.wordpress.org/rest-api/using-the-rest-api/authentication/"


@dataclass(frozen=True)
class Check:
    check_id: str
    group: str
    label: str
    mode: str
    starts: tuple[str, ...]
    source: str = HACKTRICKS


# Results are keyed to real emitted check labels, never inferred from status codes.
CHECKS = [
    Check("WP-01", "Identity", "Public WordPress users in REST", "automatic",
          ("WP users public REST listing",)),
    Check("WP-02", "Identity", "Anonymous REST edit-context user data", "automatic",
          ("WP users private edit context",)),
    Check("WP-03", "Identity", "Anonymous /users/me privilege exposure", "automatic",
          ("WP REST current user (anonymous)",)),
    Check("WP-04", "Identity", "Author archive redirects (bounded IDs)", "automatic",
          ("WP author archive ID",)),
    Check("WP-05", "Identity", "Read-only REST settings authorization", "automatic",
          ("WP REST settings (anonymous)",), WP_AUTH),
    Check("WP-06", "Identity", "Read-only plugin administration permissions", "automatic",
          ("WP REST plugin administration (anonymous)",), WP_AUTH),
    Check("WP-07", "Identity", "Read-only theme administration permissions", "automatic",
          ("WP REST themes administration (anonymous)",), WP_AUTH),
    Check("WP-08", "Identity", "Application Passwords metadata protections", "automatic",
          ("WP REST app-password list (anonymous)",), WP_AUTH),
    Check("WP-09", "Login", "Login form and routing", "automatic",
          ("WP login form",)),
    Check("WP-10", "Login", "Registration form availability", "automatic",
          ("WP registration form",)),
    Check("WP-11", "Login", "Password reset page (no emails sent)", "automatic",
          ("WP password reset form",)),
    Check("WP-12", "Login", "Multisite signup activation", "automatic",
          ("WP network signup", "WP account activation")),
    Check("WP-13", "Login", "Single valid test-account login", "opt-in",
          ("WP single test-account login",), WP_AUTH),
    Check("WP-14", "Login", "Authenticated profile/session confirmation", "opt-in",
          ("WP login session verification", "WP REST authenticated identity"), WP_AUTH),
    Check("WP-15", "Login", "Role capability comparison (auth vs anon)", "opt-in",
          ("WP role boundary:", "WooCommerce role boundary:"), WP_AUTH),
    Check("WP-16", "Login", "REST Application Password authentication", "opt-in",
          ("WP REST authenticated identity",), WP_AUTH),
    Check("WP-17", "Login", "Login-error username guessing", "manual",
          (), HACKTRICKS),
    Check("WP-18", "XML-RPC", "XML-RPC GET/POST protocol reachability", "automatic",
          ("XML-RPC endpoint GET",)),
    Check("WP-19", "XML-RPC", "system.listMethods enumeration", "automatic",
          ("XML-RPC system.listMethods",)),
    Check("WP-20", "XML-RPC", "system.getCapabilities introspection", "automatic",
          ("XML-RPC system.getCapabilities",)),
    Check("WP-21", "XML-RPC", "Unknown-method fault interpretation", "automatic",
          ("XML-RPC unknown method fault",)),
    Check("WP-22", "XML-RPC", "Malformed XML fault handling", "automatic",
          ("XML-RPC malformed XML fault",)),
    Check("WP-23", "XML-RPC", "Single valid test-account XML-RPC auth", "opt-in",
          ("WP XML-RPC test-account authentication",)),
    Check("WP-24", "XML-RPC", "Multicall/pingback method presence", "automatic",
          ("XML-RPC system.listMethods",)),
    Check("WP-25", "XML-RPC", "Pingback SSRF OAST (not auto-invoked)", "manual", ()),
    Check("WP-26", "XML-RPC", "XML-RPC multicall brute-force and DoS", "manual", ()),
    Check("WP-27", "REST/AJAX", "WP/WooCommerce REST and namespaces", "automatic",
          ("/wp-json/",)),
    Check("WP-28", "REST/AJAX", "WordPress AJAX action discovery", "automatic",
          ("AJAX action ", "AJAX discovery"), HACKTRICKS),
    Check("WP-29", "REST/AJAX", "GET action response comparisons", "opt-in",
          ("AJAX action ",)),
    Check("WP-30", "REST/AJAX", "WooCommerce Store API and reviews", "automatic",
          ("/wp-json/wc/store/v1/",)),
    Check("WP-31", "REST/AJAX", "Dynamic REST routes from the API index", "automatic",
          ("discovered URL check",)),
    Check("WP-32", "REST/AJAX", "Nonce/capability source review of custom routes", "manual",
          ()),
    Check("WP-33", "Files/Setup", "Exposed wp-config backup artifacts", "automatic",
          ("WordPress artifact config",)),
    Check("WP-34", "Files/Setup", "Public WordPress debug/PHP log", "automatic",
          ("WordPress artifact debug",)),
    Check("WP-35", "Files/Setup", "Uploads directory indexing", "automatic",
          ("WordPress artifact listing uploads",)),
    Check("WP-36", "Files/Setup", "WordPress installer still reachable", "automatic",
          ("WP installation wizard",)),
    Check("WP-37", "Files/Setup", "Unauthenticated WordPress database repair page", "automatic",
          ("WP database repair interface",)),
    Check("WP-38", "Files/Setup", "Plugin/theme direct PHP code execution", "manual", ()),
    Check("WP-39", "Surface", "Administrator access-control differential", "automatic",
          ("403 differential",)),
    Check("WP-40", "Surface", "WordPress URL path/header variants", "automatic",
          ("path payload", "header payload ")),
    Check("WP-41", "Surface", "HTTP HEAD/OPTIONS response checks", "automatic",
          ("HTTP method ",)),
    Check("WP-42", "Surface", "HTML/JS URL discovery and follow-up", "automatic",
          ("discovered URL check",)),
    Check("WP-43", "Surface", "WP-Cron DoS or load tests", "manual", ()),
    Check("WP-44", "Surface", "Generic XSS/SQLi/IDOR exploit payloads", "manual", ()),
    Check("WP-45", "Surface", "Optional configured OAST SSRF injection", "opt-in",
          ("opt-in SSRF OAST injection",)),
    Check("WP-46", "Comments", "Public comments and reviews read", "automatic",
          ("/wp-json/wp/v2/comments",)),
    Check("WP-47", "Comments", "Search for a supplied comment marker", "opt-in",
          ("comment search ", "HTML marker search")),
    Check("WP-48", "Comments", "One comment submission and public read-back", "opt-in",
          ("opt-in comment POST", "comment unauthenticated read-back")),
    Check("WP-49", "Files/Setup", "Public .env WordPress configuration", "automatic",
          ("WordPress artifact env",)),
    Check("WP-50", "Files/Setup", "Public Git HEAD of deployed WordPress installation", "automatic",
          ("WordPress artifact git",)),
    Check("WP-51", "Files/Setup", "Plugin/theme directory listing", "automatic",
          ("WordPress artifact listing plugins", "WordPress artifact listing themes")),
    Check("WP-52", "Plugins/Themes", "Plugin asset paths (not versions)", "automatic",
          ("WP plugin asset discovery",)),
    Check("WP-53", "Plugins/Themes", "Theme asset paths (not versions)", "automatic",
          ("WP theme asset discovery",)),
    Check("WP-54", "Login", "Read-only cross-role capability matrix", "opt-in",
          ("WP role-session identity", "WP role-session permission"), WP_AUTH),
    Check("WP-55", "Core Misconfig", "Anonymous access to draft posts", "automatic",
          ("WP private draft posts",), WP_REST),
    Check("WP-56", "Core Misconfig", "Anonymous access to private posts", "automatic",
          ("WP private posts",), WP_REST),
    Check("WP-57", "Core Misconfig", "Anonymous access to pending posts", "automatic",
          ("WP pending posts",), WP_REST),
    Check("WP-58", "Core Misconfig", "Anonymous access to draft pages", "automatic",
          ("WP private draft pages",), WP_REST),
    Check("WP-59", "Core Misconfig", "Anonymous access to private pages", "automatic",
          ("WP private pages",), WP_REST),
    Check("WP-60", "Core Misconfig", "Anonymous access to moderated comments", "automatic",
          ("WP pending comment moderation",), WP_REST),
    Check("WP-61", "Core Misconfig", "Anonymous access to spam comments", "automatic",
          ("WP spam comment moderation",), WP_REST),
    Check("WP-62", "Core Misconfig", "Anonymous exposure of comment moderator fields", "automatic",
          ("WP private comment edit fields",), WP_REST),
    Check("WP-63", "Comments", "Published post comment settings from REST", "automatic",
          ("WP public comment configuration",), WP_REST),
    Check("WP-64", "Core Misconfig", "Alternate rest_route private posts exposure", "automatic",
          ("WP alternate REST private posts",), WP_REST),
    Check("WP-65", "Core Misconfig", "Alternate rest_route moderated comments", "automatic",
          ("WP alternate REST moderated comments",), WP_REST),
    Check("WP-66", "Core Misconfig", "Alternate rest_route private users", "automatic",
          ("WP alternate REST private user fields",), WP_REST),
    Check("WP-67", "Core Misconfig", "Alternate rest_route admin settings", "automatic",
          ("WP alternate REST administrative settings",), WP_REST),
    Check("WP-68", "Core Misconfig", "Cross-channel REST permission comparisons", "automatic",
          ("WP REST channel comparison",), WP_REST),
    Check("WP-69", "AJAX", "Unknown action versus dispatcher baseline", "automatic",
          ("WP AJAX unknown action",), WP_REST),
    Check("WP-70", "XML-RPC", "GET/POST method policy correlation", "automatic",
          ("WP XML-RPC method policy",), WP_REST),
]

MANUAL_REASON = {
    "WP-17": "Username guessing could trigger lockouts; not sent automatically",
    "WP-25": "Pingback method is only enumerated; no pingback invocation to an external host",
    "WP-26": "Multicall brute-force/DoS explicitly excluded",
    "WP-32": "Source-level review of custom callback permissions required",
    "WP-38": "No plugin/theme PHP execution or payload uploads",
    "WP-43": "wp-cron can trigger scheduled tasks; never load-tested",
    "WP-44": "General XSS/SQLi/IDOR explicitly outside scanner scope",
}
OPTIONAL_REASON = {
    "WP-13": "Supply --login-user and a login password environment variable",
    "WP-14": "Supply a session/nonce or application password for one test account",
    "WP-15": "Requires valid test-account identity; no role guessing",
    "WP-16": "Supply --auth-user and an Application Password environment variable",
    "WP-23": "Valid test Application Password required",
    "WP-29": "GET handlers can mutate state; use --ajax-probe",
    "WP-45": "Explicit --ssrf and in-scope endpoint required",
    "WP-47": "Supply --search-comment MARKER",
    "WP-48": "Explicit --post-comment and --comment-post-id required",
    "WP-54": "Provide one or more --role-request LABEL:BURP_REQUEST_FILE",
}


def coverage(auditor):
    """Return status for each source-backed check, including the unexecuted ones."""
    rows = auditor.results
    result = []
    for check in CHECKS:
        matches = [r for r in rows if any(
            r.name.startswith(prefix) for prefix in check.starts)]
        if check.check_id == "WP-28" and not matches:
            phase = next((p for p in auditor.phase_stats
                          if "HTML/JavaScript crawling" in p["name"]), None)
            if phase and phase["requests"]:
                status, reason = "CHECKED", "Inspected HTML/JS; %d action names extracted" % (
                    len(auditor.ajax_actions))
            else:
                status, reason = "SKIPPED", "AJAX crawling did not execute"
        elif check.check_id == "WP-31" and not any(
                r.name.startswith("discovered URL check") and
                "/wp-json/" in r.url for r in matches):
            # WordPress REST route discovery is not the same as generic URL crawling.
            rest = [r for r in rows if r.name.startswith("discovered URL check")
                    and "/wp-json/" in r.url]
            if rest:
                status, reason = "CHECKED", "%d REST paths probed" % len(rest)
            else:
                status, reason = "SKIPPED", "No discovered REST route was probed"
        elif matches:
            passive = check.check_id in ("WP-52", "WP-53")
            error = all(r.status is None for r in matches) and not passive
            blocked = all(r.status in (401, 403) for r in matches)
            partial = check.check_id in ("WP-12", "WP-48", "WP-51") and any(
                not any(r.name.startswith(prefix) for r in matches)
                for prefix in check.starts
            )
            status = ("ERROR" if error else "BLOCKED" if blocked else
                      "PARTIAL" if partial else "CHECKED")
            reason = ("%d passive asset analysis result(s)" if passive
                      else "%d recorded HTTP check result(s)") % len(matches)
            if partial:
                reason += "; not all paired tests completed"
        elif check.mode == "manual":
            status, reason = "MANUAL", MANUAL_REASON.get(check.check_id, "Requires authorized manual review")
        elif check.mode == "opt-in":
            status, reason = "OPT-IN", OPTIONAL_REASON.get(check.check_id, "Requires explicit parameter")
        else:
            status = "SKIPPED"
            reason = ("Not reached; request budget, disabled module or no eligible candidate. "
                      "No test was claimed.")
        result.append({
            "id": check.check_id, "category": check.group, "check": check.label,
            "mode": check.mode, "status": status, "reason": reason, "source": check.source,
        })
    return result


def summary(items):
    c = Counter(x["status"] for x in items)
    return "  ".join("%s:%d" % (s, c.get(s, 0))
                     for s in ("CHECKED", "PARTIAL", "BLOCKED", "ERROR",
                               "SKIPPED", "OPT-IN", "MANUAL"))


def describe_plan():
    lines = ["WordPress Auditor | technique coverage plan",
             "CHECKED means a test ran, NOT that the website is vulnerable.",
             ""]
    for group in dict.fromkeys(x.group for x in CHECKS):
        lines.append(group.upper())
        for x in CHECKS:
            if x.group == group:
                lines.append("  %-6s %-10s %s" % (x.check_id, x.mode, x.label))
        lines.append("")
    lines += ["Manual/opt-in techniques never run without the stated prerequisites.",
              "References: " + HACKTRICKS, "WordPress REST: " + WP_REST]
    return "\n".join(lines)


def render_coverage_markdown(items):
    lines = ["# WordPress technique coverage", "",
             "A check marked CHECKED is **not** a confirmed vulnerability.",
             "Skipped/manual/optional checks must never be counted as tested.", "",
             "| ID | Module | Technique | Execution | Reason |",
             "|---|---|---|---|---|"]
    for item in items:
        fields = [item["id"], item["category"], item["check"], item["status"],
                  item["reason"].replace("|", "/")]
        lines.append("| " + " | ".join(fields) + " |")
    lines.append("")
    lines.append("Source references: " + HACKTRICKS + " and " + WP_REST)
    return "\n".join(lines) + "\n"
