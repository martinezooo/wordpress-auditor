"""Readable scan coverage and findings with conservative evidence classification."""
from collections import Counter
from urllib.parse import urlsplit
from .auditor import report_url

DESCRIPTIONS = {
    "Explicit comment submission":
        "One user-approved comment write and independent read-back.",
    "XML-RPC protocol diagnostics":
        "GET handshake, safe metadata calls, unknown-method and malformed-XML faults.",
    "WordPress core private-content and comment checks":
        "Anonymous REST reads of drafts/private posts, pages, moderated comments "
        "and private edit fields; verify WordPress object status, not HTTP 200 alone.",
    "Admin access-control comparison":
        "Compare /wp-admin/ with a rewritten request and random-path control.",
    "Comment/review marker search":
        "Look up the supplied marker in comments, reviews and public feeds.",
    "WordPress/WooCommerce REST and public surfaces":
        "Read WP/Woo endpoints, inspect HTTP status and access restrictions.",
    "HTML/JavaScript crawling and AJAX discovery":
        "Discover in-scope links, scripts and candidate AJAX actions.",
    "HTTP HEAD/OPTIONS capability checks":
        "Query advertised methods without issuing write-method fuzzing.",
    "New and previously discovered URL verification":
        "GET newly found safe paths within the shared request budget.",
    "Path/header payload comparisons":
        "Compare route variants and selected request headers to baseline/control.",
}

def observations(auditor, rows):
    notes = []
    http = Counter(r["status"] for r in rows)
    auth = http.get(401, 0) + http.get(403, 0)
    if auth:
        notes.append(("%d responses returned 401/403; restrictions observed, "
                      "not proof of a bypass.") % auth)
    if http.get(301, 0) + http.get(302, 0) + http.get(303, 0):
        notes.append("Redirects observed. Without following Location, no privilege "
                     "change can be inferred.")
    if http.get(200, 0):
        notes.append("%d responses returned HTTP 200; this alone "
                     "does not establish access to sensitive data." % http[200])
    if not auditor.ajax_actions:
        notes.append("No AJAX action names extracted from examined pages/scripts; "
                     "unvisited or dynamic code may still expose them.")
    else:
        notes.append("%d AJAX action names extracted; handler execution is opt-in "
                     "(--ajax-probe)." % len(auditor.ajax_actions))
    xmlrpc = [r for r in rows if r["name"].startswith("XML-RPC")]
    if xmlrpc:
        methods = next((r["detail"] for r in xmlrpc
                        if "system.listMethods" in r["name"]), "")
        if methods:
            notes.append("XML-RPC method discovery: " + methods)
        else:
            first = xmlrpc[0]
            code = first["status"]
            if code not in (200, 405):
                notes.append("XML-RPC: initial GET returned HTTP %s; "
                             "further method probes were skipped." % code)
            else:
                notes.append("XML-RPC: %d read-only protocol response(s); "
                             "no authentication, pingback or multicall invoked." % len(xmlrpc))
    candidates = [r for r in rows
                  if r.get("severity", "INFO") != "INFO"]
    verified = [r for r in rows
                if r.get("confidence") == "confirmed"
                and r.get("severity") in ("HIGH", "MEDIUM", "LOW")]
    if verified:
        notes.append("%d WordPress-specific exposures verified by content signatures; "
                     "review raw server behavior before reporting." % len(verified))
    else:
        notes.append("No vulnerability has been independently confirmed by this scan.")
    return notes, candidates


def format_terminal(auditor, rows, verbose=False, target=None):
    target = report_url(target or auditor.base)
    states = Counter(
        str(r["status"]) if r["status"] is not None
        else "PASSIVE" if r["name"] in ("WP plugin asset discovery",
                                        "WP theme asset discovery") else "ERR"
        for r in rows)
    unique_verified = auditor.wordlist & (
        getattr(auditor, "successful_get_urls", set()) |
        getattr(auditor, "prior_verified_urls", set()))
    unverified = max(0, len(auditor.wordlist) - len(unique_verified))
    lines = [
        "WORDPRESS AUDITOR / " + auditor.scan_mode.upper() + " SCAN",
        "Target: " + target,
        "Requests %d/%d  |  Recorded results: %d" %
        (auditor.request_count, auditor.limit, len(rows)),
        "Discovered URLs: %d  |  Fetched: %d  |  Not fetched: %d" %
        (len(auditor.wordlist), len(unique_verified), unverified),
        "AJAX actions: %d  |  Plugin assets: %d  |  Themes: %d" %
        (len(auditor.ajax_actions), len(auditor.plugin_slugs), len(auditor.theme_slugs)),
        "Payload variants %d  |  Method probes: %d" %
        (auditor.payload_cases, auditor.method_checks),
        "SEVERITY: " + "  ".join("%s:%d" % (level, sum(
            r.get("severity", "INFO") == level for r in rows))
            for level in ("HIGH", "MEDIUM", "LOW", "REVIEW", "INFO")),
        "",
        "WHAT THE ENGINE ACTUALLY DID",
    ]
    for phase in auditor.phase_stats:
        status = phase["state"]
        if status == "skipped":
            lines.append("  [SKIP] %-38s %s" % (phase["name"], phase["reason"]))
        elif status == "no-requests":
            lines.append("  [NONE] %-38s %s" % (phase["name"], phase["reason"]))
        else:
            lines.append("  [DONE] %-38s %3d requests / %3d results" %
                         (phase["name"], phase["requests"], phase["checks"]))
    if getattr(auditor, "coverage_rows", None):
        lines += ["", "WORDPRESS TECHNIQUE COVERAGE",
                  "  " + auditor.coverage_summary,
                  "  CHECKED means requests/results inspected, NOT a vulnerability."]
        from collections import Counter as _Counts
        grouped = {}
        for item in auditor.coverage_rows:
            counts = grouped.setdefault(item["category"], _Counts())
            counts[item["status"]] += 1
        for category, counts in grouped.items():
            tested = counts["CHECKED"] + counts["PARTIAL"] + counts["BLOCKED"] + counts["ERROR"]
            all_count = sum(counts.values())
            lines.append("  %-12s %2d/%-2d attempted | %d partial | %d blocked | %d pending" % (
                category, tested, all_count, counts["PARTIAL"], counts["BLOCKED"],
                counts["SKIPPED"] + counts["OPT-IN"] + counts["MANUAL"]))
    lines += ["", "Discovered-URL checks: %d" % auditor.discovered_checks,
              "", "RECORDED CHECK RESPONSES (excludes crawl-only requests)",
              "  " + ("  ".join("%s:%s" % (k, v) for k, v in sorted(states.items()))
                      if states else "No responses")]
    notes, candidates = observations(auditor, rows)
    lines += ["", "OBSERVATIONS (not confirmed vulnerabilities)"]
    lines += ["  - " + note for note in notes[:7]]
    for status in (401, 403):
        seen = set()
        examples = []
        for row in rows:
            if row["status"] != status:
                continue
            path = urlsplit(row["url"]).path
            if path not in seen and not row["name"].startswith(
                    ("path payload", "header payload", "HTTP method ")):
                examples.append(path)
                seen.add(path)
            if len(examples) >= 3:
                break
        if examples:
            lines.append("  - %s examples: %s" % (status, ", ".join(examples)))
    if candidates:
        lines += ["", "FINDINGS / ACTIONABLE OBSERVATIONS (%d)" % len(candidates)]
        priority = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "REVIEW": 3, "INFO": 4}
        for r in sorted(candidates, key=lambda row: priority.get(
                row.get("severity", "INFO"), 4))[:8]:
            path = urlsplit(r["url"]).path
            lines.append("  - [%s] %s %s (HTTP %s): %s" %
                         (r.get("severity", "REVIEW"), r["name"][:32], path,
                          r["status"], r["detail"][:110]))
        if len(candidates) > 8:
            lines.append("  - ... %d more in JSON" % (len(candidates) - 8))
    lines += ["", "COVERAGE & LIMITATIONS"]
    if unverified:
        lines.append("  - %d discovered URL paths were not fetched "
                     "(budget, safety filters or scheduling)." % unverified)
    if len(auditor.wordlist) > 0 and len(unique_verified) == 0:
        lines.append("  - Discovery alone is not a security check: zero paths verified.")
    if auditor.request_count >= auditor.limit:
        lines.append("  - Global request budget EXHAUSTED; some phases were truncated.")
    elif auditor.request_count < auditor.limit and unverified:
        lines.append("  - Unused budget: %d requests. Not all discoveries are safe "
                     "to probe automatically." %
                     (auditor.limit - auditor.request_count))
    if auditor.scan_mode == "quick":
        lines.append("  - Quick mode omits deeper REST, XML-RPC and method checks.")
    lines.append("  - Severity labels are evidence-gated; HTTP 200/403 alone is INFO.")
    lines.append("  - HIGH/MEDIUM/LOW reflect confirmed WordPress artifact content, "
                 "REVIEW is NOT a confirmed vulnerability.")
    lines.append("  - Anonymous access was not compared to all WordPress roles.")
    lines.append("  - No XSS/SQLi/IDOR is confirmed from HTTP status differences.")
    if getattr(auditor, "coverage_rows", None):
        pending = [r for r in auditor.coverage_rows if r["status"] in ("SKIPPED", "OPT-IN")]
        if pending:
            lines.append("  - %d WordPress techniques need prerequisites or were skipped; "
                         "inspect coverage.json." % len(pending))
            for item in pending[:4]:
                lines.append("    %s %s: %s" % (
                    item["id"], item["status"], item["reason"][:115]))
    if not any(r["name"] == "opt-in SSRF OAST injection" for r in rows):
        lines.append("  - No SSRF/OAST injection was attempted (requires --ssrf).")
    else:
        lines.append("  - SSRF OAST sent once; confirm the callback separately.")
    if verbose:
        lines += ["", "INDIVIDUAL CHECKS"]
        for row in rows:
            lines.append("  %3s %-30s %-25s %s" %
                         (str(row["status"]), row["name"][:30],
                          urlsplit(row["url"]).path[:25], row["detail"][:90]))
    return "\n".join(lines)


def format_markdown(auditor, rows):
    output = format_terminal(auditor, rows)
    return ("# WordPress Auditor - scan interpretation\n\n~~~text\n"
            + output + "\n~~~\n\n## Methodology\n\n"
            + "\n".join("- **%s:** %s" % (k, v) for k, v in DESCRIPTIONS.items())
            + "\n\nFindings are tentative unless independently verified. "
              "All HTTP tests used the selected origin and request budget.\n")
