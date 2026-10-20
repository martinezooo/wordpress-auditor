import argparse
import csv
import io
import json
import os
import sys
from collections import Counter
from urllib.parse import urlsplit
import ipaddress

from .probes import safe_candidate

from .auditor import Auditor, parse_burp, report_url
from .probes import ssrf_oast_probe
from .reporting import format_terminal, format_markdown
from .console import LivePrinter, supports_color, color_summary
from .check_catalog import coverage as build_coverage, summary as coverage_summary
from .check_catalog import describe_plan, render_coverage_markdown
from .wp_identity import Credentials, RoleSession
from .queue import load_previous as load_url_queue, save as save_url_queue


def summarize(auditor, rows, verbose=False):
    """Human-readable coverage, observations and remaining limitations."""
    return format_terminal(auditor, rows, verbose=verbose)


def render_details(rows, fmt):
    if fmt == "json":
        return json.dumps(rows, indent=2, ensure_ascii=False)
    if fmt == "csv":
        s = io.StringIO()
        w = csv.DictWriter(s, fieldnames=["name", "url", "status", "visibility", "detail",
                                           "severity", "confidence"])
        w.writeheader()
        w.writerows(rows)
        return s.getvalue()
    if fmt == "md":
        out = "| Name | URL | Status | Severity | Confidence | Visibility | Detail |\n|---|---|---:|---|---|---|---|\n"
        for r in rows:
            values = [str(r[k]).replace("|", "\\|").replace("\n", " ") for k in
                      ("name", "url", "status", "severity", "confidence", "visibility", "detail")]
            out += "| " + " | ".join(values) + " |\n"
        return out
    raise ValueError("Unsupported detailed format: " + fmt)


def main(argv=None):
    p = argparse.ArgumentParser(description="bounded WordPress visibility auditor")
    g = p.add_mutually_exclusive_group(required=False)
    g.add_argument("--url")
    g.add_argument("--request", help="file containing a raw Burp request")
    p.add_argument("--list-checks", action="store_true",
                   help="print all WordPress checks and opt-in/manual requirements; no network")
    p.add_argument("--timeout", type=float, default=8)
    p.add_argument("--languages", help="comma-separated locale prefixes, e.g. en,fr")
    p.add_argument("--scheme", choices=("http", "https"), default=None)
    p.add_argument("--authorized", action="store_true", help="allow supplied credentials and classify authenticated visibility")
    p.add_argument("--no-identity", action="store_true",
                   help="skip WordPress users/login/REST permission checks")
    p.add_argument("--auth-user", metavar="USERNAME",
                   help="valid WordPress test account for REST Application Password verification")
    p.add_argument("--app-password-env", default="WPAUDITOR_APP_PASSWORD",
                   help="environment variable holding its Application Password; never appears in reports")
    p.add_argument("--role-request", action="append", default=[], metavar="ROLE:FILE",
                   help="one authorized Burp request/session per WordPress role; can repeat")
    p.add_argument("--login-user", metavar="USERNAME",
                   help="valid test username for ONE wp-login.php login; never guesses usernames")
    p.add_argument("--login-password-env", default="WPAUDITOR_LOGIN_PASSWORD",
                   help="environment variable holding test account's primary password")
    p.add_argument("--cookie")
    p.add_argument("--header", action="append", default=[])
    p.add_argument("--proxy")
    p.add_argument("--marker")
    p.add_argument("--post-comment", action="store_true")
    p.add_argument("--comment-mode", choices=("rest", "form"), default="rest")
    p.add_argument("--comment-post-id", type=int)
    p.add_argument("--comment-author", default="Auditor")
    p.add_argument("--comment-email", default="auditor@example.invalid")
    p.add_argument("--search-comment", metavar="TEXT",
                   help="search this literal term in public comment/review sources")
    p.add_argument("--delay", type=float, default=0.2)
    p.add_argument("--max-requests", type=int, default=None)
    p.add_argument("--depth", type=int, default=1)
    p.add_argument("--full", action="store_true", help="smart/full scan (the default)")
    p.add_argument("--quick", action="store_true",
                   help="small preliminary scan instead of the default smart audit")
    p.add_argument("--progress", action="store_true",
                   help="stream scan phase progress to stderr (TTY enables automatically)")
    p.add_argument("--progress-every", type=int, default=5,
                   help="show progress every N HTTP requests (default 5)")
    p.add_argument("--color", choices=("auto", "always", "never"), default="auto",
                   help="ANSI colors in interactive terminal (default auto)")
    p.add_argument("--no-color", action="store_const", const="never", dest="color",
                   help="disable ANSI colors even on a TTY")
    p.add_argument("--deep", action="store_true",
                   help="larger in-scope GET/header payload suite (implies --full)")
    p.add_argument("--payloads", metavar="ZIP_OR_DIR",
                   help="import the previous Burp Intruder 01_headers / 02_urls wordlists")
    p.add_argument("--payload-limit", type=int, default=None,
                   help="max path/header variants in one scan")
    p.add_argument("--no-probe-discovered", action="store_true",
                   help="record but do not automatically GET discovered URLs")
    p.add_argument("--recheck-urls", action="store_true",
                   help="recheck already verified paths (default: prioritize pending paths)")
    p.add_argument("--ssrf", action="store_true",
                   help="send ONE explicit OAST injection to a chosen in-scope endpoint")
    p.add_argument("--collaborator-url", help="external HTTPS callback URL in your Collaborator")
    p.add_argument("--ssrf-path", help="explicit in-scope path to test for URL fetching")
    p.add_argument("--ssrf-param", help="parameter on endpoint which accepts a URL")
    p.add_argument("--ssrf-action", help="optional WordPress AJAX action name")
    p.add_argument("--ssrf-method", choices=("GET", "POST"), default="GET")
    p.add_argument("--xmlrpc", action="store_true")
    p.add_argument("--ajax-probe", action="store_true")
    p.add_argument("--no-ajax", action="store_true")
    p.add_argument("--wordlist-out")
    p.add_argument("--format", choices=("summary", "json", "csv", "md"), default="summary")
    p.add_argument("--verbose", action="store_true", help="show each checked endpoint")
    p.add_argument("--output", "--out", help="save report (extension .json, .csv, .md)")
    a = p.parse_args(argv)
    if a.list_checks:
        print(describe_plan())
        return 0
    if not (a.url or a.request):
        p.error("one of --url or --request is required (or --list-checks)")
    if a.quick and (a.deep or a.full):
        p.error("--quick is incompatible with --deep and --full")
    if not a.quick:
        a.full = True
    if a.deep:
        a.full = True
    if a.max_requests is None:
        a.max_requests = 350 if a.deep else 180 if a.full else 60
    if a.payload_limit is None:
        a.payload_limit = 160 if a.deep else 36 if a.full else 6
    if a.max_requests < 1 or a.delay < 0 or a.timeout <= 0:
        p.error("--max-requests must be positive, --delay nonnegative, --timeout positive")
    if a.progress_every < 1:
        p.error("--progress-every must be positive")
    if not 0 <= a.payload_limit <= 1000:
        p.error("--payload-limit must be between 0 and 1000")
    if a.ssrf and not (a.collaborator_url and a.ssrf_path and a.ssrf_param):
        p.error("--ssrf requires --collaborator-url, --ssrf-path, and --ssrf-param")
    if not a.ssrf and any((a.collaborator_url, a.ssrf_path, a.ssrf_param, a.ssrf_action)):
        p.error("SSRF-specific flags require --ssrf")
    if a.post_comment and (a.comment_post_id is None or a.comment_post_id < 1):
        p.error("--post-comment requires a positive --comment-post-id")
    headers = {}
    for item in a.header:
        if ":" not in item:
            p.error("--header must be NAME: VALUE")
        k, v = item.split(":", 1)
        headers[k.strip()] = v.strip()
    if a.request:
        # Preserve Burp's HTTP/1.1 CRLF framing exactly. Text mode normally
        # translates CRLF to LF and breaks strict request parsing.
        with open(a.request, encoding="utf-8", newline="") as f:
            url, burp_headers, _ = parse_burp(f.read(), a.scheme or "https")
        headers = {**burp_headers, **headers}
    else:
        url = a.url
    creds = Credentials()
    if a.auth_user:
        if not a.auth_user.strip():
            p.error("--auth-user must not be empty")
        secret = os.environ.get(a.app_password_env, "")
        if not secret:
            p.error("--auth-user requires a nonempty application password environment variable")
        creds.username = a.auth_user
        creds.application_password = secret
    if a.login_user:
        if not a.login_user.strip():
            p.error("--login-user must not be empty")
        secret = os.environ.get(a.login_password_env, "")
        if not secret:
            p.error("--login-user requires a nonempty login password environment variable")
        creds.login_user = a.login_user
        creds.login_password = secret
    if a.role_request:
        import re as _re
        for supplied in a.role_request[:5]:
            role, delim, filepath = supplied.partition(":")
            if not delim or not filepath or not _re.fullmatch(r"[A-Za-z0-9_-]{1,30}", role):
                p.error("--role-request requires a safe ROLE:FILE combination")
            try:
                with open(filepath, encoding="utf-8", newline="") as f:
                    session_url, session_headers, _ = parse_burp(
                        f.read(), a.scheme or urlsplit(url).scheme)
            except (OSError, ValueError):
                p.error("unable to parse --role-request as a valid HTTP/1.1 Burp request")
            supplied_url = urlsplit(session_url)
            target_url = urlsplit(url)
            same_origin = (
                supplied_url.scheme.lower(),
                (supplied_url.hostname or "").lower(),
                supplied_url.port or (443 if supplied_url.scheme == "https" else 80)
            ) == (
                (a.scheme or target_url.scheme).lower(),
                (target_url.hostname or "").lower(),
                target_url.port or (443 if (a.scheme or target_url.scheme) == "https" else 80)
            )
            if not same_origin:
                p.error("--role-request origin differs from the scan target")
            creds.role_sessions.append(RoleSession(role, session_headers))
        if len(a.role_request) > 5:
            p.error("at most five test-role sessions can be supplied")
    if a.quick and (a.auth_user or a.login_user or a.role_request):
        p.error("account tests run in the default smart mode, not --quick")
    parsed_target = urlsplit(url)
    if a.auth_user or a.login_user or a.role_request:
        host = parsed_target.hostname or ""
        try:
            local = ipaddress.ip_address(host).is_loopback
        except ValueError:
            local = host.lower() == "localhost"
        target_scheme = a.scheme or parsed_target.scheme
        if target_scheme != "https" and not local:
            p.error("test account credentials require HTTPS (except localhost/127.0.0.1)")
    auditor = Auditor(url, headers, a.cookie, a.proxy, limit=a.max_requests, delay=a.delay,
                      timeout=a.timeout, authorized=a.authorized or bool(a.auth_user or a.login_user
                                                                         or a.role_request),
                      scheme=a.scheme)
    live = a.progress or a.verbose or (sys.stderr.isatty() and a.format == "summary")
    presenter = LivePrinter(
        enabled=live, color=supports_color(sys.stderr, a.color),
        every=a.progress_every, verbose=a.verbose, stream=sys.stderr)
    auditor.progress_callback = presenter.phase if live else None
    auditor.request_progress_callback = presenter.request if live else None
    auditor.finding_callback = presenter.finding if live else None
    if a.payloads:
        # Validate local payload input before contacting any target.
        from .probes import get_payloads
        get_payloads(auditor, a.payloads)
    wordlist_out = a.wordlist_out
    if not wordlist_out:
        directory = os.path.dirname(os.path.abspath(a.output)) if a.output else os.path.abspath("audit")
        wordlist_out = os.path.join(directory, "wordlist.txt")
    if os.path.isfile(wordlist_out):
        # Merge previous in-scope discoveries so the next scan rechecks them.
        with open(wordlist_out, encoding="utf-8", errors="replace") as old:
            for idx, entry in enumerate(old):
                if idx >= 5000:
                    break
                entry = entry.strip()
                if len(entry) > 500 or not auditor._allowed(entry):
                    continue
                parsed = urlsplit(entry)
                if safe_candidate(auditor, parsed.path):
                    auditor._wordlist_url(parsed.path)
    queue_path = os.path.join(os.path.dirname(os.path.abspath(wordlist_out)),
                              "url-queue.json")
    load_url_queue(auditor, queue_path)
    auditor.recheck_prior_urls = a.recheck_urls
    if a.ssrf:
        # Prioritize explicitly requested, single OAST injection under the shared budget.
        ssrf_oast_probe(auditor, a.ssrf_path, a.ssrf_param,
                        a.collaborator_url, method=a.ssrf_method, action=a.ssrf_action)
    results = auditor.discover(a.marker, a.post_comment, post_id=a.comment_post_id,
                               depth=a.depth, full=a.full, xmlrpc=a.xmlrpc,
                               search_comment=a.search_comment or a.marker,
                               languages=a.languages.split(",") if a.languages else None,
                               comment_mode=a.comment_mode, comment_name=a.comment_author,
                               comment_email=a.comment_email, ajax_probe=a.ajax_probe,
                               no_ajax=a.no_ajax, payloads=a.payloads,
                               payload_limit=a.payload_limit,
                               probe_discovered=not a.no_probe_discovered, deep=a.deep,
                               identity_credentials=creds, disable_identity=a.no_identity)
    os.makedirs(os.path.dirname(os.path.abspath(wordlist_out)), exist_ok=True)
    with open(wordlist_out, "w", encoding="utf-8") as f:
        f.write("".join(url + "\n" for url in sorted(auditor.wordlist)))
    actions_path = os.path.join(os.path.dirname(os.path.abspath(wordlist_out)), "ajax-actions.txt")
    old_actions = set()
    if os.path.isfile(actions_path):
        import re
        with open(actions_path, encoding="utf-8", errors="replace") as f:
            old_actions = {x.strip() for x in f if re.fullmatch(r"[A-Za-z0-9_-]{1,80}", x.strip())}
    with open(actions_path, "w", encoding="utf-8") as f:
        f.write("".join(action + "\n" for action in sorted(auditor.ajax_actions | old_actions)))
    queue = save_url_queue(auditor, queue_path)
    rows = [r.__dict__ for r in results]
    checks = build_coverage(auditor)
    auditor.coverage_rows = checks
    auditor.coverage_summary = coverage_summary(checks)
    coverage_path = os.path.join(os.path.dirname(os.path.abspath(wordlist_out)),
                                 "coverage.json")
    with open(coverage_path, "w", encoding="utf-8") as f:
        json.dump(checks, f, indent=2)
    coverage_md = os.path.join(os.path.dirname(os.path.abspath(wordlist_out)),
                               "coverage.md")
    with open(coverage_md, "w", encoding="utf-8") as f:
        f.write(render_coverage_markdown(checks))
    summary = summarize(auditor, rows, verbose=a.verbose)
    summary += "\nURL queue: %d checked, %d pending. Details: %s" % (
        queue["checked_count"], queue["pending_count"], queue_path)
    summary += "\nTechnique coverage: " + coverage_path
    summary += "\n\nSaved wordlist: " + wordlist_out
    summary_path = os.path.join(os.path.dirname(os.path.abspath(wordlist_out)),
                                "scan-summary.md")
    with open(summary_path, "w", encoding="utf-8") as f:
        f.write(format_markdown(auditor, rows))
    summary += "\nScan explanation: " + summary_path
    if a.output:
        ext = os.path.splitext(a.output)[1].lower()
        output_fmt = a.format if a.format != "summary" else {
            ".json": "json", ".csv": "csv", ".md": "md",
        }.get(ext, "json")
        os.makedirs(os.path.dirname(os.path.abspath(a.output)), exist_ok=True)
        with open(a.output, "w", encoding="utf-8") as f:
            f.write(render_details(rows, output_fmt))
        print(color_summary(summary, supports_color(sys.stdout, a.color)))
        print("Saved full report: " + a.output)
    elif a.format == "summary":
        report_path = os.path.join(os.path.dirname(os.path.abspath(wordlist_out)),
                                   "latest-report.json")
        with open(report_path, "w", encoding="utf-8") as f:
            f.write(render_details(rows, "json"))
        print(color_summary(summary, supports_color(sys.stdout, a.color)))
        print("Detailed JSON: " + report_path)
    else:
        print(render_details(rows, a.format))
