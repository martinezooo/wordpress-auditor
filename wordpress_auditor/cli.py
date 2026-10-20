import argparse
import csv
import io
import json
import os
import sys
from collections import Counter
from urllib.parse import urlsplit

from .probes import safe_candidate

from .auditor import Auditor, parse_burp, report_url
from .probes import ssrf_oast_probe
from .reporting import format_terminal, format_markdown


def summarize(auditor, rows, verbose=False):
    """Human-readable coverage, observations and remaining limitations."""
    return format_terminal(auditor, rows, verbose=verbose)


def render_details(rows, fmt):
    if fmt == "json":
        return json.dumps(rows, indent=2, ensure_ascii=False)
    if fmt == "csv":
        s = io.StringIO()
        w = csv.DictWriter(s, fieldnames=["name", "url", "status", "visibility", "detail"])
        w.writeheader()
        w.writerows(rows)
        return s.getvalue()
    if fmt == "md":
        out = "| Name | URL | Status | Visibility | Detail |\n|---|---|---:|---|---|\n"
        for r in rows:
            values = [str(r[k]).replace("|", "\\|").replace("\n", " ") for k in
                      ("name", "url", "status", "visibility", "detail")]
            out += "| " + " | ".join(values) + " |\n"
        return out
    raise ValueError("Unsupported detailed format: " + fmt)


def main(argv=None):
    p = argparse.ArgumentParser(description="bounded WordPress visibility auditor")
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument("--url")
    g.add_argument("--request", help="file containing a raw Burp request")
    p.add_argument("--timeout", type=float, default=8)
    p.add_argument("--languages", help="comma-separated locale prefixes, e.g. en,fr")
    p.add_argument("--scheme", choices=("http", "https"), default=None)
    p.add_argument("--authorized", action="store_true", help="allow supplied credentials and classify authenticated visibility")
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
    p.add_argument("--deep", action="store_true",
                   help="larger in-scope GET/header payload suite (implies --full)")
    p.add_argument("--payloads", metavar="ZIP_OR_DIR",
                   help="import the previous Burp Intruder 01_headers / 02_urls wordlists")
    p.add_argument("--payload-limit", type=int, default=None,
                   help="max path/header variants in one scan")
    p.add_argument("--no-probe-discovered", action="store_true",
                   help="record but do not automatically GET discovered URLs")
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
        with open(a.request, encoding="utf-8") as f:
            url, burp_headers, _ = parse_burp(f.read(), a.scheme or "https")
        headers = {**burp_headers, **headers}
    else:
        url = a.url
    auditor = Auditor(url, headers, a.cookie, a.proxy, limit=a.max_requests, delay=a.delay, timeout=a.timeout,
                      authorized=a.authorized, scheme=a.scheme)
    if a.progress or (sys.stderr.isatty() and a.format == "summary"):
        def progress(event, title, auditor, phase=None):
            if event == "start":
                print("  => " + title + " ...", file=sys.stderr, flush=True)
            elif phase is not None:
                print("     %d requests; %d results; budget %d/%d" %
                      (phase["requests"], phase["checks"], auditor.request_count, auditor.limit),
                      file=sys.stderr, flush=True)
        auditor.progress_callback = progress
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
                               probe_discovered=not a.no_probe_discovered, deep=a.deep)
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
    rows = [r.__dict__ for r in results]
    summary = summarize(auditor, rows, verbose=a.verbose)
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
        print(summary)
        print("Saved full report: " + a.output)
    elif a.format == "summary":
        report_path = os.path.join(os.path.dirname(os.path.abspath(wordlist_out)),
                                   "latest-report.json")
        with open(report_path, "w", encoding="utf-8") as f:
            f.write(render_details(rows, "json"))
        print(summary)
        print("Detailed JSON: " + report_path)
    else:
        print(render_details(rows, a.format))
