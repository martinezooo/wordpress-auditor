import argparse
import csv
import io
import json
import os

from .auditor import Auditor, parse_burp


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
    p.add_argument("--delay", type=float, default=0)
    p.add_argument("--max-requests", type=int, default=30)
    p.add_argument("--depth", type=int, default=1)
    p.add_argument("--full", action="store_true")
    p.add_argument("--xmlrpc", action="store_true")
    p.add_argument("--ajax-probe", action="store_true")
    p.add_argument("--no-ajax", action="store_true")
    p.add_argument("--wordlist-out")
    p.add_argument("--format", choices=("json", "csv", "md"), default="json")
    p.add_argument("--output")
    a = p.parse_args(argv)
    if a.max_requests < 1 or a.delay < 0 or a.timeout <= 0:
        p.error("--max-requests must be positive, --delay nonnegative, --timeout positive")
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
    results = auditor.discover(a.marker, a.post_comment, post_id=a.comment_post_id,
                               depth=a.depth, full=a.full, xmlrpc=a.xmlrpc,
                               search_comment=a.search_comment or a.marker,
                               languages=a.languages.split(",") if a.languages else None,
                               comment_mode=a.comment_mode, comment_name=a.comment_author,
                               comment_email=a.comment_email, ajax_probe=a.ajax_probe,
                               no_ajax=a.no_ajax)
    wordlist_out = a.wordlist_out
    if not wordlist_out and a.output:
        wordlist_out = os.path.join(os.path.dirname(os.path.abspath(a.output)), "wordlist.txt")
    if wordlist_out:
        os.makedirs(os.path.dirname(os.path.abspath(wordlist_out)), exist_ok=True)
        with open(wordlist_out, "w", encoding="utf-8") as f:
            f.write("".join(url + "\n" for url in sorted(auditor.wordlist)))
        with open(os.path.join(os.path.dirname(os.path.abspath(wordlist_out)), "ajax-actions.txt"),
                  "w", encoding="utf-8") as f:
            f.write("".join(action + "\n" for action in sorted(auditor.ajax_actions)))
    rows = [r.__dict__ for r in results]
    if a.format == "json":
        out = json.dumps(rows, indent=2)
    elif a.format == "csv":
        s = io.StringIO()
        w = csv.DictWriter(s, fieldnames=["name", "url", "status", "visibility", "detail"])
        w.writeheader(); w.writerows(rows); out = s.getvalue()
    else:
        out = "| Name | URL | Status | Visibility | Detail |\n|---|---|---:|---|---|\n"
        out += "".join(f"| {r['name']} | {r['url']} | {r['status']} | {r['visibility']} | {r['detail']} |\n" for r in rows)
    if a.output:
        with open(a.output, "w", encoding="utf-8") as f:
            f.write(out)
    else:
        print(out)
