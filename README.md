# wordpress-auditor

Bounded WordPress/WooCommerce HTTP auditor. **Run only against systems you own or
have explicit permission to test.** This project does not brute-force accounts,
automatically post comments, or perform plugin-version/CVE matching.

## Install

Requires Python 3.9+. Clone the repository and install in a virtual environment:

```sh
git clone https://github.com/martinezooo/wordpress-auditor.git
cd wordpress-auditor
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e .
wordpress-auditor --help
```

## Basic usage

```sh
# Read-only reconnaissance
wordpress-auditor --url https://example.invalid --max-requests 20 --delay 0.3
# Import raw Burp HTTP/1.1 request as base URL and headers; does not replay it
wordpress-auditor --request request.txt --authorized
# Search for a marker in comments/reviews, feeds and multilingual HTML
wordpress-auditor --url https://example.invalid --search-comment 'unique-marker' --languages en,fr
# Opt-in XML-RPC protocol diagnostics: system.listMethods; never pingback or login
wordpress-auditor --url https://example.invalid --xmlrpc
# Passive same-origin AJAX discovery with stable URL/action wordlists
wordpress-auditor --url https://example.invalid --wordlist-out ./audit-wordlist.txt
# Explicit opt-in, bounded GET action checks (never POSTs or follows redirects)
wordpress-auditor --url https://example.invalid --ajax-probe --wordlist-out ./audit-wordlist.txt
# Exactly one harmless comment submission to known post ID; no implicit writes
wordpress-auditor --url https://example.invalid --post-comment --comment-post-id 42 --comment-mode form --marker 'unique-marker'
```

HTTP responses are not vulnerabilities. `401/403` indicate access controls;
`200` or `302` alone does not prove a bypass. Comment write acknowledgement
does not prove publication. Read-back independently checks public access
(without cookies) and, when configured, the authenticated session.

`--request` treats the Burp request as context, *not* as a request to replay
the original body/method. HTTPS is the default (use `--scheme http` only when
appropriate). Authorization/Cookie headers are sent only with `--authorized`;
hop-by-hop headers are removed and redirects are never followed. Query
parameters and response body snippets are omitted from saved findings.

AJAX discovery is passive by default: it reads a small bounded set of same-origin
HTML, JavaScript, REST-index and sitemap resources, then writes deduplicated
query-free URLs to `--wordlist-out` and sorted action names to `ajax-actions.txt`
beside it. `--ajax-probe` is required to call observed actions with bounded GET
requests; responses are reported as requiring review, not as authentication
bypasses. `--no-ajax` disables discovery. No off-origin requests, cookies in
unauthenticated comparisons, POST action probes, or redirects are used.

## Offline tests and shareable log (macOS)

```sh
set -o pipefail
{
  python3 -m unittest discover -s tests -v
  python3 -m compileall -q wordpress_auditor
  wordpress-auditor --help
} 2>&1 | tee wordpress-auditor-check.log
pbcopy < wordpress-auditor-check.log
```

Tests connect only to `127.0.0.1` fixtures. Do not paste real cookies,
Authorization headers, customer requests or private URLs into public issues.
Reports are best-effort diagnostics, not a vulnerability confirmation.
