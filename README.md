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
# Smart audit by default, showing phases and a human-readable explanation.
# Includes limited read-only XML-RPC POST diagnostic calls.
wordpress-auditor --url https://example.invalid

# Optional quick mode, without XML-RPC method introspection
wordpress-auditor --url https://example.invalid --quick

# Stream engine phases while executing
wordpress-auditor --url https://example.invalid --progress

# Print every individual endpoint check
wordpress-auditor --url https://example.invalid --verbose

# Explicit smart mode (identical to the default)
wordpress-auditor --url https://example.invalid --full

# Save all evidence and a concise explanation without JSON output to console
wordpress-auditor --url https://example.invalid --output ./audit/report.json

# Explicit detailed stdout (JSON/CSV/Markdown)
wordpress-auditor --url https://example.invalid --format json
# Automated bounded payload tests: paths, read-only method negotiation,
# conditional 401/403 header variations, and discovered URL rechecks.
wordpress-auditor --url https://example.invalid --full --max-requests 180 \
  --output ./audit/report.json

# Deeper GET/header payload audit with imported prior Burp Intruder ZIP.
wordpress-auditor --url https://example.invalid --deep \
  --payloads ~/Downloads/wp_intruder_expanded.zip \
  --payload-limit 160 --max-requests 350 \
  --output ./audit/deep.json

# Narrow a scan to a supplied HTTP request context plus known cookies.
wordpress-auditor --request request.txt --authorized --full \
  --output ./audit/authenticated.json

# Optional OAST SSRF: one explicit request to an in-scope endpoint.
# It cannot confirm SSRF without a separate Collaborator callback.
wordpress-auditor --url https://example.invalid --ssrf \
  --collaborator-url https://your-id.oast.invalid/callback \
  --ssrf-path /wp-admin/admin-ajax.php --ssrf-action preview_url \
  --ssrf-param url --ssrf-method GET --max-requests 60

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

## What happens during a normal scan?

The default scan is now smart rather than the old limited quick mode. The CLI
explains each module and actual HTTP request/check counts: XML-RPC,
administrator access controls, WP/Woo REST, HTML/JS crawling, AJAX action
discovery, HEAD/OPTIONS capability tests, GET verification of discovered
routes, and differential path/header payload checks.

Results are stored in the ignored local audit/ directory:
- scan-summary.md: human-readable description of phases and observations
- latest-report.json: every individual request/check result
- wordlist.txt and ajax-actions.txt: reusable, deduplicated discoveries

The engine spends unused request budget on newly discovered in-scope GET
routes rather than stopping after eight URL checks. It also discovers
concrete GET-capable paths directly from the REST route index, avoiding
variable, cart, checkout and payment paths. A 200 status does not prove
privileged access. A 401/403 status usually means access control.
An automated scan cannot guarantee discovery of every vulnerability.

The default console view is a short, factual summary, not a JSON array.
Use --format json, --format csv, or --format md for detailed stdout.
Using --output report.json writes detailed findings to that file and keeps
the terminal summary concise. Add --verbose to show individual checks.

--full enables a broader bounded read-only HTTP probe list and also runs
XML-RPC protocol diagnostics. Those diagnostics use several small POST
requests, but only for read-only introspection and malformed-method
error responses: no login, pingback, multicall, brute-force, or DoS.
Both --full and --xmlrpc consume the global request budget.
Rate limit with --delay (default 0.2s) and --max-requests (default 180 for smart mode).
A response code of 200, 302 or 401 alone is not proof of a vulnerability.

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

## Automated verification model

This auditor performs bounded response comparisons, not only endpoint listing.
Normal scans discover AJAX actions and URLs, keep them in audit/wordlist.txt
and audit/ajax-actions.txt, and recheck prior same-origin discoveries.
--full probes additional WP/WooCommerce REST endpoints, XML-RPC introspection,
HTTP HEAD/OPTIONS, and path/header variations. --deep increases request budget
and can use the complete previously generated Burp Intruder payload package.
--payloads accepts 01_headers.txt and 02_urls.txt in either ZIP or folder form;
unsafe or out-of-scope candidates are filtered. Write-capable HTTP methods
and comment/XSS payloads are never fired automatically. --post-comment is
explicit for one harmless marker. No brute force or DoS.

--max-requests and --delay control load. --quick defaults to 60.
Normal smart mode (including --full) defaults to 180. --deep defaults to 350. All modules share the global request limit.
--no-probe-discovered saves URLs without requesting them. --no-ajax disables
action discovery. Header spoofing tests never include session cookies.
Same-origin checks and no-redirect transport prevent off-origin crawling.

Interpretation: a response difference means requires-review, NOT a proven
privilege bypass. Login pages and soft-404s can cause false positives.
SSRF requires a separately confirmed Collaborator callback; HTTP 200 is
not proof. This tool complements Burp, manual role testing, and Nuclei.

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
