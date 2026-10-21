# wordpress-auditor

A focused WordPress / WooCommerce security auditor for **authorized assessments**.
It tests WordPress-specific behaviors, not plugin-version CVEs or generic XSS,
SQL injection and IDOR payloads.

**What makes this different from a URL wordlist?** Every scan reports what
actually ran, what was blocked, what needs review and which checks were
skipped. The built-in technique catalog explicitly distinguishes tests from
manual and opt-in activities. HTTP 200, 401 or 403 alone is **not** a finding.

References: [HackTricks WordPress](https://book.hacktricks.wiki/en/network-services-pentesting/pentesting-web/wordpress.html),
[WordPress REST API](https://developer.wordpress.org/rest-api/reference/),
[WordPress Authentication](https://developer.wordpress.org/rest-api/using-the-rest-api/authentication/).

## Installation (Kali / macOS / Linux)

Python **3.10+** required.

~~~sh
git clone https://github.com/martinezooo/wordpress-auditor.git
cd wordpress-auditor
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e .
wordpress-auditor --list-checks
~~~

## Run a scan

~~~sh
# Standard smart scan: WordPress checks, live colored progress, reports
wordpress-auditor --url https://your-authorized-lab.example

# Detailed phase/check output and explicitly forced colors
wordpress-auditor --url https://your-authorized-lab.example --verbose --color always

# Quick reconnaissance with a tighter request budget
wordpress-auditor --url https://your-authorized-lab.example --quick

# Deeper bounded GET/path/header suite (can import earlier Intruder payload ZIP)
wordpress-auditor --url https://your-authorized-lab.example --deep \
  --payloads ~/Downloads/wp_intruder_expanded.zip --max-requests 350 \
  --output ./audit/deep.json

# Use cookies and a nonce from your own test session in a raw Burp request
wordpress-auditor --request request.txt --authorized \
  --output ./audit/authenticated.json

# Inspect every supported, optional, manual and skipped technique
wordpress-auditor --list-checks
~~~

The output uses **HIGH** (red), **MEDIUM** (yellow), **LOW** (cyan),
**REVIEW** (magenta), and **INFO** (cyan). Green DONE means a phase finished,
not that a vulnerability was exploited.

With an interactive terminal, stage progress and significant observations
are printed immediately. Use --progress for non-interactive terminals,
--progress-every 5 to adjust heartbeat frequency, --verbose for each result,
or --no-color for plain logs. A scan uses a shared request budget (default
180 in smart mode, 350 in deep mode), per-request delay (default 0.2s)
and a no-redirect, same-origin HTTP transport.

## What is checked automatically?

| Group | Examples |
|---|---|
| WordPress identity | Public authors in REST, bounded author archives, private edit-context data, anonymous /users/me |
| REST permissions | Anonymous access to settings, plugins, themes and Application Password metadata |
| Login/registration | WordPress login, password-reset and registration forms, installer and DB repair exposure |
| XML-RPC | GET status, safe POST system.listMethods and system.getCapabilities, unknown-method and malformed-XML fault responses |
| WooCommerce | Public Store API versus protected WooCommerce REST routes and product reviews |
| AJAX | Discover action names from HTML/JavaScript and same-origin asset references |
| Configuration | Public wp-config backups, .env, debug.log, .git/HEAD and WordPress content directory listings |
| Core private-content access | Anonymous REST queries for draft/private/pending posts/pages, moderated comments and private comment fields |
| Comment capabilities | Read-only identification of open comments and possible classic/REST/XML-RPC creation channels; no automatic POST |
| Routing | HTTP HEAD/OPTIONS, admin access checks, path/header normalization controls |
| Discovery | REST route index, HTML, JS, sitemap, persisted wordlist and bounded read-back |

Plugin and theme asset paths are identified **without version matching or CVE lookups**.
Sensitive response bodies, user email addresses, passwords, tokens and cookies
are never copied into report findings.

### Focus: WordPress Core misconfigurations, not generic exploitation

This project prioritizes WordPress-specific mistakes. In smart and deep
mode, an additional read-only module asks WordPress REST whether anonymous
users can read actual draft/private/pending posts or pages, moderated
comments, or moderator-only comment fields. It also flags the particularly dangerous
combination of anonymous site settings showing registration enabled and
the administrator role as the default for new accounts. No user is created.
Only a JSON WordPress object
with a numeric ID, matching private status or sensitive field, confirms
exposure. HTTP 200 with a login/soft-404 page does not.

New permission correlation joins existing standard /wp-json/ and alternate
?rest_route= results for the same WordPress operation without repeating requests.
A mismatch is REVIEW until the alternate route independently discloses protected
WordPress content; HTTP status differences alone never prove privilege bypass.
XML-RPC GET/POST differences are explained as policy observations, not bugs.
Two bounded anonymous AJAX requests compare the no-action dispatcher response
against a random unregistered action. No discovered plugin AJAX handler is
executed automatically, and neither request submits a comment or changes data.

Additional anonymous checks exercise WordPress REST through the alternative
?rest_route= channel for private posts, moderated comments, user edit
fields and site settings. This can reveal inconsistent WAF routing or
misconfigured permission callbacks, but a response alone never proves bypass.
The standard and alternate routes share the global request budget.

The scanner distinguishes real registration, reset, multisite signup,
installer and database repair forms from HTTP 200 soft-404 pages. It never
submits registration forms, activation keys, password resets, installation
forms or database repair actions. It also probes whether the direct
wp-config.php endpoint accidentally serves PHP source rather than executing
it; response content is suppressed in reports. These core checks run before
the large discovered-URL queue.

It also checks sampled public post comment settings. Comments being enabled,
an XML-RPC method being listed, or a REST route advertising POST are
capabilities, not vulnerabilities. The generated core-operations.md groups
operations by channel (classic form, REST, XML-RPC), and explicitly
distinguishes route discovery from an executed test.
The matrix never sends write requests.

Active comment submission remains an explicit, single-marker opt-in via
--post-comment; never triggered by --full or --deep. No brute-force,
DoS, generic XSS/SQLi/IDOR payloads, plugin-version CVE matching, or blind
WooCommerce cart/checkout requests are part of the core checks.

A 403 to XML-RPC GET doesn't automatically stop testing: one safe
system.listMethods POST is attempted to distinguish GET filtering from XML-RPC
protocol availability. The scanner does **not** invoke pingback.ping,
system.multicall, wp-cron.php or a password brute-force.

## Authenticated testing with your own test account

No username or password guessing occurs. Without credentials the scanner
automatically runs anonymous checks and explains which authenticated checks
were skipped.

### Application Password (preferred for REST API)

Use the **Application Password**, not your primary login password.
Provide it in an environment variable, **never in CLI arguments, Git files
or chat messages**. The scanner validates identity via /wp-json/wp/v2/users/me
and compares a limited selection of anonymous and authenticated read-only
endpoints. It also tries **one** wp.getUsersBlogs request to XML-RPC
using that valid test account where XML-RPC is supported.

~~~sh
read -rs WPAUDITOR_APP_PASSWORD
export WPAUDITOR_APP_PASSWORD
wordpress-auditor --url https://your-authorized-lab.example \
  --auth-user YOUR_TEST_USERNAME --output ./audit/test-account.json
unset WPAUDITOR_APP_PASSWORD
~~~

### WordPress login form (one attempt only)

If you specifically want to test wp-login.php authentication with a real
test account's **primary password**, provide a separate environment variable.
The scanner sends exactly one POST, does not follow redirects, and attempts
to verify the resulting session only when it receives WordPress session cookies.
A 2FA challenge, failed login or redirect is **not** reported as a confirmed
authenticated session.

~~~sh
read -rs WPAUDITOR_LOGIN_PASSWORD
export WPAUDITOR_LOGIN_PASSWORD
wordpress-auditor --url https://your-authorized-lab.example \
  --login-user YOUR_TEST_USERNAME
unset WPAUDITOR_LOGIN_PASSWORD
~~~

### Several WordPress roles (read-only comparison)

Export one raw Burp HTTP/1.1 request per valid test session containing its
Cookie and X-WP-Nonce, then provide them with role labels. All requests must
match the exact target origin. This checks the same private REST endpoints
with each session; roles are not guessed, and a label isn't trusted unless
the REST profile confirms it. No role modifications are attempted.

~~~sh
wordpress-auditor --url https://your-authorized-lab.example   --role-request subscriber:subscriber.burp   --role-request shop_manager:shop-manager.burp   --role-request administrator:administrator.burp   --output ./audit/roles.json
~~~

The two credential modes are optional and may be used together.
They require HTTPS except for local loopback tests. Existing Burp cookies
and X-WP-Nonce can be supplied with --request and --authorized.
WordPress REST cookie authentication may reject a cookie-only session without
a valid REST nonce.

## Optional actions

~~~sh
# Search for a previously submitted harmless comment marker
wordpress-auditor --url https://your-authorized-lab.example \
  --search-comment UNIQUE_MARKER

# Post one benign test comment only on explicit command
wordpress-auditor --url https://your-authorized-lab.example \
  --post-comment --comment-post-id 42 --comment-mode form \
  --marker UNIQUE_MARKER

# Opt in to GET probes of discovered AJAX handlers; GET can have side effects
wordpress-auditor --url https://your-authorized-lab.example --ajax-probe

# A single SSRF OAST injection into an operator-chosen in-scope URL parameter
wordpress-auditor --url https://your-authorized-lab.example --ssrf \
  --ssrf-path /wp-admin/admin-ajax.php --ssrf-action preview_url \
  --ssrf-param url --collaborator-url https://your-token.oast.invalid
~~~

The SSRF test never directly requests the collaborator URL. HTTP 200 is not
proof of SSRF; correlate the callback separately. Unknown AJAX POST handlers,
password attacks, plugin/theme PHP execution, user creation and DoS techniques
are not executed by default or as part of --deep.

## Scan output

Files are placed in the ignored local audit/ directory by default.

| File | Purpose |
|---|---|
| scan-summary.md | Human explanation of what ran and what was observed |
| coverage.json / coverage.md | **Every WordPress-specific technique**: CHECKED, PARTIAL, BLOCKED, SKIPPED, OPT-IN, MANUAL or ERROR, with reason and reference |
| latest-report.json | Individual results with HTTP status, severity, confidence and sanitized detail |
| wordlist.txt | Deduplicated same-origin URL paths, merged between scans |
| url-queue.json | Same-origin URL verification state: checked vs pending |
| core-operations.json / core-operations.md | Per-operation channels: DISCOVERED is not an executed write, TESTED means an actual read-only check ran, UNKNOWN is not assumed safe |
| ajax-actions.txt | Discovered AJAX actions (no automatic write requests) |

## Does it test every path?

There is no finite list of all WordPress paths: plugins can register arbitrary
REST routes, AJAX actions and frontend pages. The scanner automatically
collects candidate paths from bounded WordPress core probes, REST route
discovery, HTML and JavaScript, sitemap and previously saved wordlists.

Eligible read-only GET routes are checked while the shared request budget
allows. Some routes are intentionally excluded, including cart, checkout,
logout, download, payment, and dynamic URLs with potentially state-changing
effects. Variable REST routes need real context and are not blindly fuzzed.

The url-queue.json file remembers actual HTTP-responding GETs from prior scans.
The next run prioritizes unverified paths rather than starting at the
beginning of the wordlist again. --recheck-urls repeats previously
verified discovered paths. A checked URL means a real HTTP response was
received, NOT that the URL is secure or vulnerability-free.

The console reports checked vs pending paths; queue and coverage.md
show what has not been verified. --max-requests and --delay continue to
control rate. Always use a clearly defined authorized scope.

Use --output ./audit/report.json to choose the report path, --format json/csv/md
for verbose machine-readable terminal output, and --list-checks to print
the entire technique catalog before scanning.

**Limitations:** This is a bounded black-box auditor. It cannot inspect PHP
source for missing capability checks, prove plugin-specific authentication
bypasses from HTTP statuses, or safely execute every published HackTricks
exploit. Those are marked MANUAL rather than silently counted as tests.
Do not mistake a public author slug or enabled XML-RPC for a vulnerability.

## Offline self-tests

Tests use Python local HTTP fixtures on 127.0.0.1 only.

~~~sh
python3 -m unittest discover -s tests -v
python3 -m compileall -q wordpress_auditor
wordpress-auditor --help
wordpress-auditor --list-checks
~~~

Never publish real Burp request files, session cookies, authentication
tokens, test-user passwords, internal WordPress reports or client URLs.
