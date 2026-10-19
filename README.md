# wordpress-auditor

Install with `pip install .`, then run `wordpress-auditor --url http://127.0.0.1:8080 --format json`.
Use `--request burp.txt` for a raw Burp request, `--header 'Authorization: Bearer …'`,
`--cookie 'wordpress_logged_in=…'`, `--proxy http://127.0.0.1:8888`, or `--marker TEST`.
Reports support `--format json|csv|md` and `--output report.ext`. Comment posting is never
performed unless `--post-comment` is explicitly supplied; it is a single benign REST POST
with a follow-up read-back. Requests are same-origin, bounded, and otherwise read-only.
XML-RPC only calls `system.listMethods` and an unknown-method diagnostic (never pingback or
authentication attacks). Authenticated and public visibility are represented by the supplied
request credentials; no plugin VERSION checks are made. Offline fixture example:
`python -m unittest discover -s tests`.
