# wordpress-auditor

Install with `pip install .`. The safe offline invocation is:

```sh
wordpress-auditor --url http://127.0.0.1:8080 --max-requests 10
python -m unittest discover -s tests
```

Use `--request burp.txt` for a strict raw Burp request (HTTPS is the default;
use `--scheme http` only for an explicitly local HTTP fixture). Credentials
are ignored unless `--authorized` is supplied. Reports are redacted and omit
query strings. Useful flags are `--delay`, `--max-requests`, `--depth`,
`--full`, `--xmlrpc`, `--search-comment`, and `--comment-post-id N`.

Redirects are never followed, requests stay on the exact origin and scheme,
and the global request budget includes every helper. XML-RPC is opt-in and
only sends `system.listMethods` via POST; GET 405 is handled. XML is parsed
without DTD/entity support and pingback is never called. Comment posting is
opt-in and read-back is classified as public, authenticated, or moderated.
