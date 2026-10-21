"""Per-target XDG scan state, independent of the working directory."""
from __future__ import annotations
import hashlib
import os
import re
from urllib.parse import urlsplit


def default_audit_dir(url: str) -> str:
    parsed = urlsplit(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ValueError("expected absolute HTTP(S) URL")
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    origin = "%s://%s:%d" % (parsed.scheme, parsed.hostname.lower(), port)
    fingerprint = hashlib.sha256(origin.encode("utf-8")).hexdigest()[:12]
    slug = re.sub(r"[^a-z0-9.-]+", "-", parsed.hostname.lower())[:48].strip("-.")
    state_root = os.environ.get("XDG_STATE_HOME") or os.path.expanduser("~/.local/state")
    return os.path.join(os.path.abspath(os.path.expanduser(state_root)),
                        "wordpress-auditor", "scans", "%s-%s" % (slug, fingerprint))
