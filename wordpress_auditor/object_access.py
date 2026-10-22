"""Evidence-backed WordPress object authorization checks.

The scanner uses IDs returned by WordPress itself; it never guesses object IDs.
All requests are read-only and response content is reduced to structural proof
before a finding is recorded.
"""
from __future__ import annotations

import json
import re

WP_POSTS = "https://developer.wordpress.org/rest-api/reference/posts/"
WP_REVISIONS = "https://developer.wordpress.org/rest-api/reference/post-revisions/"
WP_REVISION_PERMISSION = (
    "https://developer.wordpress.org/reference/classes/"
    "wp_rest_revisions_controller/get_items_permissions_check/"
)
WP_MEDIA = "https://developer.wordpress.org/rest-api/reference/media/"

LOW_ROLES = frozenset({"subscriber", "customer", "contributor", "author"})
NONPUBLIC_STATUSES = frozenset({"draft", "pending", "private", "future"})
PASSWORD_FORM = re.compile(
    r"post-password-form|name=['\"]post_password|password required|"
    r"protected content", re.I,
)
TAG = re.compile(r"<[^>]+>")


def _json(body):
    if len(body) > 512 * 1024:
        return None
    try:
        return json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        return None


def _records(body):
    value = _json(body)
    if not isinstance(value, list):
        return []
    return [item for item in value[:100]
            if isinstance(item, dict) and type(item.get("id")) is int
            and item["id"] > 0]


def _forbidden_status(body):
    error = _json(body)
    details = error.get("data", {}).get("details", {}) if isinstance(error, dict) else {}
    status_error = details.get("status", {}) if isinstance(details, dict) else {}
    return (isinstance(status_error, dict)
            and status_error.get("code") == "rest_forbidden_status")


def _field_text(obj, *, allow_rendered=True):
    """Return True for nonempty WP text fields without returning their values."""
    for key in ("content", "title", "excerpt"):
        field = obj.get(key)
        if not isinstance(field, dict):
            continue
        raw = field.get("raw")
        if isinstance(raw, str) and raw.strip():
            return True
        rendered = field.get("rendered")
        if allow_rendered and isinstance(rendered, str) and TAG.sub(" ", rendered).strip():
            return True
    return False


def _protected_text_exposed(obj):
    for key in ("content", "excerpt"):
        field = obj.get(key)
        if not isinstance(field, dict) or field.get("protected") is not True:
            continue
        raw = field.get("raw")
        if isinstance(raw, str) and raw.strip():
            return True
        rendered = field.get("rendered")
        if (isinstance(rendered, str) and TAG.sub(" ", rendered).strip()
                and not PASSWORD_FORM.search(rendered)):
            return True
    return False


def _evaluate_private_collection(status, body, expected):
    if status in (401, 403):
        return "auth-required", "Anonymous access restricted as expected"
    if status == 400 and _forbidden_status(body):
        return "auth-required", "WordPress rejected anonymous access to this post status"
    if status != 200:
        return "not-confirmed", "Endpoint returned HTTP %s" % status
    objects = [item for item in _records(body)
               if item.get("status") == expected]
    exposed = sum(_field_text(item) for item in objects)
    if exposed:
        return "confirmed-public-nonpublic-wp-content", (
            "%d future WordPress object(s) exposed unpublished text anonymously; "
            "content and IDs withheld" % exposed)
    if objects:
        return "review-private-wp-object-metadata", (
            "%d future-status object(s) returned without unpublished text proof" %
            len(objects))
    return "not-confirmed", "No future WordPress objects returned"


def audit_future_content(auditor):
    """Exercise future/scheduled post and page reads without guessing IDs."""
    for rest_base, label in (("posts", "posts"), ("pages", "pages")):
        if auditor.request_count >= auditor.limit:
            break
        path = (f"/wp-json/wp/v2/{rest_base}?status=future&per_page=2&"
                "_fields=id,status,title,content,excerpt")
        status, body, _ = auditor.request(path, include_credentials=False)
        visibility, detail = _evaluate_private_collection(status, body, "future")
        auditor.add("WP scheduled future " + label, path, status,
                    visibility=visibility, detail=detail, reference=WP_POSTS)


def _child_collection(auditor, rest_base, parent_id, child):
    path = f"/wp-json/wp/v2/{rest_base}/{parent_id}/{child}?per_page=2"
    status, body, _ = auditor.request(path, include_credentials=False)
    objects = _records(body)
    proved = sum(_field_text(item) for item in objects)
    if proved:
        state = ("confirmed-public-revision-content" if child == "revisions"
                 else "confirmed-public-autosave-content")
        detail = ("%d %s object(s) exposed content anonymously; values and IDs withheld" %
                  (proved, child))
    elif objects:
        state = "review-public-" + child + "-metadata"
        detail = ("%d %s object(s) returned anonymously without content proof" %
                  (len(objects), child))
    elif status in (401, 403):
        state = "auth-required"
        detail = "Anonymous access denied as expected"
    else:
        state = "not-confirmed"
        detail = "No %s content exposure verified (HTTP %s)" % (child, status)
    name = "WP anonymous %s %s" % (rest_base.rstrip("s"), child)
    auditor.add(name, path, status, visibility=state, detail=detail,
                reference=WP_REVISION_PERMISSION)


def anonymous_object_boundaries(auditor, max_parents=1):
    """Check protected content, revisions/autosaves and media edit fields."""
    for rest_base in ("posts", "pages"):
        if auditor.request_count >= auditor.limit:
            break
        path = (f"/wp-json/wp/v2/{rest_base}?per_page=20&"
                "_fields=id,status,author,content,excerpt")
        status, body, _ = auditor.request(path, include_credentials=False)
        objects = _records(body)
        protected = sum(_protected_text_exposed(item) for item in objects)
        if protected:
            state = "confirmed-public-password-protected-content"
            detail = ("%d password-protected object(s) exposed protected text without a "
                      "password; content and IDs withheld" % protected)
        else:
            state = "observed"
            detail = ("%d public objects inspected; no protected text exposure verified" %
                      len(objects))
        auditor.add("WP password-protected " + rest_base, path, status,
                    visibility=state, detail=detail, reference=WP_POSTS)
        for parent in objects[:max_parents]:
            for child in ("revisions", "autosaves"):
                if auditor.request_count >= auditor.limit:
                    break
                _child_collection(auditor, rest_base, parent["id"], child)

    if auditor.request_count >= auditor.limit:
        return
    view_path = ("/wp-json/wp/v2/media?context=view&per_page=2&"
                 "_fields=id,caption,description,meta")
    view_status, view_body, _ = auditor.request(
        view_path, include_credentials=False)
    view = {item["id"]: item for item in _records(view_body)}
    media = ("/wp-json/wp/v2/media?context=edit&per_page=2&"
             "_fields=id,caption,description,meta")
    status, body, _ = auditor.request(media, include_credentials=False)
    objects = _records(body)
    edit_only = 0
    for item in objects:
        public = view.get(item["id"], {})
        raw = any(
            isinstance(item.get(key), dict)
            and isinstance(item[key].get("raw"), str)
            and bool(item[key]["raw"].strip())
            and not (isinstance(public.get(key), dict)
                     and public[key].get("raw") == item[key]["raw"])
            for key in ("caption", "description")
        )
        meta = (isinstance(item.get("meta"), dict) and bool(item["meta"])
                and item.get("meta") != public.get("meta"))
        edit_only += bool(raw or meta)
    if edit_only:
        state = "confirmed-public-media-edit-fields"
        detail = ("%d media object(s) exposed nonempty edit-only fields anonymously; "
                  "values and IDs withheld" % edit_only)
    elif objects:
        state = "review-public-media-edit-context"
        detail = ("Media edit-context returned object metadata, but no nonempty private "
                  "field was verified")
    elif status in (401, 403):
        state = "auth-required"
        detail = "Anonymous media edit-context access denied as expected"
    else:
        state = "not-confirmed"
        detail = "No private media edit-context exposure verified (HTTP %s)" % status
    auditor.add("WP anonymous media edit-context", media, status,
                visibility=state, detail=detail, reference=WP_MEDIA)


def audit_low_role_objects(auditor, label, role, user_id, *, headers=None,
                           isolate_headers=False):
    """Exercise low-role access to other authors' nonpublic objects/revisions."""
    if role not in LOW_ROLES or type(user_id) is not int or user_id < 1:
        return 0
    if auditor.request_count >= auditor.limit:
        return 0
    kwargs = {
        "headers": headers or {},
        "include_credentials": True,
        "isolate_headers": isolate_headers,
    }
    requests = 0
    path = ("/wp-json/wp/v2/posts?context=edit&"
            "status=draft,pending,private,future&per_page=5&"
            "_fields=id,status,author,title,content,excerpt")
    status, body, _ = auditor.request(path, **kwargs)
    requests += 1
    objects = [item for item in _records(body)
               if item.get("status") in NONPUBLIC_STATUSES]
    if role in ("subscriber", "customer"):
        unauthorized = objects
    else:
        unauthorized = [item for item in objects
                        if type(item.get("author")) is int
                        and item["author"] != user_id]
    exposed = sum(_field_text(item) for item in unauthorized)
    if exposed:
        state = "confirmed-low-priv-nonpublic-content"
        detail = ("Confirmed %s session read %d nonpublic object(s) outside its expected "
                  "author boundary; content and IDs withheld" % (role, exposed))
    elif unauthorized:
        state = "review-low-priv-other-author-metadata"
        detail = ("Low-role session received other-author/nonpublic metadata without "
                  "content proof")
    elif status in (401, 403) or status == 400 and _forbidden_status(body):
        state = "role-restricted"
        detail = "Confirmed %s session denied nonpublic collection access" % role
    else:
        state = "expected-role-boundary"
        detail = "No out-of-bound nonpublic content verified for confirmed %s session" % role
    auditor.add("WP low-role object boundary " + label, path, status,
                visibility=state, detail=detail, reference=WP_POSTS)

    if auditor.request_count >= auditor.limit:
        return requests
    parent_path = "/wp-json/wp/v2/posts?per_page=5&_fields=id,author,status"
    parent_status, parent_body, _ = auditor.request(
        parent_path, include_credentials=False)
    requests += 1
    parents = [item for item in _records(parent_body)
               if item.get("status") == "publish"
               and type(item.get("author")) is int
               and item["author"] != user_id]
    if not parents or auditor.request_count >= auditor.limit:
        auditor.add("WP low-role revision boundary " + label, parent_path,
                    parent_status, visibility="not-confirmed",
                    detail="No public other-author parent available for revision check",
                    reference=WP_REVISION_PERMISSION)
        return requests
    revision_path = "/wp-json/wp/v2/posts/%d/revisions?per_page=2" % parents[0]["id"]
    revision_status, revision_body, _ = auditor.request(revision_path, **kwargs)
    requests += 1
    revisions = _records(revision_body)
    revision_text = sum(_field_text(item) for item in revisions)
    if revision_text:
        state = "confirmed-low-priv-revision-content"
        detail = ("Confirmed %s session read %d revision(s) of another author's post; "
                  "content and IDs withheld" % (role, revision_text))
    elif revisions:
        state = "review-low-priv-revision-metadata"
        detail = "Other-author revision metadata returned without content proof"
    elif revision_status in (401, 403):
        state = "role-restricted"
        detail = "Confirmed %s session denied another author's revisions" % role
    else:
        state = "not-confirmed"
        detail = "No other-author revision exposure verified (HTTP %s)" % revision_status
    auditor.add("WP low-role revision boundary " + label, revision_path,
                revision_status, visibility=state, detail=detail,
                reference=WP_REVISION_PERMISSION)
    return requests
