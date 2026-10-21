"""Local-only unit tests for WordPress permission correlation."""
import unittest
from types import SimpleNamespace
from wordpress_auditor.wp_permissions import compare_rest, probe_ajax_unknown, summarize_xmlrpc_policy

class FakeAuditor:
    def __init__(self, baseline=(400, b"0"), unknown=(400, b"0"), limit=10):
        self.baseline, self.unknown, self.limit = baseline, unknown, limit
        self.request_count = 0
        self.calls = []
        self.results = []
    def request(self, path, include_credentials=False):
        self.calls.append((path, include_credentials))
        self.request_count += 1
        status, body = self.baseline if "?" not in path else self.unknown
        return status, body, {}
    def add(self, name, path, status, visibility, detail, **extra):
        self.results.append(SimpleNamespace(name=name, url=path, status=status,
                                            visibility=visibility, detail=detail, **extra))

class PermissionTests(unittest.TestCase):
    def test_normal_denials(self):
        checks = [SimpleNamespace(name="WP private posts", status=403, visibility="auth-required"),
                  SimpleNamespace(name="WP alternate REST private posts", status=403, visibility="auth-required")]
        self.assertEqual(compare_rest(checks)[0][1], "access-restricted")
    def test_verified_alternative_exposure_is_review(self):
        checks = [SimpleNamespace(name="WP private posts", status=403, visibility="auth-required"),
                  SimpleNamespace(name="WP alternate REST private posts", status=200,
                                  visibility="confirmed-public-nonpublic-wp-content")]
        self.assertEqual(compare_rest(checks)[0][1], "review-cross-channel-permission")
    def test_http_200_alone_not_proof(self):
        checks = [SimpleNamespace(name="WP private posts", status=403, visibility="auth-required"),
                  SimpleNamespace(name="WP alternate REST private posts", status=200, visibility="not-confirmed")]
        self.assertEqual(compare_rest(checks)[0][1], "review-cross-channel-behavior")
    def test_missing_checks_no_invented_result(self):
        self.assertEqual(compare_rest([])[0][1], "not-evaluated")
    def test_unknown_action_is_safe_and_redacted(self):
        a = FakeAuditor()
        self.assertEqual(probe_ajax_unknown(a), 2)
        self.assertEqual(a.results[-1].visibility, "expected-ajax-unknown-action")
        self.assertEqual(len(a.calls), 2)
        self.assertTrue(all(flag is False for _, flag in a.calls))
        self.assertNotIn("wp_audit_nonexistent_", str(a.results))
    def test_nonstandard_ajax_is_review_only(self):
        a = FakeAuditor(unknown=(200, b'{"ok":true}'))
        probe_ajax_unknown(a)
        self.assertEqual(a.results[-1].visibility, "review-ajax-unknown-action")
    def test_same_ajax_500_is_bootstrap_diagnosis_not_handler_claim(self):
        a = FakeAuditor(baseline=(500, b"critical"), unknown=(500, b"critical"))
        probe_ajax_unknown(a)
        self.assertEqual(a.results[-1].visibility, "ajax-bootstrap-error")
        self.assertIn("before any registered AJAX handler", a.results[-1].meaning)
        self.assertIn("github.com/WordPress/WordPress", a.results[-1].reference)
    def test_budget(self):
        a = FakeAuditor(limit=1)
        self.assertEqual(probe_ajax_unknown(a), 0)
        self.assertFalse(a.calls)
    def test_xmlrpc_policy_get403_post200_is_normal(self):
        checks = [{"name": "XML-RPC endpoint GET", "status": 403},
                  {"name": "XML-RPC system.listMethods", "status": 200}]
        state, detail = summarize_xmlrpc_policy(checks)
        self.assertEqual(state, "observed")
        self.assertIn("normal WordPress behavior", detail)

if __name__ == "__main__":
    unittest.main()
