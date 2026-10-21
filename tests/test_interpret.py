"""Status-meaning logic: the same HTTP status must mean different things by file role."""
import unittest

from wordpress_auditor.assessment import assess
from wordpress_auditor.interpret import classify_role, interpret

LEAK = (b"\nFatal error: Uncaught Error: Call to undefined function x() in "
        b"/var/www/html/wp-content/plugins/p/p.php:3\nStack trace:\n#0 {main}\n")


class InterpretTests(unittest.TestCase):
    def verdict(self, path, status, body=b"", control=404):
        found = interpret(path, status, body, control)
        return found.verdict if found else None

    def test_roles(self):
        self.assertEqual(classify_role("/wp-login.php"), "entry")
        self.assertEqual(classify_role("/wp-includes/functions.php"), "internal")
        self.assertEqual(classify_role("/wp-content/plugins/x/x.php"), "plugin")
        self.assertEqual(classify_role("/wp-content/uploads/2026/a.php"), "uploads")
        self.assertEqual(classify_role("/wp-config.php.bak"), "backup")
        self.assertEqual(classify_role("/wp-admin/maint/repair.php"), "setup")

    def test_500_on_plugin_file_is_review_with_explanation(self):
        found = interpret("/wp-content/plugins/x/x.php", 500, b"", 404)
        self.assertEqual(found.verdict, "review-direct-php-execution")
        self.assertIn("ABSPATH", found.meaning)
        self.assertTrue(found.action)
        self.assertEqual(assess("n", 500, found.verdict, "")[0], "REVIEW")

    def test_500_on_core_include_is_info_hardening(self):
        found = interpret("/wp-settings.php", 500, b"", 404)
        self.assertEqual(found.verdict, "internal-file-executed")
        self.assertEqual(assess("n", 500, found.verdict, "")[0], "INFO")

    def test_same_500_on_nonexistent_sibling_is_not_file_specific(self):
        self.assertEqual(self.verdict("/wp-content/plugins/x/x.php", 500, b"", 500),
                         "server-wide-error")

    def test_php_error_text_is_confirmed_disclosure_on_500_and_200(self):
        for status in (500, 200):
            found = interpret("/wp-content/plugins/p/p.php", status, LEAK, 404)
            self.assertEqual(found.verdict, "confirmed-public-php-error-disclosure")
            self.assertEqual(assess("n", status, found.verdict, "")[0], "LOW")

    def test_wp_critical_error_page_is_not_a_leak(self):
        body = b"<p>There has been a critical error on this website.</p>"
        self.assertEqual(self.verdict("/wp-settings.php", 500, body), "internal-file-executed")

    def test_waf_500_is_not_execution(self):
        self.assertEqual(self.verdict("/wp-content/plugins/x/x.php", 500,
                                      b"Request blocked by ModSecurity"), "waf-blocked")

    def test_500_on_entry_and_setup(self):
        self.assertEqual(self.verdict("/wp-login.php", 500), "entrypoint-error")
        self.assertEqual(self.verdict("/wp-admin/install.php", 500), "review-setup-script-error")

    def test_gateway_and_rate_limit(self):
        self.assertEqual(self.verdict("/wp-login.php", 503), "server-unavailable")
        self.assertEqual(self.verdict("/wp-login.php", 503, b"Briefly unavailable for scheduled maintenance"),
                         "maintenance-mode")
        self.assertEqual(self.verdict("/anything.php", 429), "rate-limited")

    def test_php_in_uploads_is_review(self):
        self.assertEqual(self.verdict("/wp-content/uploads/a.php", 200, b"x"),
                         "review-php-executable-in-uploads")

    def test_source_disclosure_and_silent_exec(self):
        self.assertEqual(self.verdict("/wp-includes/version.php", 200, b"<?php $wp_version='6';"),
                         "confirmed-php-source-disclosure")
        self.assertEqual(assess("n", 200, "confirmed-php-source-disclosure", "")[0], "HIGH")
        self.assertEqual(self.verdict("/wp-includes/version.php", 200, b""),
                         "internal-file-executes-silently")

    def test_denied_internal_file_is_good_hardening(self):
        found = interpret("/wp-includes/functions.php", 403, b"", 404)
        self.assertEqual(found.verdict, "auth-required")


if __name__ == "__main__":
    unittest.main()
