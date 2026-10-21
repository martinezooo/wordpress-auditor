"""Read-only WordPress policy signatures. No remote target, no state-changing POST."""
import unittest
from wordpress_auditor.wp_policy import classify


class PolicySignatures(unittest.TestCase):
    def test_wordpress_registration_requires_real_form(self):
        body = (b'<form id="registerform"><input name="user_login">'
                b'<input name="user_email"></form>')
        self.assertEqual(classify("register", 200, body)[0], "review-open-registration")
        for content in (b"<html>WordPress registration unavailable</html>",
                        b'<form id="loginform"><input name="log"></form>',
                        b"not found"):
            self.assertEqual(classify("register", 200, content)[0], "not-confirmed")

    def test_registration_disabled_is_informational(self):
        result = classify("register", 200,
                          b"<p>User registration is currently not allowed</p>")
        self.assertEqual(result[0], "registration-restricted")

    def test_multisite_signup_and_activation_are_passive(self):
        self.assertEqual(classify("signup", 200,
                         b'<form id="setupform" action="wp-signup.php"></form>')[0],
                         "multisite-signup-observed")
        self.assertEqual(classify("activation", 200,
                         b"<h2>Activation Key</h2><a href='wp-activate.php'>activate</a>")[0],
                         "multisite-activation-observed")
        self.assertEqual(classify("signup", 200, b"Signup blocked")[0],
                         "not-confirmed")

    def test_installer_requires_all_fields(self):
        body = (b'<form method="POST" action="install.php?step=2">'
                b'<input name="weblog_title"><input name="user_name">'
                b'<input name="admin_email"></form>')
        self.assertEqual(classify("install", 200, body)[0], "review-wp-install-open")
        self.assertEqual(classify("install", 200,
                                 b"<h1>Install WordPress</h1><p>Already Installed</p>")[0],
                         "not-confirmed")
        self.assertNotIn("attempted", classify("install", 200, body)[1].lower().replace(
            "not attempted", ""))

    def test_database_repair_requires_actual_action_link(self):
        body = (b'<p>Repair Database</p>'
                b'<a href="/wp-admin/maint/repair.php?repair=1">Repair Database</a>')
        self.assertEqual(classify("repair", 200, body)[0], "review-wp-repair-open")
        disabled = (b'<p>To repair database, add WP_ALLOW_REPAIR=true. '
                    b'Then try repair=1</p>')
        self.assertEqual(classify("repair", 200, disabled)[0], "not-confirmed")

    def test_http_status_and_login_markers_are_not_findings(self):
        self.assertEqual(classify("login", 403, b"")[0], "auth-required")
        self.assertEqual(classify("login", 200, b"<html>Soft 404 login</html>")[0],
                         "not-confirmed")
        self.assertEqual(classify("lostpassword", 200,
                                 b'<form id="lostpasswordform"></form>')[0],
                         "reset-form-observed")


if __name__ == "__main__":
    unittest.main()
