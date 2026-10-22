"""Local-only install layout and target-scoped artifact regression tests."""
import contextlib
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from wordpress_auditor.cli import main
from wordpress_auditor.storage import default_audit_dir


class InstallationTests(unittest.TestCase):
    def test_version_and_python_module_entrypoint(self):
        p = subprocess.run([sys.executable, "-m", "wordpress_auditor", "--version"],
                           capture_output=True, text=True, check=True)
        self.assertIn("0.5.0", p.stdout)
        with self.assertRaises(SystemExit) as exc:
            with contextlib.redirect_stdout(io.StringIO()) as out:
                main(["--version"])
        self.assertEqual(exc.exception.code, 0)

    def test_per_origin_artifacts_ignore_paths_and_tokens(self):
        with tempfile.TemporaryDirectory() as d, patch.dict(
                os.environ, {"XDG_STATE_HOME": d}):
            a = default_audit_dir("https://preprod.example.invalid/?token=SECRET")
            b = default_audit_dir("https://preprod.example.invalid/wp-json/")
            c = default_audit_dir("https://preprod.example.invalid:8443/")
            e = default_audit_dir("http://preprod.example.invalid/")
            self.assertEqual(a, b)
            self.assertNotEqual(a, c)
            self.assertNotEqual(a, e)
            self.assertTrue(a.startswith(d))
            self.assertNotIn("SECRET", a)
            self.assertTrue(a.endswith(os.path.basename(b)))
            self.assertNotIn("?", a)

    def test_default_cli_artifacts_in_state_dir_not_current_directory(self):
        from test_explain import ExplainScanTest
        ExplainScanTest.setUpClass()
        try:
            with tempfile.TemporaryDirectory() as base:
                with patch.dict(os.environ, {"XDG_STATE_HOME": base}):
                    expected = Path(default_audit_dir(ExplainScanTest.url))
                    target = Path(base) / "working"
                    target.mkdir()
                    cwd = os.getcwd()
                    os.chdir(target)
                    try:
                        with contextlib.redirect_stdout(io.StringIO()) as out:
                            main(["--url", ExplainScanTest.url,
                                  "--quick", "--max-requests", "7",
                                  "--delay", "0", "--payload-limit", "0"])
                    finally:
                        os.chdir(cwd)
                    self.assertFalse((target / "audit").exists())
                    self.assertTrue((expected / "wordlist.txt").exists())
                    self.assertTrue((expected / "scan-summary.md").exists())
                    self.assertTrue((expected / "core-operations.json").exists())
                    self.assertIn(str(expected), out.getvalue())
        finally:
            ExplainScanTest.tearDownClass()

    def test_explicit_audit_dir_and_wordlist_path_override(self):
        from wordpress_auditor.storage import default_audit_dir
        with tempfile.TemporaryDirectory() as base:
            with patch.dict(os.environ, {"XDG_STATE_HOME": base}):
                self.assertEqual(default_audit_dir("https://example.invalid/"),
                                 default_audit_dir("https://example.invalid/wp-login.php"))

    def test_flatten_script_retains_dot_git_scans_and_user_changes(self):
        repo = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as d:
            nested = Path(d) / "wordpress-auditor" / "wordpress-auditor"
            (nested / "scripts").mkdir(parents=True)
            (nested / ".git").mkdir()
            (nested / "audit").mkdir()
            (nested / "pyproject.toml").write_text("[project]\nname='fixture'\n")
            (nested / "audit" / "report.json").write_text('{"test":true}\n')
            (nested / "local-change.txt").write_text("retain me")
            source = repo / "scripts" / "flatten-checkout.sh"
            script = nested / "scripts" / "flatten-checkout.sh"
            script.write_bytes(source.read_bytes())
            subprocess.run(["bash", str(script)], check=True,
                           capture_output=True, text=True)
            outer = Path(d) / "wordpress-auditor"
            self.assertTrue((outer / ".git").exists())
            self.assertTrue((outer / "audit" / "report.json").exists())
            self.assertEqual((outer / "local-change.txt").read_text(), "retain me")
            self.assertFalse((outer / "wordpress-auditor").exists())

    def test_flatten_refuses_when_parent_has_other_files(self):
        repo = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as d:
            outer = Path(d) / "wordpress-auditor"
            nested = outer / "wordpress-auditor"
            (nested / "scripts").mkdir(parents=True)
            (nested / ".git").mkdir()
            (nested / "pyproject.toml").write_text("x")
            (outer / "do-not-touch").write_text("original")
            script = nested / "scripts" / "flatten-checkout.sh"
            script.write_bytes((repo / "scripts" / "flatten-checkout.sh").read_bytes())
            p = subprocess.run(["bash", str(script)], capture_output=True, text=True)
            self.assertNotEqual(p.returncode, 0)
            self.assertEqual((outer / "do-not-touch").read_text(), "original")
            self.assertTrue((nested / ".git").exists())


if __name__ == "__main__":
    unittest.main()
