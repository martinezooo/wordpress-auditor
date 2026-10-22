"""Persistent discovery queue integration. All HTTP is localhost only."""
import contextlib
import io
import json
import os
import tempfile
import unittest
from urllib.parse import urlsplit

from test_explain import ExplainScanTest
from wordpress_auditor.auditor import Auditor
from wordpress_auditor.cli import main
from wordpress_auditor.queue import load_previous, save


class ResumeQueueTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        ExplainScanTest.setUpClass()
        cls.url = ExplainScanTest.url

    @classmethod
    def tearDownClass(cls):
        ExplainScanTest.tearDownClass()

    def test_new_scans_advance_across_pending_discoveries(self):
        with tempfile.TemporaryDirectory() as tmp:
            wl = os.path.join(tmp, "wordlist.txt")
            histories = []
            for _ in range(3):
                with contextlib.redirect_stdout(io.StringIO()):
                    main(["--url", self.url, "--quick",
                          "--max-requests", "30", "--payload-limit", "0",
                          "--delay", "0", "--wordlist-out", wl])
                with open(os.path.join(tmp, "url-queue.json")) as handle:
                    state = json.load(handle)
                self.assertGreaterEqual(state["pending_count"], 40)
                histories.append(set(state["verified_urls"]))
                self.assertIn("origin", state)
                self.assertEqual(state["origin"], self.url)
                self.assertEqual(len(state["verified_urls"]), state["checked_count"])
            self.assertTrue(histories[0] < histories[1] < histories[2])
            self.assertGreater(len(histories[-1] - histories[0]), 5)

    def test_no_prior_recheck_unless_explicitly_requested(self):
        a = Auditor(self.url, limit=6, delay=0)
        a.wordlist.add(self.url + "/content/000")
        a.prior_verified_urls.add(self.url + "/content/000")
        from wordpress_auditor.probes import ProbeSuite
        self.assertEqual(ProbeSuite(a).probe_discovered(5), 0)
        self.assertEqual(a.request_count, 0)
        a.recheck_prior_urls = True
        self.assertEqual(ProbeSuite(a).probe_discovered(5), 1)
        self.assertEqual(a.request_count, 1)

    def test_queue_is_origin_scoped_no_cross_site_checking(self):
        with tempfile.TemporaryDirectory() as tmp:
            queue = os.path.join(tmp, "url-queue.json")
            data = {
                "origin": self.url,
                "verified_urls": [
                    self.url + "/content/000",
                    "https://different.invalid/private",
                    self.url + "/?token=123",
                    self.url + "/logout",
                ],
            }
            with open(queue, "w") as f:
                json.dump(data, f)
            a = Auditor(self.url)
            self.assertEqual(load_previous(a, queue), 1)
            self.assertEqual(a.prior_verified_urls, {self.url + "/content/000"})
            data["origin"] = "https://different.invalid"
            with open(queue, "w") as f:
                json.dump(data, f)
            self.assertEqual(load_previous(a, queue), 0)
            self.assertEqual(a.prior_verified_urls, set())

    def test_saving_queue_does_not_mark_network_failures_verified(self):
        with tempfile.TemporaryDirectory() as tmp:
            a = Auditor(self.url, limit=3)
            a.wordlist = {
                self.url + "/content/001",
                self.url + "/content/002",
            }
            a.successful_get_urls = {self.url + "/content/001"}
            state = save(a, os.path.join(tmp, "queue.json"))
            self.assertEqual(state["checked_count"], 1)
            self.assertEqual(state["pending_count"], 1)
            self.assertEqual(state["pending_urls"], [self.url + "/content/002"])

    def test_queue_is_scoped_to_wordpress_root_and_keeps_provenance(self):
        with tempfile.TemporaryDirectory() as tmp:
            queue = os.path.join(tmp, "queue.json")
            mounted = Auditor(self.url + "/blog", limit=2)
            found = self.url + "/blog/unlinked-post/"
            mounted._wordlist_url(found, source="sitemap:/blog/wp-sitemap.xml")
            state = save(mounted, queue)
            self.assertEqual(state["root"], self.url + "/blog/")
            self.assertEqual(state["sources"][found],
                             ["sitemap:/blog/wp-sitemap.xml"])
            same_root = Auditor(self.url + "/blog")
            self.assertEqual(load_previous(same_root, queue), 0)
            self.assertEqual(same_root.discovery_sources[found],
                             {"sitemap:/blog/wp-sitemap.xml"})
            other_root = Auditor(self.url + "/shop")
            self.assertEqual(load_previous(other_root, queue), 0)
            self.assertEqual(other_root.discovery_sources, {})

    def test_report_queue_contains_no_cookies_or_query_strings(self):
        with tempfile.TemporaryDirectory() as tmp:
            wl = os.path.join(tmp, "wordlist.txt")
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                main(["--url", self.url, "--quick", "--max-requests", "28",
                      "--delay", "0", "--wordlist-out", wl])
            with open(os.path.join(tmp, "url-queue.json"), encoding="utf-8") as f:
                data = f.read()
            self.assertNotIn("Cookie", data)
            self.assertNotIn("Authorization", data)
            self.assertTrue(all("?" not in url for url in
                json.loads(data)["verified_urls"] + json.loads(data)["pending_urls"]))
            self.assertIn("URL queue:", stdout.getvalue())


if __name__ == "__main__":
    unittest.main()
