"""ANSI color and live scan presentation; never alters machine-readable artifacts."""
from __future__ import annotations

import os
import re
import sys
from urllib.parse import urlsplit

COLORS = {
    "HIGH": "\033[1;31m",
    "MEDIUM": "\033[1;33m",
    "LOW": "\033[1;36m",
    "REVIEW": "\033[1;35m",
    "INFO": "\033[36m",
    "DONE": "\033[32m",
    "SKIP": "\033[2m",
}
RESET = "\033[0m"
ANSI_RE = re.compile(r"\033\[[0-9;]*m")

def supports_color(stream=None, choice="auto"):
    stream = stream or sys.stderr
    if choice == "never" or os.environ.get("NO_COLOR") is not None:
        return False
    if choice == "always":
        return True
    return bool(getattr(stream, "isatty", lambda: False)() and
                os.environ.get("TERM", "") != "dumb")

def paint(text, label, enabled):
    if not enabled:
        return text
    return COLORS.get(label, "") + text + RESET

def color_summary(text, enabled):
    """Only color known labels, headings and states. No user-controlled ANSI codes."""
    if not enabled:
        return text
    output = []
    for line in text.splitlines():
        if line.startswith("SEVERITY:"):
            colored = line
            for label in ("HIGH", "MEDIUM", "LOW", "REVIEW", "INFO"):
                colored = re.sub(r"\b" + label + r":([1-9][0-9]*)\b",
                                 lambda m, lbl=label: paint(lbl + ":" + m.group(1), lbl, True),
                                 colored)
            output.append(colored)
            continue
        if line.startswith(("WORDPRESS AUDITOR", "WHAT THE ENGINE", "WORDPRESS TECHNIQUE",
                             "OBSERVATIONS", "FOLLOW-UP", "COVERAGE", "FINDINGS")):
            output.append("\033[1m" + line + RESET)
            continue
        updated = line
        for label in ("HIGH", "MEDIUM", "LOW", "REVIEW", "INFO"):
            updated = updated.replace("[" + label + "]",
                                      paint("[" + label + "]", label, True))
        if line.lstrip().startswith("[DONE]"):
            updated = updated.replace("[DONE]", paint("[DONE]", "DONE", True), 1)
        elif line.lstrip().startswith("[SKIP]"):
            updated = updated.replace("[SKIP]", paint("[SKIP]", "SKIP", True), 1)
        output.append(updated)
    return "\n".join(output)

class LivePrinter:
    """Bounded streaming events: phases, periodic progress, and actionable evidence."""

    def __init__(self, enabled=True, color=False, every=10, verbose=False, stream=None):
        self.enabled = enabled
        self.color = color
        self.every = max(1, every)
        self.verbose = verbose
        self.stream = stream or sys.stderr
        self._seen = set()

    def log(self, message, label=None):
        if self.enabled:
            print(paint(message, label, self.color) if label else message,
                  file=self.stream, flush=True)

    def phase(self, event, title, auditor, phase=None):
        if event == "start":
            self.log("  => " + title + " ...")
        elif phase is not None:
            state = phase["state"]
            if state == "done":
                suffix = ""
                if "HTML/JavaScript crawling" in title:
                    suffix = " | discovered %d URLs, %d AJAX actions" % (
                        len(auditor.wordlist), len(auditor.ajax_actions))
                elif "New and previously discovered URL" in title:
                    suffix = " | %d discovered URL checks" % auditor.discovered_checks
                self.log("     [DONE] %d requests / %d results (budget %d/%d)%s" % (
                    phase["requests"], phase["checks"],
                    auditor.request_count, auditor.limit, suffix), "DONE")
            else:
                self.log("     [%s] %s" % (state.upper(), phase["reason"]), "SKIP")

    def request(self, auditor, method, url):
        if auditor.request_count % self.every:
            return
        path = urlsplit(url).path or "/"
        self.log("     [PROGRESS] %d/%d requests | last %s %s" %
                 (auditor.request_count, auditor.limit, method, path[:96]), "INFO")

    def finding(self, auditor, result):
        label = result.severity
        if label == "INFO" and not self.verbose:
            # Show meaningful WP discovery and authentication outcomes live,
            # but do not flood the console with all ordinary 200/401/403s.
            significant = (
                result.name.startswith("WP users public REST listing") and
                result.visibility == "public-author-info"
                or result.name.startswith("WP author archive ID") and
                result.visibility == "public-author-info"
                or result.name.startswith("WP REST authenticated identity")
                or result.name.startswith("WP single test-account login")
                or result.name.startswith("WP XML-RPC test-account authentication")
                or result.name == "XML-RPC system.listMethods"
            )
            if not significant:
                return
        key = (label, result.name, result.url, result.detail)
        if key in self._seen:
            return
        self._seen.add(key)
        path = urlsplit(result.url).path or "/"
        # Already sanitized during auditor.add(); avoid URL queries and body excerpts.
        msg = "     [%s] %s %s | HTTP %s | %s" % (
            label, result.name[:34], path[:95],
            result.status if result.status is not None else "?",
            result.detail[:110] or result.visibility)
        self.log(msg, label)
