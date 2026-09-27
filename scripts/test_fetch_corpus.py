#!/usr/bin/env python3
"""Regression tests for the corpus fetcher's reporting.

D25: the fetcher reported 0/77 on a corpus where all 77 files were already on
disk. Two separate causes, both of them a tool asserting a conclusion it had
not actually established:

  1. Files already on disk were not counted, so a fully-present corpus
     printed as 0/N -- indistinguishable from a corpus that had failed to
     download anything at all.
  2. Transient upstream failures were treated as "this repo has no lockfile",
     so one flaky request permanently removed a target from the reported set.

The same failure class as D01/D22/D23, in the tooling rather than the
product: a number that looks like a finding and is not one. These tests run
the real functions against a temp tree, so they are not a restatement of the
implementation.

Run: python3 scripts/test_fetch_corpus.py
"""

import io
import os
import shutil
import sys
import tempfile
import unittest
from contextlib import redirect_stdout

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fetch_corpus as fc  # noqa: E402


class FetcherReportingTest(unittest.TestCase):
    """The fetcher's reported counts must match what is actually on disk."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self._orig_corpus = fc.CORPUS
        fc.CORPUS = self.tmp

    def tearDown(self):
        fc.CORPUS = self._orig_corpus
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _run(self, spec, filenames):
        """Run fetch_eco with probing stubbed; return (stdout, cache_dir)."""
        buf = io.StringIO()

        def fake_probe(repo, filename, subpaths):
            # Every target reports a lockfile with a fixed body.
            return "package-lock.json", b'{"lockfileVersion":3,"packages":{}}'

        orig_probe = fc.probe_one
        fc.probe_one = fake_probe
        try:
            with redirect_stdout(buf):
                fc.fetch_eco(spec, filenames, "npm", "npm")
        finally:
            fc.probe_one = orig_probe
        return buf.getvalue(), os.path.join(self.tmp, "npm", "real")

    def test_cached_files_are_counted_not_reported_absent(self):
        """D25: a second run must report the same total as the first.

        The bug was that a repo whose file was already on disk was neither
        fetched nor counted, so `have` came out as 0 on a complete corpus.
        """
        spec = {"a/b": ["x"], "c/d": ["x"]}
        filenames = ("package-lock.json",)

        first, _ = self._run(spec, filenames)
        self.assertIn("2/2 repos have a lockfile", first,
                      "cold run should find both targets")
        self.assertIn("2 fetched", first)

        second, _ = self._run(spec, filenames)
        self.assertIn("2/2 repos have a lockfile", second,
                      "warm run must report the same total as the cold run")
        self.assertIn("0 fetched", second)
        self.assertIn("2 already present", second)
        # The specific D25 symptom: not a single repo reported as absent.
        self.assertNotIn("1 have none", second)
        self.assertNotIn("0/2", second)

    def test_partial_cache_reports_both_numbers(self):
        """A half-populated corpus must show 1 fetched and 1 cached."""
        cache = os.path.join(self.tmp, "npm", "real", "a", "b")
        os.makedirs(cache)
        with open(os.path.join(cache, "package-lock.json"), "w") as fh:
            fh.write('{"lockfileVersion":3,"packages":{}}')

        out, _ = self._run({"a/b": ["x"], "c/d": ["x"]}, ("package-lock.json",))
        self.assertIn("2/2 repos have a lockfile", out)
        self.assertIn("1 fetched", out)
        self.assertIn("1 already present", out)

    def test_transient_failure_is_reported_as_error_not_absence(self):
        """A failing request is not evidence the repo has no lockfile."""
        def flaky_probe(repo, filename, subpaths):
            if repo == "flaky/repo":
                raise TimeoutError("simulated upstream timeout")
            return "package-lock.json", b'{"lockfileVersion":3,"packages":{}}'

        buf = io.StringIO()
        orig = fc.probe_one
        fc.probe_one = flaky_probe
        try:
            with redirect_stdout(buf):
                fc.fetch_eco({"flaky/repo": ["x"], "good/repo": ["x"]},
                             ("package-lock.json",), "npm", "npm")
        finally:
            fc.probe_one = orig

        out = buf.getvalue()
        self.assertIn("ERROR", out, "a failed fetch must be logged as an error")
        self.assertIn("flaky/repo", out)
        # The good repo still counts.
        self.assertIn("1/2 repos have a lockfile", out)

    def test_empty_file_is_not_treated_as_cached(self):
        """A zero-byte file is a failed download, not a usable fixture."""
        cache = os.path.join(self.tmp, "npm", "real", "a", "b")
        os.makedirs(cache)
        with open(os.path.join(cache, "package-lock.json"), "w") as fh:
            fh.write("")

        out, _ = self._run({"a/b": ["x"]}, ("package-lock.json",))
        # It must be refetched. The count has to be matched as a number:
        # assertNotIn("already present") passes against the substring inside
        # the correct output "0 already present", so it would green-light the
        # exact bug it was written to catch.
        self.assertIn("1 fetched", out)
        self.assertIn("0 already present", out)
        self.assertNotRegex(out, r"[1-9]\d* already present")

    def test_summary_counts_actual_files_on_disk(self):
        """summary() must report real files, not the number of targets."""
        d = os.path.join(self.tmp, "npm", "real", "some", "deep", "path")
        os.makedirs(d)
        for n in range(3):
            with open(os.path.join(d, f"f{n}.txt"), "w") as fh:
                fh.write("x" * 10)
        buf = io.StringIO()
        with redirect_stdout(buf):
            fc.summary()
        self.assertIn("corpus npm: 3 files", buf.getvalue())


class NpmV1TagTest(unittest.TestCase):
    """npm v1 fixtures come from pinned tags, with a known-good URL shape."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self._orig_corpus = fc.CORPUS
        fc.CORPUS = self.tmp

    def tearDown(self):
        fc.CORPUS = self._orig_corpus
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_tag_urls_carry_the_v_prefix(self):
        """Without the `v`, every URL 404s and the corpus reads as empty.

        This is the exact bug that cost a full search: probing
        `mochajs/mocha/6.2.0/package-lock.json` returns 404, which looks
        identical to "this project has no lockfile". The fix is asserted
        here so the prefix cannot be dropped again.
        """
        recorded = []

        def fake_get(url):
            recorded.append(url)
            if "package.json" in url:
                return b'{"name":"x","version":"1.0.0"}'
            return b'{"lockfileVersion":1,"dependencies":{}}'

        orig = fc.get
        fc.get = fake_get
        try:
            buf = io.StringIO()
            with redirect_stdout(buf):
                fc.fetch_npm_v1()
        finally:
            fc.get = orig

        self.assertTrue(recorded, "fetch_npm_v1 made no requests")
        # get() is called with a repo-relative path and builds the raw
        # GitHub URL itself, so the tag ref is asserted on the path as
        # passed, not on a fully-qualified URL.
        for url in recorded:
            self.assertRegex(url, r"^\S+/v\d", 
                             f"tag path missing the v prefix: {url}")
        for repo, tag in fc.NPM_V1_TAGS:
            self.assertTrue(
                any(f"{repo}/v{tag}/package-lock.json" == u for u in recorded),
                f"no lockfile request recorded for {repo}@v{tag} (got {recorded})")

    def test_zero_v1_fixtures_is_loud(self):
        """A silently-empty v1 corpus must warn, not pass quietly."""
        orig = fc.get
        fc.get = lambda url: None          # every probe comes back empty
        buf = io.StringIO()
        try:
            with redirect_stdout(buf):
                fc.fetch_npm_v1()
        finally:
            fc.get = orig
        self.assertIn("WARNING", buf.getvalue(),
                      "a zero-fixture v1 run must warn loudly")


if __name__ == "__main__":
    unittest.main(verbosity=2)
