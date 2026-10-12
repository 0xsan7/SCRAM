"""The mutation harness must fail when a mutant cannot be evaluated."""
import contextlib
import importlib.util
import io
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock


class MutationHarnessTests(unittest.TestCase):
    def test_only_killed_mutants_pass(self):
        script = Path(__file__).with_name("mutation_audit.py")
        spec = importlib.util.spec_from_file_location("mutation_audit_under_test", script)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        for status in ("killed", "SURVIVED", "INVALID", "BROKEN"):
            with self.subTest(status=status), tempfile.TemporaryDirectory() as root:
                Path(root, "scripts").mkdir()
                result = {"id": "fixture", "status": status, "why": "synthetic harness check"}
                with mock.patch.object(module, "ROOT", root), \
                     mock.patch.object(module, "MUTANTS", [("fixture", "", "", "", [])]), \
                     mock.patch.object(module, "check_mutant", return_value=result), \
                     mock.patch.object(module.shutil, "copytree"), \
                     mock.patch.object(sys, "argv", [str(script), "--jobs", "1"]), \
                     contextlib.redirect_stdout(io.StringIO()):
                    self.assertEqual(module.main(), 0 if status == "killed" else 1)


if __name__ == "__main__":
    unittest.main()
