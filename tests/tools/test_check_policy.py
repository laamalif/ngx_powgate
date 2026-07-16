import os
import pathlib
import shutil
import subprocess
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]


class SanitizerPolicyTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.temporary.name)
        (self.root / "tools").mkdir()
        (self.root / "src").mkdir()
        (self.root / "out").mkdir()
        shutil.copy(ROOT / "tools" / "check-policy.sh",
                    self.root / "tools" / "check-policy.sh")
        shutil.copy(ROOT / "tools" / "ubsan-nginx.supp",
                    self.root / "tools" / "ubsan-nginx.supp")
        (self.root / "tools" / "golden-image-lock.py").write_text(
            "raise SystemExit(0)\n", encoding="ascii"
        )
        (self.root / "src" / "pow_parse.c").write_text(
            "int pow_policy_control(void) { return 0; }\n", encoding="ascii"
        )
        (self.root / "Makefile").write_text("all:\n\t@true\n", encoding="ascii")

    def tearDown(self):
        self.temporary.cleanup()

    def run_policy(self):
        return subprocess.run(
            ["/bin/sh", "tools/check-policy.sh"],
            cwd=self.root,
            env={**os.environ, "LC_ALL": "C"},
            check=False,
            capture_output=True,
            text=True,
        )

    def test_clean_minimal_tree_passes(self):
        result = self.run_policy()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_rejects_project_alignment_sanitizer_exclusions(self):
        rows = (
            '__attribute__((no_sanitize("alignment")))\n'
            "int pow_policy_control(void) { return 0; }\n",
        )
        for source in rows:
            with self.subTest(source=source):
                (self.root / "src" / "pow_parse.c").write_text(
                    source, encoding="ascii"
                )
                result = self.run_policy()
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("alignment sanitizer", result.stdout)

    def test_rejects_alignment_disabled_by_build_flags(self):
        (self.root / "Makefile").write_text(
            "CFLAGS=-fno-sanitize=alignment\n", encoding="ascii"
        )
        result = self.run_policy()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("alignment sanitizer disabled", result.stdout)

    def test_rejects_fault_or_negative_artifacts_under_out(self):
        for name in ("module-fault.so", "alignment-negative-control"):
            with self.subTest(name=name):
                artifact = self.root / "out" / name
                artifact.write_bytes(b"artifact")
                result = self.run_policy()
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("test artifact under out", result.stdout)
                artifact.unlink()


if __name__ == "__main__":
    unittest.main()
