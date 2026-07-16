import pathlib
import re
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]


class Phase4CReleaseGateTests(unittest.TestCase):
    def test_makefile_exposes_architecture_neutral_browser_unit_gate(self):
        makefile = (ROOT / "Makefile").read_text(encoding="utf-8")

        match = re.search(r"^test-browser-unit:[^\n]*\n((?:\t.*\n)+)",
                          makefile, re.MULTILINE)
        self.assertIsNotNone(match)
        recipe = match.group(1)
        for test_file in (
            "fixture.test.mjs",
            "request-observation.test.mjs",
            "e2e.test.mjs",
            "sanitizer.test.mjs",
            "evidence.test.mjs",
            "benchmark.test.mjs",
        ):
            self.assertIn(test_file, recipe)

        check = re.search(r"^check:([^\n]*(?:\\\n\t+[^\n]*)*)", makefile,
                          re.MULTILINE)
        self.assertIsNotNone(check)
        self.assertIn("test-browser-unit", check.group(1))

    def test_makefile_exposes_lightweight_committed_evidence_gate(self):
        makefile = (ROOT / "Makefile").read_text(encoding="utf-8")

        match = re.search(r"^check-phase4c-evidence:([^\n]*)\n"
                          r"((?:\t.*\n)+)", makefile, re.MULTILINE)
        self.assertIsNotNone(match)
        self.assertIn("check-policy", match.group(1))
        self.assertIn("test-browser-evidence", match.group(1))
        self.assertIn("tools/check-phase4c-evidence.mjs", match.group(2))


if __name__ == "__main__":
    unittest.main()
