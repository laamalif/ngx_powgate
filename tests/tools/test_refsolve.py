import hashlib
import json
from pathlib import Path
import subprocess
import sys
import unittest


ROOT = Path(__file__).resolve().parents[2]
REFSOLVE = ROOT / "tools" / "refsolve.py"
VECTOR = ROOT / "tests" / "vectors" / "v1.json"


class RefsolveTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.case = json.loads(VECTOR.read_text(encoding="utf-8"))["cases"][0]

    def run_refsolve(self, *arguments):
        return subprocess.run(
            [sys.executable, str(REFSOLVE), *map(str, arguments)],
            cwd=ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=10,
        )

    def context_arguments(self):
        return (
            "--secret-hex", self.case["secret_hex"],
            "--ip", self.case["ip"],
            "--plen", self.case["plen"],
            "--bucket", self.case["bucket"],
            "--difficulty", self.case["difficulty"],
        )

    def output_json(self, result):
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertEqual(result.stderr, b"")
        self.assertLessEqual(len(result.stdout), 2048)
        return json.loads(result.stdout)

    def test_verify_preserves_immutable_vector_contract(self):
        result = self.run_refsolve("verify", "tests/vectors/v1.json")

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            result.stdout,
            b"tests/vectors/v1.json: 1 case verified\n",
        )
        self.assertEqual(result.stderr, b"")

    def test_auth_accepts_mixed_case_cli_secret_and_matches_vector(self):
        secret = "".join(
            character.upper() if index % 2 else character
            for index, character in enumerate(self.case["secret_hex"])
        )
        result = self.run_refsolve(
            "auth",
            "--secret-hex", secret,
            "--ip", self.case["ip"],
            "--expiry", self.case["expiry"],
            "--difficulty", self.case["difficulty"],
            "--plen", self.case["plen"],
        )
        output = self.output_json(result)

        self.assertEqual(
            set(output),
            {
                "auth_cookie",
                "auth_mac_hex",
                "auth_payload_hex",
                "masked_ip16_hex",
            },
        )
        self.assertEqual(output["auth_cookie"], self.case["auth_cookie"])
        self.assertEqual(output["auth_mac_hex"], self.case["auth_mac_hex"])
        self.assertEqual(
            output["auth_payload_hex"], self.case["auth_payload_hex"]
        )
        self.assertEqual(
            output["masked_ip16_hex"], self.case["masked_ip16_hex"]
        )
        self.assertTrue(all(isinstance(value, str) for value in output.values()))

    def test_mine_starts_at_requested_counter_and_returns_complete_cookie(self):
        start = self.case["counter"]
        result = self.run_refsolve(
            "mine", *self.context_arguments(), "--start-counter", start
        )
        output = self.output_json(result)

        self.assertEqual(
            set(output),
            {
                "counter",
                "counter_ascii",
                "masked_ip16_hex",
                "nonce_b64url",
                "nonce_hex",
                "proof_cookie",
                "proof_digest_hex",
            },
        )
        self.assertEqual(output["counter"], self.case["counter"])
        self.assertEqual(output["counter_ascii"], self.case["counter_ascii"])
        self.assertEqual(
            output["proof_cookie"],
            f"1.{self.case['bucket']}.{self.case['counter']}",
        )
        self.assertEqual(output["nonce_hex"], self.case["nonce_hex"])
        self.assertEqual(
            output["proof_digest_hex"], self.case["proof_digest_hex"]
        )
        self.assertIs(type(output["counter"]), int)
        for key, value in output.items():
            if key != "counter":
                self.assertIs(type(value), str, key)

    def test_mine_returns_first_valid_counter_at_or_after_start(self):
        start = self.case["counter"] + 1
        output = self.output_json(
            self.run_refsolve(
                "mine", *self.context_arguments(), "--start-counter", start
            )
        )
        nonce = bytes.fromhex(output["nonce_hex"])
        limit = 1 << (256 - self.case["difficulty"])

        self.assertGreaterEqual(output["counter"], start)
        for counter in range(start, output["counter"]):
            digest = hashlib.sha256(nonce + str(counter).encode("ascii"))
            self.assertGreaterEqual(int.from_bytes(digest.digest(), "big"), limit)
        digest = hashlib.sha256(
            nonce + str(output["counter"]).encode("ascii")
        )
        self.assertLess(int.from_bytes(digest.digest(), "big"), limit)

    def test_proof_check_reports_valid_and_invalid_explicit_counters(self):
        valid = self.output_json(
            self.run_refsolve(
                "proof-check",
                *self.context_arguments(),
                "--counter", self.case["counter"],
            )
        )
        invalid = self.output_json(
            self.run_refsolve(
                "proof-check",
                *self.context_arguments(),
                "--counter", self.case["counter"] - 1,
            )
        )

        expected_keys = {
            "counter", "counter_ascii", "proof_digest_hex", "valid"
        }
        self.assertEqual(set(valid), expected_keys)
        self.assertEqual(set(invalid), expected_keys)
        self.assertIs(valid["valid"], True)
        self.assertIs(invalid["valid"], False)
        self.assertEqual(valid["proof_digest_hex"], self.case["proof_digest_hex"])
        self.assertIs(type(valid["counter"]), int)
        self.assertIs(type(valid["counter_ascii"]), str)
        self.assertIs(type(valid["proof_digest_hex"]), str)

    def test_rejects_malformed_and_out_of_range_arguments(self):
        cases = (
            ("mine", *self.context_arguments(), "--secret-hex", "00"),
            ("mine", *self.context_arguments(), "--difficulty", 0),
            (
                "proof-check", *self.context_arguments(),
                "--counter", -1,
            ),
            (
                "auth",
                "--secret-hex", self.case["secret_hex"],
                "--ip", self.case["ip"],
                "--expiry", self.case["expiry"],
                "--difficulty", self.case["difficulty"],
            ),
        )

        for arguments in cases:
            with self.subTest(arguments=arguments):
                result = self.run_refsolve(*arguments)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stdout, b"")
                self.assertNotEqual(result.stderr, b"")
                self.assertLessEqual(len(result.stderr), 2048)


if __name__ == "__main__":
    unittest.main()
