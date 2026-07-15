import json
import os
import pathlib
import stat
import subprocess
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]
WRAPPER = ROOT / "tools" / "run-browser-x86.sh"
GUARD = ROOT / "tools" / "require-browser-x86.sh"
IMAGE = "localhost/ngx-powgate-dev:trixie"
LABEL = "org.ngx-powgate.golden-image-lock"
APPROVED = (
    "test-browser-feasibility",
    "test-browser-e2e",
    "test-browser-partitioned-feasibility",
    "benchmark-browser",
    "check-browser-x86",
)
REMOTE_ENVIRONMENT = (
    "POW_GATE_BROWSER_WS_ENDPOINT",
    "PUPPETEER_BROWSER_WS_ENDPOINT",
    "PUPPETEER_EXECUTABLE_PATH",
    "CHROME_PATH",
)


def version_lock():
    values = {}
    for line in (ROOT / "build" / "versions.env").read_text(
        encoding="ascii"
    ).splitlines():
        if line and not line.startswith("#"):
            name, value = line.split("=", 1)
            values[name] = value
    return values


class RunBrowserX86Test(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.directory = pathlib.Path(self.temporary.name)
        self.bin = self.directory / "bin"
        self.bin.mkdir()
        self.record = self.directory / "run.json"
        fake = self.bin / "podman"
        fake.write_text(
            """#!/usr/bin/env python3
import json
import os
import pathlib
import sys

args = sys.argv[1:]
if args[0] == "info":
    print(json.dumps({"host": {"security": {"rootless":
        os.environ.get("FAKE_ROOTLESS", "1") == "1"}}}))
elif args[:2] == ["image", "inspect"]:
    print(json.dumps([{
        "Id": "sha256:fixed-image-id",
        "Architecture": os.environ.get("FAKE_ARCH", "amd64"),
        "RepoDigests": ["localhost/ngx-powgate-dev@sha256:fixed-digest"],
        "Labels": {"org.ngx-powgate.golden-image-lock":
            os.environ["FAKE_IMAGE_LOCK"]},
    }]))
elif args[0] == "version":
    print("5.4.2")
elif args[0] == "run":
    pathlib.Path(os.environ["FAKE_RUN_RECORD"]).write_text(
        json.dumps(args), encoding="utf-8")
else:
    raise SystemExit("unexpected podman invocation: " + repr(args))
""",
            encoding="utf-8",
        )
        fake.chmod(fake.stat().st_mode | stat.S_IXUSR)
        fake_git = self.bin / "git"
        fake_git.write_text(
            "#!/bin/sh\n"
            "test \"$1 $2\" = \"rev-parse --show-toplevel\" || exit 2\n"
            f"printf '%s\\n' {ROOT.resolve()}\n",
            encoding="utf-8",
        )
        fake_git.chmod(fake_git.stat().st_mode | stat.S_IXUSR)

    def tearDown(self):
        self.temporary.cleanup()

    def run_wrapper(self, *arguments, env=None, cwd=ROOT):
        values = os.environ.copy()
        values.update(
            {
                "PATH": f"{self.bin}:{values['PATH']}",
                "FAKE_IMAGE_LOCK": version_lock()["GOLDEN_IMAGE_LOCK_SHA256"],
                "FAKE_RUN_RECORD": str(self.record),
            }
        )
        if env:
            values.update(env)
        return subprocess.run(
            ["/bin/sh", str(WRAPPER), *arguments],
            cwd=cwd,
            env=values,
            check=False,
            capture_output=True,
            text=True,
        )

    def recorded_run_argv(self):
        return json.loads(self.record.read_text(encoding="utf-8"))

    def expected_run_argv(self, target):
        lock = version_lock()["GOLDEN_IMAGE_LOCK_SHA256"]
        return [
            "run",
            "--rm",
            "--userns=keep-id",
            "-v",
            f"{ROOT.resolve()}:/work:Z",
            "-w",
            "/work",
            "-e",
            f"POWGATE_HOST_UID={os.getuid()}",
            "-e",
            f"POWGATE_HOST_GID={os.getgid()}",
            "-e",
            "POWGATE_IMAGE_ID=sha256:fixed-image-id",
            "-e",
            "POWGATE_IMAGE_DIGEST=localhost/ngx-powgate-dev@sha256:fixed-digest",
            "-e",
            f"POWGATE_IMAGE_LOCK={lock}",
            "-e",
            "POWGATE_PODMAN_VERSION=5.4.2",
            IMAGE,
            "make",
            target,
        ]

    def test_rejects_zero_two_or_unknown_targets(self):
        for arguments in ((), ("unknown",), (APPROVED[0], APPROVED[1])):
            with self.subTest(arguments=arguments):
                self.assertNotEqual(self.run_wrapper(*arguments).returncode, 0)

    def test_rejects_remote_browser_environment(self):
        for name in REMOTE_ENVIRONMENT:
            with self.subTest(name=name):
                result = self.run_wrapper(APPROVED[0], env={name: "forbidden"})
                self.assertNotEqual(result.returncode, 0)

    def test_rejects_rootful_non_amd64_and_mismatched_label(self):
        cases = (
            ({"FAKE_ROOTLESS": "0"}, "rootless"),
            ({"FAKE_ARCH": "arm64"}, "amd64"),
            ({"FAKE_IMAGE_LOCK": "0" * 64}, "lock"),
        )
        for environment, message in cases:
            with self.subTest(environment=environment):
                result = self.run_wrapper(APPROVED[0], env=environment)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(message, result.stderr.lower())

    def test_rejects_working_directory_below_repository_root(self):
        result = self.run_wrapper(APPROVED[0], cwd=ROOT / "tests")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("repository root", result.stderr.lower())

    def test_success_uses_only_the_fixed_invocation(self):
        result = self.run_wrapper(APPROVED[0])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            self.recorded_run_argv(), self.expected_run_argv(APPROVED[0])
        )


class RequireBrowserX86Test(unittest.TestCase):
    def run_guard(self, target=APPROVED[0], env=None):
        values = os.environ.copy()
        values.update(
            {
                "POWGATE_HOST_UID": str(os.getuid()),
                "POWGATE_HOST_GID": str(os.getgid()),
                "POWGATE_IMAGE_ID": "sha256:test",
                "POWGATE_IMAGE_DIGEST": "",
                "POWGATE_IMAGE_LOCK": version_lock()["GOLDEN_IMAGE_LOCK_SHA256"],
                "POWGATE_PODMAN_VERSION": "5.4.2",
            }
        )
        if env:
            values.update(env)
        return subprocess.run(
            ["/bin/sh", str(GUARD), target],
            cwd=ROOT,
            env=values,
            check=False,
            capture_output=True,
            text=True,
        )

    def test_accepts_the_canonical_container_identity(self):
        for target in APPROVED:
            with self.subTest(target=target):
                result = self.run_guard(target)
                self.assertEqual(result.returncode, 0, result.stderr)

    def test_non_x86_diagnostic_names_the_public_target(self):
        with tempfile.TemporaryDirectory() as temporary:
            fake = pathlib.Path(temporary) / "uname"
            fake.write_text("#!/bin/sh\nprintf '%s\\n' aarch64\n", encoding="ascii")
            fake.chmod(fake.stat().st_mode | stat.S_IXUSR)
            result = self.run_guard(
                "test-browser-e2e",
                env={"PATH": f"{temporary}:{os.environ['PATH']}"},
            )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("test-browser-e2e", result.stderr)
        self.assertIn("aarch64", result.stderr)

    def test_rejects_remote_browser_environment(self):
        for name in REMOTE_ENVIRONMENT:
            with self.subTest(name=name):
                result = self.run_guard(env={name: "forbidden"})
                self.assertNotEqual(result.returncode, 0)


class BrowserMakeTargetsTest(unittest.TestCase):
    def test_browser_aggregate_is_sequential_and_bounded(self):
        makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
        for target in APPROVED:
            self.assertIn(f"{target}:", makefile)
        self.assertIn("--kill-after=20s 1280s", makefile)
        self.assertIn(
            "$(MAKE) test-browser-feasibility && $(MAKE) test-browser-e2e && "
            "$(MAKE) benchmark-browser",
            makefile.replace("\\\n\t  ", ""),
        )


if __name__ == "__main__":
    unittest.main()
