import importlib.util
import hashlib
import json
import pathlib
import shutil
import subprocess
import sys
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "golden-image-lock.py"
SPEC = importlib.util.spec_from_file_location("golden_image_lock", TOOL)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot load golden-image-lock.py")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)

OWNED_INPUTS = MODULE.OWNED_INPUTS
compute_lock = MODULE.compute_lock


class GoldenImageLockTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.temporary.name)
        for index, relative in enumerate(OWNED_INPUTS):
            path = self.root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(f"input-{index}\n".encode("ascii"))
        manifest = {
            "name": "fixture",
            "private": True,
            "version": "1.0.0",
            "devDependencies": {
                "ajv": "8.17.1",
                "puppeteer-core": "24.43.1",
            },
        }
        lock = {
            "name": "fixture",
            "version": "1.0.0",
            "lockfileVersion": 3,
            "requires": True,
            "packages": {
                "": {
                    "name": "fixture",
                    "version": "1.0.0",
                    "devDependencies": {
                        "ajv": "8.17.1",
                        "puppeteer-core": "24.43.1",
                    },
                },
                "node_modules/ajv": {
                    "version": "8.17.1",
                    "resolved": "https://registry.npmjs.org/ajv/-/ajv-8.17.1.tgz",
                    "integrity": "sha512-example",
                    "dev": True,
                },
                "node_modules/puppeteer-core": {
                    "version": "24.43.1",
                    "resolved": "https://registry.npmjs.org/puppeteer-core/-/puppeteer-core-24.43.1.tgz",
                    "integrity": "sha512-example",
                    "dev": True,
                },
            },
        }
        (self.root / "build/browser/package.json").write_text(
            json.dumps(manifest), encoding="utf-8"
        )
        (self.root / "build/browser/package-lock.json").write_text(
            json.dumps(lock), encoding="utf-8"
        )
        (self.root / "build/versions.env").write_text(
            "PUPPETEER_CORE_VERSION=24.43.1\n"
            "AJV_VERSION=8.17.1\n"
            "AJV_INTEGRITY=sha512-example\n",
            encoding="ascii",
        )

    def tearDown(self):
        self.temporary.cleanup()

    def write(self, relative, body, *, append=False, root=None):
        path = (root or self.root) / relative
        mode = "ab" if append else "wb"
        data = body.encode("ascii") if isinstance(body, str) else body
        with path.open(mode) as output:
            output.write(data)

    def copy_root(self):
        clone = pathlib.Path(tempfile.mkdtemp(dir=self.temporary.name))
        for relative in OWNED_INPUTS:
            source = self.root / relative
            target = clone / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, target)
        return clone

    def run_check(self, value):
        versions = self.root / "build" / "versions.env"
        body = versions.read_bytes()
        body = b"".join(
            line
            for line in body.splitlines(keepends=True)
            if not line.startswith(b"GOLDEN_IMAGE_LOCK_SHA256=")
        )
        if value is not None:
            body += f"GOLDEN_IMAGE_LOCK_SHA256={value}\n".encode("ascii")
        versions.write_bytes(body)
        return subprocess.run(
            [sys.executable, str(TOOL), "check", "--root", str(self.root)],
            check=False,
            capture_output=True,
            text=True,
        )

    def test_encoding_is_ordered_length_prefixed_and_excludes_self_line(self):
        first = compute_lock(self.root)
        self.write(
            "build/versions.env",
            "GOLDEN_IMAGE_LOCK_SHA256=" + "0" * 64 + "\n",
            append=True,
        )
        self.assertEqual(compute_lock(self.root), first)

        digest = hashlib.sha256()
        for relative in reversed(OWNED_INPUTS):
            digest.update(MODULE.canonical_body(relative, (self.root / relative).read_bytes()))
        self.assertNotEqual(digest.hexdigest(), first)

    def test_each_owned_input_changes_the_lock(self):
        baseline = compute_lock(self.root)
        for relative in OWNED_INPUTS:
            with self.subTest(relative=relative):
                clone = self.copy_root()
                self.write(relative, b"\nmutation\n", append=True, root=clone)
                self.assertNotEqual(compute_lock(clone), baseline)

    def test_check_rejects_missing_malformed_and_stale_lock(self):
        for value in (None, "xyz", "0" * 64):
            with self.subTest(value=value):
                self.assertNotEqual(self.run_check(value).returncode, 0)

    def test_check_accepts_current_lock(self):
        self.assertEqual(self.run_check(compute_lock(self.root)).returncode, 0)

    def test_update_replaces_exactly_one_lock_line(self):
        versions = self.root / "build" / "versions.env"
        versions.write_bytes(
            versions.read_bytes() + b"GOLDEN_IMAGE_LOCK_SHA256=" + b"0" * 64 + b"\n"
        )
        result = subprocess.run(
            [sys.executable, str(TOOL), "update", "--root", str(self.root)],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        lines = [
            line
            for line in versions.read_text(encoding="ascii").splitlines()
            if line.startswith("GOLDEN_IMAGE_LOCK_SHA256=")
        ]
        self.assertEqual(lines, ["GOLDEN_IMAGE_LOCK_SHA256=" + compute_lock(self.root)])


class BrowserDependencyPolicyTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.temporary.name)
        browser = self.root / "build" / "browser"
        browser.mkdir(parents=True)
        self.manifest = {
            "name": "ngx-powgate-browser-tests",
            "private": True,
            "version": "1.0.0",
            "devDependencies": {
                "ajv": "8.17.1",
                "puppeteer-core": "24.43.1",
            },
        }
        self.lock = {
            "name": "ngx-powgate-browser-tests",
            "version": "1.0.0",
            "lockfileVersion": 3,
            "requires": True,
            "packages": {
                "": {
                    "name": "ngx-powgate-browser-tests",
                    "version": "1.0.0",
                    "devDependencies": dict(self.manifest["devDependencies"]),
                },
                "node_modules/ajv": {
                    "version": "8.17.1",
                    "resolved": "https://registry.npmjs.org/ajv/-/ajv-8.17.1.tgz",
                    "integrity": "sha512-example",
                    "dev": True,
                },
                "node_modules/puppeteer-core": {
                    "version": "24.43.1",
                    "resolved": "https://registry.npmjs.org/puppeteer-core/-/puppeteer-core-24.43.1.tgz",
                    "integrity": "sha512-example",
                    "dev": True,
                },
            },
        }
        (self.root / "build" / "versions.env").write_text(
            "PUPPETEER_CORE_VERSION=24.43.1\n"
            "AJV_VERSION=8.17.1\n"
            "AJV_INTEGRITY=sha512-example\n",
            encoding="ascii",
        )
        self.write_files()

    def tearDown(self):
        self.temporary.cleanup()

    def write_files(self):
        browser = self.root / "build" / "browser"
        (browser / "package.json").write_text(json.dumps(self.manifest), encoding="utf-8")
        (browser / "package-lock.json").write_text(json.dumps(self.lock), encoding="utf-8")

    def assert_policy_error(self, text):
        self.write_files()
        with self.assertRaisesRegex(ValueError, text):
            MODULE.validate_browser_dependencies(self.root)

    def test_accepts_exact_development_dependencies_and_integrity(self):
        MODULE.validate_browser_dependencies(self.root)

    def test_rejects_dependency_ranges(self):
        self.manifest["devDependencies"]["ajv"] = "^8.17.1"
        self.assert_policy_error("exact version")

    def test_rejects_direct_browser_download_packages(self):
        for package in ("puppeteer", "@puppeteer/browsers"):
            with self.subTest(package=package):
                self.manifest["devDependencies"][package] = "1.0.0"
                self.assert_policy_error("browser-download package")
                del self.manifest["devDependencies"][package]

    def test_rejects_browser_acquisition_lifecycle_scripts(self):
        for script in ("preinstall", "install", "postinstall"):
            with self.subTest(script=script):
                self.manifest["scripts"] = {script: "download-browser"}
                self.assert_policy_error("lifecycle browser acquisition")
                del self.manifest["scripts"]

    def test_rejects_runtime_dependencies(self):
        self.manifest["dependencies"] = {"ajv": "8.17.1"}
        self.assert_policy_error("devDependencies")

    def test_rejects_root_lock_disagreement(self):
        self.lock["packages"][""]["devDependencies"]["ajv"] = "8.17.0"
        self.assert_policy_error("root dependencies")

    def test_rejects_version_lock_disagreement(self):
        versions = self.root / "build" / "versions.env"
        versions.write_text(
            versions.read_text(encoding="ascii").replace("AJV_VERSION=8.17.1", "AJV_VERSION=8.17.0"),
            encoding="ascii",
        )
        with self.assertRaisesRegex(ValueError, "versions.env"):
            MODULE.validate_browser_dependencies(self.root)

    def test_rejects_ajv_integrity_disagreement(self):
        self.lock["packages"]["node_modules/ajv"]["integrity"] = "sha512-wrong"
        self.assert_policy_error("Ajv integrity")

    def test_rejects_missing_registry_integrity(self):
        del self.lock["packages"]["node_modules/ajv"]["integrity"]
        self.assert_policy_error("integrity")


if __name__ == "__main__":
    unittest.main()
