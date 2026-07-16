#!/usr/bin/env python3

import argparse
import hashlib
import hmac
import json
import os
import pathlib
import re
import struct
import sys
import tempfile


OWNED_INPUTS = (
    "Containerfile",
    "build/install-dev.sh",
    "build/versions.env",
    "build/browser/package.json",
    "build/browser/package-lock.json",
)
LOCK_PREFIX = b"GOLDEN_IMAGE_LOCK_SHA256="
LOCK_PATTERN = re.compile(rb"^[0-9a-f]{64}$")
EXACT_NPM_VERSION = re.compile(r"^[0-9]+(?:\.[0-9]+){2}(?:[-+][0-9A-Za-z.-]+)?$")
FORBIDDEN_DIRECT_PACKAGES = frozenset(("puppeteer", "@puppeteer/browsers"))
INSTALL_LIFECYCLE_SCRIPTS = frozenset(("preinstall", "install", "postinstall"))


def canonical_body(relative: str, body: bytes) -> bytes:
    if relative == "build/versions.env":
        body = b"".join(
            line
            for line in body.splitlines(keepends=True)
            if not line.startswith(LOCK_PREFIX)
        )
    name = relative.encode("ascii")
    return (
        struct.pack(">Q", len(name))
        + name
        + struct.pack(">Q", len(body))
        + body
    )


def compute_lock(root: pathlib.Path) -> str:
    digest = hashlib.sha256()
    for relative in OWNED_INPUTS:
        digest.update(canonical_body(relative, (root / relative).read_bytes()))
    return digest.hexdigest()


def lock_lines(body: bytes) -> list[bytes]:
    return [
        line[len(LOCK_PREFIX) :].rstrip(b"\r\n")
        for line in body.splitlines(keepends=True)
        if line.startswith(LOCK_PREFIX)
    ]


def read_versions(root: pathlib.Path) -> dict[str, str]:
    values = {}
    for line in (root / "build" / "versions.env").read_text(encoding="ascii").splitlines():
        if not line or line.startswith("#"):
            continue
        name, separator, value = line.partition("=")
        if not separator or not name or name in values:
            raise ValueError("build/versions.env contains an invalid assignment")
        values[name] = value
    return values


def validate_browser_dependencies(root: pathlib.Path) -> None:
    browser = root / "build" / "browser"
    manifest = json.loads((browser / "package.json").read_text(encoding="utf-8"))
    lock = json.loads((browser / "package-lock.json").read_text(encoding="utf-8"))

    if "dependencies" in manifest or not isinstance(manifest.get("devDependencies"), dict):
        raise ValueError("browser packages must be declared only in devDependencies")
    scripts = manifest.get("scripts", {})
    if not isinstance(scripts, dict):
        raise ValueError("browser manifest scripts must be an object")
    lifecycle_scripts = sorted(INSTALL_LIFECYCLE_SCRIPTS.intersection(scripts))
    if lifecycle_scripts:
        raise ValueError(
            "lifecycle browser acquisition is forbidden: "
            f"{lifecycle_scripts[0]}"
        )
    dependencies = manifest["devDependencies"]
    forbidden = sorted(FORBIDDEN_DIRECT_PACKAGES.intersection(dependencies))
    if forbidden:
        raise ValueError(f"direct browser-download package is forbidden: {forbidden[0]}")
    for name, version in dependencies.items():
        if not isinstance(version, str) or EXACT_NPM_VERSION.fullmatch(version) is None:
            raise ValueError(f"browser dependency {name} must use an exact version")
    versions = read_versions(root)
    expected = {
        "ajv": versions.get("AJV_VERSION"),
        "puppeteer-core": versions.get("PUPPETEER_CORE_VERSION"),
    }
    if dependencies != expected:
        raise ValueError("browser manifest disagrees with build/versions.env")

    if lock.get("lockfileVersion") != 3 or not isinstance(lock.get("packages"), dict):
        raise ValueError("browser package lock must use lockfile version 3")
    packages = lock["packages"]
    root_entry = packages.get("")
    if not isinstance(root_entry, dict) or root_entry.get("devDependencies") != dependencies:
        raise ValueError("browser lock root dependencies disagree with the manifest")
    if "dependencies" in root_entry:
        raise ValueError("browser lock root must contain only devDependencies")

    for name, version in dependencies.items():
        entry = packages.get(f"node_modules/{name}")
        if not isinstance(entry, dict) or entry.get("version") != version:
            raise ValueError(f"browser lock entry for {name} disagrees with the manifest")
    if packages["node_modules/ajv"].get("integrity") != versions.get("AJV_INTEGRITY"):
        raise ValueError("browser lock Ajv integrity disagrees with build/versions.env")
    for path, entry in packages.items():
        if path == "" or not isinstance(entry, dict):
            continue
        resolved = entry.get("resolved")
        if isinstance(resolved, str) and resolved.startswith("https://registry.npmjs.org/"):
            integrity = entry.get("integrity")
            if not isinstance(integrity, str) or not integrity.startswith("sha512-"):
                raise ValueError(f"browser registry package {path} lacks integrity metadata")


def check_lock(root: pathlib.Path) -> bool:
    validate_browser_dependencies(root)
    versions = (root / "build" / "versions.env").read_bytes()
    values = lock_lines(versions)
    if len(values) != 1 or LOCK_PATTERN.fullmatch(values[0]) is None:
        return False
    return hmac.compare_digest(values[0].decode("ascii"), compute_lock(root))


def update_lock(root: pathlib.Path) -> str:
    path = root / "build" / "versions.env"
    body = path.read_bytes()
    values = lock_lines(body)
    if len(values) > 1:
        raise ValueError("build/versions.env contains multiple golden-image locks")

    value = compute_lock(root).encode("ascii")
    replacement = LOCK_PREFIX + value + b"\n"
    lines = body.splitlines(keepends=True)
    if values:
        lines = [replacement if line.startswith(LOCK_PREFIX) else line for line in lines]
        updated = b"".join(lines)
    else:
        separator = b"" if not body or body.endswith(b"\n") else b"\n"
        updated = body + separator + replacement

    mode = path.stat().st_mode
    with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as output:
        temporary = pathlib.Path(output.name)
        output.write(updated)
        output.flush()
        os.fsync(output.fileno())
    try:
        os.chmod(temporary, mode)
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)
    return value.decode("ascii")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("compute", "check", "update"))
    parser.add_argument("--root", type=pathlib.Path, default=pathlib.Path.cwd())
    arguments = parser.parse_args()
    root = arguments.root.resolve()

    try:
        if arguments.command == "compute":
            print(compute_lock(root))
            return 0
        if arguments.command == "check":
            if check_lock(root):
                return 0
            print("golden-image lock is missing, malformed, or stale", file=sys.stderr)
            return 1
        print(update_lock(root))
        return 0
    except (json.JSONDecodeError, OSError, ValueError) as error:
        print(f"golden-image lock: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
