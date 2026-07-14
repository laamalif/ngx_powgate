#!/usr/bin/env python3

import json
import os
import sys
from pathlib import Path


class VectorError(ValueError):
    pass


def require_int(case, name, minimum, maximum):
    value = case.get(name)
    if isinstance(value, bool) or not isinstance(value, int):
        raise VectorError(f"{name} must be an integer")
    if value < minimum or value > maximum:
        raise VectorError(f"{name} is out of range")
    return value


def require_hex(case, name, length):
    value = case.get(name)
    if not isinstance(value, str):
        raise VectorError(f"{name} must be a string")
    try:
        decoded = bytes.fromhex(value)
    except ValueError as error:
        raise VectorError(f"{name} is not hexadecimal") from error
    if len(decoded) != length or decoded.hex() != value:
        raise VectorError(f"{name} must contain {length} canonical bytes")
    return decoded


def require_ascii(case, name, maximum):
    value = case.get(name)
    if not isinstance(value, str) or not value or len(value) > maximum:
        raise VectorError(f"{name} has invalid length")
    try:
        return value.encode("ascii")
    except UnicodeEncodeError as error:
        raise VectorError(f"{name} must be ASCII") from error


def render_array(name, value):
    lines = [f"static const uint8_t  {name}[{len(value)}] = {{"]
    for offset in range(0, len(value), 8):
        chunk = value[offset:offset + 8]
        suffix = "," if offset + 8 < len(value) else ""
        lines.append("    " + ", ".join(f"0x{byte:02x}" for byte in chunk)
                     + suffix)
    lines.append("};")
    return "\n".join(lines)


def render(document):
    if not isinstance(document, dict) or document.get("version") != 1:
        raise VectorError("version must be 1")
    cases = document.get("cases")
    if not isinstance(cases, list) or len(cases) != 1:
        raise VectorError("Phase 1 requires exactly one canonical case")
    case = cases[0]
    if not isinstance(case, dict):
        raise VectorError("first case must be an object")

    secret = require_hex(case, "secret_hex", 32)
    ip16 = require_hex(case, "ip16_hex", 16)
    masked_ip16 = require_hex(case, "masked_ip16_hex", 16)
    nonce = require_hex(case, "nonce_hex", 32)
    proof_digest = require_hex(case, "proof_digest_hex", 32)
    auth_payload = require_hex(case, "auth_payload_hex", 10)
    auth_mac = require_hex(case, "auth_mac_hex", 16)
    counter_ascii = require_ascii(case, "counter_ascii", 16)
    auth_cookie = require_ascii(case, "auth_cookie", 256)
    plen = require_int(case, "plen", 0, 128)
    bucket = require_int(case, "bucket", 0, 2**64 - 1)
    difficulty = require_int(case, "difficulty", 1, 32)
    expiry = require_int(case, "expiry", 0, 2**64 - 1)

    sections = [
        "#ifndef VECTOR_V1_H",
        "#define VECTOR_V1_H",
        "",
        "",
        "#include <stddef.h>",
        "#include <stdint.h>",
        "",
        "",
        render_array("vector_v1_secret", secret),
        "",
        render_array("vector_v1_ip16", ip16),
        "",
        render_array("vector_v1_masked_ip16", masked_ip16),
        "",
        render_array("vector_v1_nonce", nonce),
        "",
        render_array("vector_v1_counter_ascii", counter_ascii),
        ("static const size_t  vector_v1_counter_ascii_len = "
         f"{len(counter_ascii)};"),
        "",
        render_array("vector_v1_proof_digest", proof_digest),
        "",
        render_array("vector_v1_auth_payload", auth_payload),
        "",
        render_array("vector_v1_auth_mac", auth_mac),
        "",
        render_array("vector_v1_auth_cookie", auth_cookie),
        ("static const size_t  vector_v1_auth_cookie_len = "
         f"{len(auth_cookie)};"),
        "",
        f"static const uint8_t  vector_v1_plen = {plen};",
        f"static const uint8_t  vector_v1_difficulty = {difficulty};",
        ("static const uint64_t  vector_v1_bucket = "
         f"UINT64_C({bucket});"),
        ("static const uint64_t  vector_v1_expiry = "
         f"UINT64_C({expiry});"),
        "",
        "",
        "#endif /* VECTOR_V1_H */",
        ""
    ]
    return "\n".join(sections)


def convert(input_path, output_path):
    try:
        document = json.loads(input_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise VectorError(f"cannot read vector: {error}") from error
    content = render(document)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    temporary = output_path.with_name(output_path.name + ".tmp")
    temporary.write_text(content, encoding="utf-8")
    os.replace(temporary, output_path)


def main():
    if len(sys.argv) != 3:
        print("usage: vector-to-c.py INPUT OUTPUT", file=sys.stderr)
        return 2
    try:
        convert(Path(sys.argv[1]), Path(sys.argv[2]))
    except VectorError as error:
        print(error, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
