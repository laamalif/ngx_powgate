#!/usr/bin/env python3

import argparse
import base64
import hashlib
import hmac
import ipaddress
import json
import sys
from pathlib import Path


CHALLENGE_LABEL = b"PGv1-chal"
COOKIE_LABEL = b"PGv1-cook"
SECRET_LEN = 32
IP_LEN = 16
NONCE_LEN = 32
PAYLOAD_LEN = 10
MAC_LEN = 16
COUNTER_MAX = 2**53 - 1


class VectorError(ValueError):
    pass


def require_int(value, name, minimum, maximum):
    if isinstance(value, bool) or not isinstance(value, int):
        raise VectorError(f"{name} must be an integer")
    if value < minimum or value > maximum:
        raise VectorError(f"{name} is out of range")
    return value


def decode_hex(value, name, length):
    if not isinstance(value, str):
        raise VectorError(f"{name} must be a string")
    try:
        decoded = bytes.fromhex(value)
    except ValueError as error:
        raise VectorError(f"{name} is not hexadecimal") from error
    if len(decoded) != length or value != decoded.hex():
        raise VectorError(f"{name} must be {length} canonical bytes")
    return decoded


def decode_cli_hex(value, name, length):
    if not isinstance(value, str):
        raise VectorError(f"{name} must be a string")
    if len(value) != length * 2 or any(
        character not in "0123456789abcdefABCDEF" for character in value
    ):
        raise VectorError(f"{name} must be exactly {length} hexadecimal bytes")
    return bytes.fromhex(value)


def b64url(value):
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def canonical_ip(text):
    if not isinstance(text, str):
        raise VectorError("ip must be a string")
    try:
        address = ipaddress.ip_address(text)
    except ValueError as error:
        raise VectorError("ip is invalid") from error
    if address.version == 4:
        return bytes(10) + b"\xff\xff" + address.packed
    return address.packed


def mask_ip(ip16, plen):
    require_int(plen, "plen", 0, 128)
    if len(ip16) != IP_LEN:
        raise VectorError("ip16 must be 16 bytes")
    value = int.from_bytes(ip16, "big")
    if plen == 0:
        value = 0
    elif plen < 128:
        value &= ((1 << plen) - 1) << (128 - plen)
    return value.to_bytes(IP_LEN, "big")


def derive_nonce(secret, ip16, plen, bucket):
    require_int(plen, "plen", 0, 128)
    require_int(bucket, "bucket", 0, 2**64 - 1)
    if len(secret) != SECRET_LEN:
        raise VectorError("secret must be 32 bytes")
    message = CHALLENGE_LABEL + ip16 + bytes([plen])
    message += bucket.to_bytes(8, "big")
    return hmac.new(secret, message, hashlib.sha256).digest()


def proof_digest(nonce, counter_ascii):
    if len(nonce) != NONCE_LEN:
        raise VectorError("nonce must be 32 bytes")
    return hashlib.sha256(nonce + counter_ascii).digest()


def proof_valid(digest, difficulty):
    require_int(difficulty, "difficulty", 1, 32)
    return int.from_bytes(digest, "big") < 1 << (256 - difficulty)


def mine_counter(nonce, difficulty, start_counter=0):
    require_int(difficulty, "difficulty", 1, 32)
    require_int(start_counter, "start_counter", 0, COUNTER_MAX)
    for counter in range(start_counter, COUNTER_MAX + 1):
        counter_ascii = str(counter).encode("ascii")
        digest = proof_digest(nonce, counter_ascii)
        if proof_valid(digest, difficulty):
            return counter, counter_ascii, digest
    raise VectorError("counter space exhausted")


def auth_values(secret, ip16, expiry, difficulty, plen):
    require_int(expiry, "expiry", 0, 2**64 - 1)
    require_int(difficulty, "difficulty", 1, 32)
    require_int(plen, "plen", 32, 128)
    payload = expiry.to_bytes(8, "big") + bytes([difficulty, plen])
    digest = hmac.new(
        secret, COOKIE_LABEL + payload + ip16, hashlib.sha256
    ).digest()
    mac = digest[:MAC_LEN]
    cookie = f"1.{b64url(payload)}.{b64url(mac)}"
    return payload, mac, cookie


def compare(case_name, field, actual, expected):
    if actual != expected:
        raise VectorError(f"{case_name}: {field} mismatch")


def verify_case(case):
    if not isinstance(case, dict):
        raise VectorError("case must be an object")
    name = case.get("name")
    if not isinstance(name, str) or not name:
        raise VectorError("case name must be a non-empty string")

    secret = decode_hex(case.get("secret_hex"), "secret_hex", SECRET_LEN)
    plen = require_int(case.get("plen"), "plen", 32, 128)
    bucket = require_int(case.get("bucket"), "bucket", 0, 2**64 - 1)
    difficulty = require_int(case.get("difficulty"), "difficulty", 1, 32)
    expiry = require_int(case.get("expiry"), "expiry", 0, 2**64 - 1)
    counter = require_int(case.get("counter"), "counter", 0, COUNTER_MAX)

    raw_ip16 = canonical_ip(case.get("ip"))
    compare(name, "ip16_hex", raw_ip16.hex(), case.get("ip16_hex"))
    ip16 = mask_ip(raw_ip16, plen)
    compare(name, "masked_ip16_hex", ip16.hex(), case.get("masked_ip16_hex"))

    nonce = derive_nonce(secret, ip16, plen, bucket)
    compare(name, "nonce_hex", nonce.hex(), case.get("nonce_hex"))
    compare(name, "nonce_b64url", b64url(nonce), case.get("nonce_b64url"))

    counter_ascii = str(counter).encode("ascii")
    compare(name, "counter_ascii", counter_ascii.decode("ascii"),
            case.get("counter_ascii"))
    digest = proof_digest(nonce, counter_ascii)
    compare(name, "proof_digest_hex", digest.hex(),
            case.get("proof_digest_hex"))
    if not proof_valid(digest, difficulty):
        raise VectorError(f"{name}: proof does not meet difficulty")

    payload, mac, cookie = auth_values(
        secret, ip16, expiry, difficulty, plen
    )
    compare(name, "auth_payload_hex", payload.hex(),
            case.get("auth_payload_hex"))
    compare(name, "auth_mac_hex", mac.hex(), case.get("auth_mac_hex"))
    compare(name, "auth_cookie", cookie, case.get("auth_cookie"))


def verify_vector(path):
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise VectorError(f"{path}: cannot read vector: {error}") from error
    if not isinstance(document, dict) or document.get("version") != 1:
        raise VectorError(f"{path}: version must be 1")
    cases = document.get("cases")
    if not isinstance(cases, list) or not cases:
        raise VectorError(f"{path}: cases must be a non-empty array")
    for case in cases:
        verify_case(case)
    print(f"{path}: {len(cases)} case verified"
          if len(cases) == 1 else f"{path}: {len(cases)} cases verified")


def mine_command(args):
    secret = decode_cli_hex(args.secret_hex, "secret_hex", SECRET_LEN)
    plen = require_int(args.plen, "plen", 0, 128)
    bucket = require_int(args.bucket, "bucket", 0, 2**64 - 1)
    difficulty = require_int(args.difficulty, "difficulty", 1, 32)
    start_counter = require_int(
        args.start_counter, "start_counter", 0, COUNTER_MAX
    )
    ip16 = mask_ip(canonical_ip(args.ip), plen)
    nonce = derive_nonce(secret, ip16, plen, bucket)
    counter, counter_ascii, digest = mine_counter(
        nonce, difficulty, start_counter
    )
    print(json.dumps({
        "masked_ip16_hex": ip16.hex(),
        "nonce_hex": nonce.hex(),
        "nonce_b64url": b64url(nonce),
        "counter": counter,
        "counter_ascii": counter_ascii.decode("ascii"),
        "proof_cookie": f"1.{bucket}.{counter}",
        "proof_digest_hex": digest.hex()
    }, indent=2, sort_keys=True))


def proof_check_command(args):
    secret = decode_cli_hex(args.secret_hex, "secret_hex", SECRET_LEN)
    plen = require_int(args.plen, "plen", 0, 128)
    bucket = require_int(args.bucket, "bucket", 0, 2**64 - 1)
    difficulty = require_int(args.difficulty, "difficulty", 1, 32)
    counter = require_int(args.counter, "counter", 0, COUNTER_MAX)
    ip16 = mask_ip(canonical_ip(args.ip), plen)
    nonce = derive_nonce(secret, ip16, plen, bucket)
    counter_ascii = str(counter).encode("ascii")
    digest = proof_digest(nonce, counter_ascii)
    print(json.dumps({
        "counter": counter,
        "counter_ascii": counter_ascii.decode("ascii"),
        "proof_digest_hex": digest.hex(),
        "valid": proof_valid(digest, difficulty)
    }, indent=2, sort_keys=True))


def auth_command(args):
    secret = decode_cli_hex(args.secret_hex, "secret_hex", SECRET_LEN)
    plen = require_int(args.plen, "plen", 32, 128)
    expiry = require_int(args.expiry, "expiry", 0, 2**64 - 1)
    difficulty = require_int(args.difficulty, "difficulty", 1, 32)
    ip16 = mask_ip(canonical_ip(args.ip), plen)
    payload, mac, cookie = auth_values(
        secret, ip16, expiry, difficulty, plen
    )
    print(json.dumps({
        "auth_cookie": cookie,
        "auth_mac_hex": mac.hex(),
        "auth_payload_hex": payload.hex(),
        "masked_ip16_hex": ip16.hex()
    }, indent=2, sort_keys=True))


def add_proof_context(parser):
    parser.add_argument("--secret-hex", required=True)
    parser.add_argument("--ip", required=True)
    parser.add_argument("--plen", required=True, type=int)
    parser.add_argument("--bucket", required=True, type=int)
    parser.add_argument("--difficulty", required=True, type=int)


def parse_args():
    parser = argparse.ArgumentParser(description="ngx_powgate v1 reference")
    subparsers = parser.add_subparsers(dest="command", required=True)

    verify = subparsers.add_parser("verify")
    verify.add_argument("path", type=Path)

    mine = subparsers.add_parser("mine")
    add_proof_context(mine)
    mine.add_argument("--start-counter", type=int, default=0)

    proof_check = subparsers.add_parser("proof-check")
    add_proof_context(proof_check)
    proof_check.add_argument("--counter", required=True, type=int)

    auth = subparsers.add_parser("auth")
    auth.add_argument("--secret-hex", required=True)
    auth.add_argument("--ip", required=True)
    auth.add_argument("--expiry", required=True, type=int)
    auth.add_argument("--difficulty", required=True, type=int)
    auth.add_argument("--plen", required=True, type=int)

    return parser.parse_args()


def main():
    args = parse_args()
    if args.command == "verify":
        verify_vector(args.path)
    elif args.command == "mine":
        mine_command(args)
    elif args.command == "proof-check":
        proof_check_command(args)
    else:
        auth_command(args)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except VectorError as error:
        print(error, file=sys.stderr)
        raise SystemExit(1) from error
