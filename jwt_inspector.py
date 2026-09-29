#!/usr/bin/env python3
"""
jwt_inspector.py - Decode and inspect a JSON Web Token (JWT).

Decodes the header and payload (without verifying the signature) and flags
common security weaknesses, such as the 'none' algorithm or a missing
expiration claim. Useful for understanding tokens during authorized testing.

This tool does NOT verify signatures and never transmits the token anywhere;
it only parses locally.

Usage:
    python jwt_inspector.py <token>

Example:
    python jwt_inspector.py eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIn0.abc
"""

import argparse
import base64
import json
import sys
from datetime import datetime, timezone


def b64url_decode(segment: str) -> bytes:
    """Decode a base64url segment, adding the padding JWT omits."""
    padding = "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(segment + padding)


def decode_segment(segment: str) -> dict:
    """Decode a JWT segment into a JSON object."""
    return json.loads(b64url_decode(segment))


def inspect(token: str) -> int:
    parts = token.split(".")
    if len(parts) != 3:
        print("[!] Not a valid JWT: expected 3 dot-separated segments "
              f"(got {len(parts)}).", file=sys.stderr)
        return 1

    header_seg, payload_seg, signature_seg = parts

    try:
        header = decode_segment(header_seg)
        payload = decode_segment(payload_seg)
    except (ValueError, json.JSONDecodeError) as exc:
        print(f"[!] Failed to decode token: {exc}", file=sys.stderr)
        return 1

    print("=== Header ===")
    print(json.dumps(header, indent=2))
    print("\n=== Payload ===")
    print(json.dumps(payload, indent=2))
    print(f"\n=== Signature ===\n{signature_seg or '(empty)'}")

    # --- Weakness checks ---
    warnings: list[str] = []

    alg = str(header.get("alg", "")).lower()
    if alg == "none":
        warnings.append("Algorithm is 'none' - the token is unsigned and trivially forgeable.")
    if not signature_seg:
        warnings.append("Signature segment is empty - token integrity is not protected.")

    if "exp" not in payload:
        warnings.append("No 'exp' (expiration) claim - token may never expire.")
    else:
        try:
            exp = datetime.fromtimestamp(int(payload["exp"]), tz=timezone.utc)
            if exp < datetime.now(tz=timezone.utc):
                warnings.append(f"Token expired at {exp.isoformat()}.")
            else:
                print(f"\n[i] Expires at {exp.isoformat()}")
        except (ValueError, OSError):
            warnings.append("'exp' claim is present but not a valid timestamp.")

    print("\n=== Security notes ===")
    if warnings:
        for w in warnings:
            print(f"[!] {w}")
    else:
        print("[+] No obvious weaknesses detected in header/claims "
              "(signature not verified).")

    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Decode and inspect a JWT.")
    parser.add_argument("token", help="The JWT string to inspect")
    args = parser.parse_args()
    return inspect(args.token.strip())


if __name__ == "__main__":
    raise SystemExit(main())
