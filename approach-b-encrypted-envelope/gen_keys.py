#!/usr/bin/env python3
"""Generate a static X25519 keypair for the receiver (Approach B).

Design (Approach B wire protocol, implemented in later tasks):
The sender loads the receiver's X25519 public key and generates an ephemeral X25519
keypair per transfer. It performs ECDHE, derives a per-transfer symmetric key with
HKDF-SHA256, and encrypts each file chunk with ChaCha20-Poly1305; each chunk uses a
unique nonce derived from a running counter so (key, nonce) pairs are never reused.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

# Chunk size for Approach B transfers (used by sender/receiver in later tasks).
CHUNK_SIZE = 4 << 20

_SCRIPT_DIR = Path(__file__).resolve().parent
_KEYS_DIR = _SCRIPT_DIR / "keys"
_PRIVATE_PATH = _KEYS_DIR / "receiver_private.key"
_PUBLIC_PATH = _KEYS_DIR / "receiver_public.key"


def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Generate X25519 receiver keys for Approach B.")
    p.add_argument(
        "--force",
        action="store_true",
        help="Overwrite existing key files in keys/. Without this flag, existing files raise an error.",
    )
    return p.parse_args()


def main() -> int:
    args = _parse_args()

    if _PRIVATE_PATH.exists() or _PUBLIC_PATH.exists():
        if not args.force:
            print(
                "Key files already exist. Re-run with --force to overwrite them.",
                file=sys.stderr,
            )
            return 1

    _KEYS_DIR.mkdir(parents=True, exist_ok=True)

    private_key = X25519PrivateKey.generate()
    public_key = private_key.public_key()

    priv_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    _PRIVATE_PATH.write_bytes(priv_pem)
    _PUBLIC_PATH.write_bytes(pub_pem)

    print(
        "KEEP receiver_private.key SECRET. Only receiver_public.key needs to be shared with the sender."
    )
    print(f"Wrote {_PRIVATE_PATH}")
    print(f"Wrote {_PUBLIC_PATH}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
