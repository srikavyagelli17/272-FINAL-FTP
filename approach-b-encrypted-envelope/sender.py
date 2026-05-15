"""Encrypts and sends a file over plain TCP using an application-layer envelope."""

from __future__ import annotations

import argparse
import os
import socket
import struct
import sys
import time
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

_REPO_ROOT = Path(__file__).resolve().parents[1]
_SCRIPT_DIR = Path(__file__).resolve().parent
if str(_SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(_SCRIPT_DIR))
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from gen_keys import CHUNK_SIZE as DEFAULT_CHUNK_SIZE  # noqa: E402
from shared.hash_utils import hash_file  # noqa: E402

HKDF_INFO = b"chunk-encryption"
SESSION_NONCE_LEN = 32
EPHEMERAL_PUB_RAW_LEN = 32
NONCE_LEN = 12


def _send_all(sock: socket.socket, data: bytes) -> None:
    view = memoryview(data)
    while len(view):
        n = sock.send(view)
        view = view[n:]


def _load_receiver_public(path: str) -> x25519.X25519PublicKey:
    data = Path(path).read_bytes()
    key = serialization.load_pem_public_key(data)
    if not isinstance(key, x25519.X25519PublicKey):
        raise ValueError("receiver public key must be an X25519 key in PEM format")
    return key


def _derive_chunk_key(shared_secret: bytes, session_nonce: bytes) -> bytes:
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=session_nonce,
        info=HKDF_INFO,
    )
    return hkdf.derive(shared_secret)


def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Approach B: encrypted file sender (plain TCP).")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=9001)
    p.add_argument("--file", required=True, help="Path to the plaintext file to send.")
    p.add_argument(
        "--receiver-pubkey",
        default="keys/receiver_public.key",
        help="Receiver X25519 public key (PEM).",
    )
    p.add_argument(
        "--chunk-size",
        type=int,
        default=DEFAULT_CHUNK_SIZE,
        help=f"Plaintext chunk size in bytes (default: {DEFAULT_CHUNK_SIZE}).",
    )
    return p.parse_args()


def main() -> int:
    args = _parse_args()
    chunk_size = args.chunk_size
    if chunk_size <= 0:
        print("--chunk-size must be positive.", file=sys.stderr)
        return 1

    filepath = args.file
    try:
        total_size = os.path.getsize(filepath)
    except OSError as exc:
        print(f"Cannot read input file: {exc}", file=sys.stderr)
        return 1

    try:
        receiver_pub = _load_receiver_public(args.receiver_pubkey)
    except (OSError, ValueError) as exc:
        print(f"Cannot load receiver public key: {exc}", file=sys.stderr)
        return 1

    ephemeral_private = x25519.X25519PrivateKey.generate()
    ephemeral_public = ephemeral_private.public_key()
    shared_secret = ephemeral_private.exchange(receiver_pub)

    session_nonce = os.urandom(SESSION_NONCE_LEN)
    chunk_key = _derive_chunk_key(shared_secret, session_nonce)
    aead = ChaCha20Poly1305(chunk_key)

    eph_pub_raw = ephemeral_public.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    if len(eph_pub_raw) != EPHEMERAL_PUB_RAW_LEN:
        print("Internal error: unexpected ephemeral public key length.", file=sys.stderr)
        return 1

    preamble = (
        session_nonce
        + eph_pub_raw
        + struct.pack("!QQ", total_size, chunk_size)
    )

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    xfer_start: float | None = None
    try:
        sock.connect((args.host, args.port))
        _send_all(sock, preamble)

        chunk_index = 0
        sent = 0
        with open(filepath, "rb") as in_f:
            while sent < total_size:
                n = min(chunk_size, total_size - sent)
                plaintext = in_f.read(n)
                if len(plaintext) != n:
                    print("Unexpected end of file while reading.", file=sys.stderr)
                    return 1
                nonce = chunk_index.to_bytes(4, "big") + session_nonce[:8]
                if len(nonce) != NONCE_LEN:
                    return 1
                ciphertext = aead.encrypt(nonce, plaintext, None)
                frame = struct.pack("!II", chunk_index, n) + nonce + ciphertext
                if xfer_start is None:
                    xfer_start = time.monotonic()
                _send_all(sock, frame)
                sent += n
                chunk_index += 1

        digest_ascii = hash_file(filepath).encode("ascii")
        if len(digest_ascii) != 64:
            print("Internal error: unexpected digest length.", file=sys.stderr)
            return 1
        _send_all(sock, digest_ascii)
        xfer_end = time.monotonic()
        if xfer_start is None:
            xfer_start = xfer_end
        elapsed = max(xfer_end - xfer_start, 1e-9)
        if total_size == 0:
            print("Throughput: 0.00 MB/s")
        else:
            mib = total_size / elapsed / (1024 * 1024)
            print(f"Throughput: {mib:.2f} MB/s")
        return 0
    except OSError as exc:
        print(f"Network error: {exc}", file=sys.stderr)
        return 1
    finally:
        try:
            sock.close()
        except OSError:
            pass


if __name__ == "__main__":
    raise SystemExit(main())
