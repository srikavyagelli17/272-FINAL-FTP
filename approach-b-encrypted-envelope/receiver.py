"""Receives an encrypted envelope over TCP, decrypts, and verifies integrity."""

from __future__ import annotations

import argparse
import os
import socket
import struct
import sys
import time
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

_REPO_ROOT = Path(__file__).resolve().parents[1]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from shared.hash_utils import hash_file  # noqa: E402

HKDF_INFO = b"chunk-encryption"
SESSION_NONCE_LEN = 32
EPHEMERAL_PUB_RAW_LEN = 32
PREAMBLE_LEN = SESSION_NONCE_LEN + EPHEMERAL_PUB_RAW_LEN + 8 + 8
DIGEST_ASCII_LEN = 64
SOCKET_RECV_CAP = 1 << 20
# Reject absurd chunk sizes from a malicious sender (must match sender's intended upper bound).
MAX_PLAINTEXT_CHUNK = 64 << 20


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    chunks: list[bytes] = []
    remaining = n
    while remaining:
        block = sock.recv(min(SOCKET_RECV_CAP, remaining))
        if not block:
            raise EOFError("connection closed before expected bytes arrived")
        chunks.append(block)
        remaining -= len(block)
    return b"".join(chunks)


def _delete_if_exists(path: str) -> None:
    try:
        os.unlink(path)
    except FileNotFoundError:
        pass


def _load_receiver_private(path: str) -> x25519.X25519PrivateKey:
    data = Path(path).read_bytes()
    key = serialization.load_pem_private_key(data, password=None)
    if not isinstance(key, x25519.X25519PrivateKey):
        raise ValueError("private key must be an X25519 key in PEM format")
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
    p = argparse.ArgumentParser(description="Approach B: encrypted file receiver (plain TCP).")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=9001)
    p.add_argument("--output", required=True, help="Final output path (writes to <output>.tmp first).")
    p.add_argument("--privkey", required=True, help="Receiver X25519 private key (PEM).")
    return p.parse_args()


def main() -> int:
    args = _parse_args()
    out_path = args.output
    temp_path = f"{out_path}.tmp"

    _delete_if_exists(temp_path)

    try:
        priv = _load_receiver_private(args.privkey)
    except (OSError, ValueError) as exc:
        print(f"Cannot load private key: {exc}", file=sys.stderr)
        return 1

    listen_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        listen_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listen_sock.bind((args.host, args.port))
        listen_sock.listen(1)
        conn, _addr = listen_sock.accept()
    except OSError as exc:
        print(f"Listen/accept failed: {exc}", file=sys.stderr)
        return 1
    finally:
        listen_sock.close()

    try:
        return _receive_envelope(conn, temp_path, out_path, priv)
    finally:
        try:
            conn.close()
        except OSError:
            pass


def _receive_envelope(
    conn: socket.socket,
    temp_path: str,
    out_path: str,
    priv: x25519.X25519PrivateKey,
) -> int:
    def abort(msg: str) -> int:
        _delete_if_exists(temp_path)
        print(msg, file=sys.stderr)
        return 1

    xfer_start: float | None = None
    recv_t0 = time.monotonic()

    try:
        preamble = _recv_exact(conn, PREAMBLE_LEN)
        session_nonce = preamble[:SESSION_NONCE_LEN]
        eph_raw = preamble[SESSION_NONCE_LEN : SESSION_NONCE_LEN + EPHEMERAL_PUB_RAW_LEN]
        total_size, _wire_chunk_size = struct.unpack(
            "!QQ",
            preamble[SESSION_NONCE_LEN + EPHEMERAL_PUB_RAW_LEN :],
        )
        if total_size < 0 or _wire_chunk_size < 0:
            return abort("Transfer failed: invalid size header.")

        eph_pub = x25519.X25519PublicKey.from_public_bytes(eph_raw)
        shared = priv.exchange(eph_pub)
        chunk_key = _derive_chunk_key(shared, session_nonce)
        aead = ChaCha20Poly1305(chunk_key)

        received = 0
        expected_index = 0

        with open(temp_path, "wb") as out_f:
            while received < total_size:
                hdr = _recv_exact(conn, 8)
                chunk_index, chunk_len = struct.unpack("!II", hdr)
                if chunk_len > MAX_PLAINTEXT_CHUNK:
                    return abort("Transfer failed: chunk length too large.")
                remaining_plain = total_size - received
                if chunk_len > remaining_plain:
                    return abort("Transfer failed: chunk length exceeds remaining file size.")
                if chunk_index != expected_index:
                    return abort("Transfer failed: chunk out of order (possible replay).")
                nonce = _recv_exact(conn, 12)
                ct_len = chunk_len + 16
                ciphertext = _recv_exact(conn, ct_len)
                if xfer_start is None:
                    xfer_start = time.monotonic()
                try:
                    plaintext = aead.decrypt(nonce, ciphertext, None)
                except InvalidTag:
                    return abort("Transfer failed: chunk authentication failed (AEAD tag mismatch).")
                if len(plaintext) != chunk_len:
                    return abort("Transfer failed: unexpected plaintext length after decrypt.")
                out_f.write(plaintext)
                received += len(plaintext)
                expected_index += 1

                if expected_index % 100 == 0:
                    print(
                        f"Decrypted {expected_index} chunks ({received}/{total_size} bytes).",
                        file=sys.stderr,
                    )

        if xfer_start is None and total_size == 0:
            xfer_start = time.monotonic()

        digest_raw = _recv_exact(conn, DIGEST_ASCII_LEN)
        try:
            digest_ascii = digest_raw.decode("ascii")
        except UnicodeDecodeError:
            return abort("Transfer failed: invalid digest encoding.")

        if len(digest_ascii) != DIGEST_ASCII_LEN or any(
            c not in "0123456789abcdefABCDEF" for c in digest_ascii
        ):
            return abort("Transfer failed: invalid digest format.")

        computed = hash_file(temp_path)
        if computed != digest_ascii.lower():
            _delete_if_exists(temp_path)
            print("Transfer failed: end-to-end digest mismatch.", file=sys.stderr)
            return 1

        os.rename(temp_path, out_path)

        recv_end = time.monotonic()
        elapsed = recv_end - (xfer_start or recv_end)
        print(f"SHA-256: {computed}")
        print(f"Transfer time: {elapsed:.3f} seconds")
        wall = max(recv_end - recv_t0, 1e-9)
        if total_size > 0:
            recv_mib = total_size / wall / (1024 * 1024)
            print(f"Receive throughput: {recv_mib:.2f} MB/s")
        else:
            print("Receive throughput: 0.00 MB/s")
        return 0

    except EOFError:
        return abort("Transfer failed: connection closed before transfer completed.")
    except OSError as exc:
        return abort(f"Transfer failed: I/O error ({exc}).")


if __name__ == "__main__":
    raise SystemExit(main())
