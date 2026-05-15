#!/usr/bin/env python3
"""Quick smoke test: Approach B sender + minimal decrypting listener (not full receiver.py)."""

from __future__ import annotations

import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from shared.hash_utils import hash_file  # noqa: E402

HKDF_INFO = b"chunk-encryption"
SESSION_NONCE_LEN = 32
EPHEMERAL_PUB_RAW_LEN = 32
PREAMBLE_LEN = SESSION_NONCE_LEN + EPHEMERAL_PUB_RAW_LEN + 8 + 8


def _recv_exact(conn: socket.socket, n: int) -> bytes:
    out = bytearray()
    while len(out) < n:
        b = conn.recv(n - len(out))
        if not b:
            raise EOFError("short read")
        out += b
    return bytes(out)


def _free_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    _, p = s.getsockname()
    s.close()
    return int(p)


def _mini_receiver(
    port: int,
    priv_path: Path,
    out_path: Path,
    expected_plaintext: bytes,
    done: threading.Event,
    errors: list[str],
) -> None:
    try:
        priv_pem = priv_path.read_bytes()
        priv_key = serialization.load_pem_private_key(priv_pem, password=None)
        if not isinstance(priv_key, x25519.X25519PrivateKey):
            raise ValueError("private key must be X25519 PEM")

        listen = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listen.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listen.bind(("127.0.0.1", port))
        listen.listen(1)
        conn, _ = listen.accept()
        listen.close()
        with conn:
            preamble = _recv_exact(conn, PREAMBLE_LEN)
            session_nonce = preamble[:SESSION_NONCE_LEN]
            eph_raw = preamble[SESSION_NONCE_LEN : SESSION_NONCE_LEN + EPHEMERAL_PUB_RAW_LEN]
            total_size, _chunk_size = struct.unpack(
                "!QQ",
                preamble[SESSION_NONCE_LEN + EPHEMERAL_PUB_RAW_LEN :],
            )
            if total_size != len(expected_plaintext):
                raise ValueError(
                    f"size mismatch: wire={total_size} expected={len(expected_plaintext)}"
                )

            eph_pub = x25519.X25519PublicKey.from_public_bytes(eph_raw)
            shared = priv_key.exchange(eph_pub)
            hkdf = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=session_nonce,
                info=HKDF_INFO,
            )
            chunk_key = hkdf.derive(shared)
            aead = ChaCha20Poly1305(chunk_key)

            buf = bytearray()
            expected_index = 0
            while len(buf) < total_size:
                hdr = _recv_exact(conn, 8)
                chunk_index, chunk_len = struct.unpack("!II", hdr)
                if chunk_index != expected_index:
                    raise ValueError(f"chunk order: got {chunk_index} want {expected_index}")
                nonce = _recv_exact(conn, 12)
                ct = _recv_exact(conn, chunk_len + 16)
                buf += aead.decrypt(nonce, ct, None)
                expected_index += 1

            digest_ascii = _recv_exact(conn, 64).decode("ascii")
            if bytes(buf) != expected_plaintext:
                raise ValueError("plaintext mismatch after decrypt")

            out_path.write_bytes(buf)
            if hash_file(str(out_path)) != digest_ascii.lower():
                raise ValueError("digest mismatch")

        done.set()
    except Exception as exc:  # noqa: BLE001 — smoke harness
        errors.append(str(exc))


def main() -> int:
    priv = SCRIPT_DIR / "keys" / "receiver_private.key"
    pub = SCRIPT_DIR / "keys" / "receiver_public.key"
    if not priv.is_file() or not pub.is_file():
        print("Missing keys. Run: python gen_keys.py", file=sys.stderr)
        return 1

    payload = b"smoke-test approach-b " + bytes(range(200))
    port = _free_port()
    done = threading.Event()
    errors: list[str] = []

    with tempfile.TemporaryDirectory() as td:
        tdir = Path(td)
        plain = tdir / "plain.bin"
        out = tdir / "out.bin"
        plain.write_bytes(payload)

        th = threading.Thread(
            target=_mini_receiver,
            args=(port, priv, out, payload, done, errors),
            daemon=True,
        )
        th.start()
        time.sleep(0.25)

        cmd = [
            sys.executable,
            str(SCRIPT_DIR / "sender.py"),
            "--host",
            "127.0.0.1",
            "--port",
            str(port),
            "--file",
            str(plain),
            "--receiver-pubkey",
            str(pub),
            "--chunk-size",
            str(min(4096, len(payload))),
        ]
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        th.join(timeout=60)

        if r.returncode != 0:
            print("sender failed:", r.stderr or r.stdout, file=sys.stderr)
            return 1
        if errors:
            print("receiver thread:", errors, file=sys.stderr)
            return 1
        if not done.is_set():
            print("receiver did not complete", file=sys.stderr)
            return 1
        if out.read_bytes() != payload:
            print("output mismatch", file=sys.stderr)
            return 1

    print("Approach B smoke test: OK (sender + minimal decrypt path)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
