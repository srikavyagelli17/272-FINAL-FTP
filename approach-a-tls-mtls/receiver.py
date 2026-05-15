"""TLS server that accepts a streamed file, verifies integrity, and writes it safely."""

from __future__ import annotations

import argparse
import os
import socket
import ssl
import struct
import sys
import time
from pathlib import Path

# Repo root (parent of approach-a-tls-mtls/) so `shared` is importable when run from this dir.
_REPO_ROOT = Path(__file__).resolve().parents[1]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from shared.hash_utils import hash_file  # noqa: E402

HEADER_STRUCT = struct.Struct("!QQ")  # total file size, chunk size (both uint64 BE)
DIGEST_ASCII_LEN = 64  # SHA-256 hex
SOCKET_RECV_CAP = 1 << 20  # cap per recv to avoid huge buffers from bogus header chunk size


def _ssl_server_context(*, cert: str, key: str, ca: str) -> ssl.SSLContext:
    if hasattr(ssl, "TLSProtocol"):
        ctx = ssl.SSLContext(ssl.TLSProtocol.TLS_SERVER)
    else:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.options |= ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.load_verify_locations(cafile=ca)
    ctx.load_cert_chain(certfile=cert, keyfile=key)
    return ctx


def _recv_exact(sock: ssl.SSLSocket, n: int) -> bytes:
    """Read exactly *n* bytes or raise EOFError if the peer closes early."""
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


def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="mTLS file receiver (Approach A).")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=9000)
    p.add_argument("--output", required=True, help="Final output path (writes to <output>.tmp first).")
    p.add_argument("--cert", required=True, help="Server certificate PEM path.")
    p.add_argument("--key", required=True, help="Server private key PEM path.")
    p.add_argument("--ca", required=True, help="CA bundle to verify the client certificate.")
    return p.parse_args()


def main() -> int:
    args = _parse_args()
    out_path = args.output
    temp_path = f"{out_path}.tmp"

    _delete_if_exists(temp_path)

    ctx = _ssl_server_context(cert=args.cert, key=args.key, ca=args.ca)

    listen_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        listen_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listen_sock.bind((args.host, args.port))
        listen_sock.listen(1)
        conn, _addr = listen_sock.accept()
    finally:
        listen_sock.close()

    try:
        ssl_sock = ctx.wrap_socket(conn, server_side=True)
    except ssl.SSLError as exc:
        conn.close()
        print(f"TLS handshake failed: {exc}", file=sys.stderr)
        return 1

    try:
        return _receive_transfer(ssl_sock, temp_path, out_path)
    finally:
        ssl_sock.close()


def _receive_transfer(ssl_sock: ssl.SSLSocket, temp_path: str, out_path: str) -> int:
    last_progress = time.monotonic()
    xfer_start: float | None = None
    recv_t0 = time.monotonic()

    def fail_incomplete() -> int:
        _delete_if_exists(temp_path)
        print("INCOMPLETE TRANSFER — partial file deleted", file=sys.stderr)
        return 1

    try:
        header = _recv_exact(ssl_sock, HEADER_STRUCT.size)
        total_size, chunk_size = HEADER_STRUCT.unpack(header)
        if total_size < 0 or chunk_size < 0:
            return fail_incomplete()

        received = 0
        with open(temp_path, "wb") as out_f:
            while received < total_size:
                remaining = total_size - received
                hint = chunk_size if chunk_size > 0 else SOCKET_RECV_CAP
                to_read = min(SOCKET_RECV_CAP, remaining, hint)
                block = ssl_sock.recv(to_read)
                if not block:
                    return fail_incomplete()
                if xfer_start is None:
                    xfer_start = time.monotonic()
                out_f.write(block)
                received += len(block)

                now = time.monotonic()
                if now - last_progress >= 5.0 and total_size > 0:
                    pct = 100.0 * received / total_size
                    print(
                        f"Progress: {pct:.2f}% ({received}/{total_size} bytes)",
                        file=sys.stderr,
                    )
                    last_progress = now

        if xfer_start is None and total_size == 0:
            xfer_start = time.monotonic()

        try:
            digest_bytes = _recv_exact(ssl_sock, DIGEST_ASCII_LEN)
            digest_ascii = digest_bytes.decode("ascii")
        except (EOFError, UnicodeDecodeError):
            return fail_incomplete()

        if len(digest_ascii) != DIGEST_ASCII_LEN or any(c not in "0123456789abcdefABCDEF" for c in digest_ascii):
            return fail_incomplete()

        computed = hash_file(temp_path)
        if computed != digest_ascii.lower():
            _delete_if_exists(temp_path)
            print("INTEGRITY FAILURE — partial file deleted", file=sys.stderr)
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

    except (EOFError, ssl.SSLError, OSError, ValueError):
        return fail_incomplete()


if __name__ == "__main__":
    raise SystemExit(main())
