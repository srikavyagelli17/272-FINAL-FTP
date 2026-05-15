"""TLS client that streams a file to the receiver with mutual TLS."""

from __future__ import annotations

import argparse
import os
import socket
import ssl
import struct
import sys
import time
from pathlib import Path

DEFAULT_CHUNK_SIZE = 1 << 20  # 1 MiB

_REPO_ROOT = Path(__file__).resolve().parents[1]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from shared.hash_utils import hash_file  # noqa: E402

HEADER_STRUCT = struct.Struct("!QQ")


def _ssl_client_context(*, ca: str, cert: str, key: str) -> ssl.SSLContext:
    if hasattr(ssl, "TLSProtocol"):
        ctx = ssl.SSLContext(ssl.TLSProtocol.TLS_CLIENT)
    else:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.options |= ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.check_hostname = True
    ctx.load_verify_locations(cafile=ca)
    ctx.load_cert_chain(certfile=cert, keyfile=key)
    return ctx


def _send_all(sock: ssl.SSLSocket, data: bytes) -> None:
    view = memoryview(data)
    while len(view):
        n = sock.send(view)
        view = view[n:]


def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="mTLS file sender (Approach A).")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=9000)
    p.add_argument("--file", required=True, help="Path to the file to send.")
    p.add_argument("--cert", required=True, help="Client certificate PEM path.")
    p.add_argument("--key", required=True, help="Client private key PEM path.")
    p.add_argument("--ca", required=True, help="CA bundle to verify the server certificate.")
    p.add_argument(
        "--chunk-size",
        type=int,
        default=DEFAULT_CHUNK_SIZE,
        help=f"Read/send chunk size in bytes (default: {DEFAULT_CHUNK_SIZE}).",
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

    ctx = _ssl_client_context(ca=args.ca, cert=args.cert, key=args.key)

    raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        raw_sock.connect((args.host, args.port))
        ssl_sock = ctx.wrap_socket(raw_sock, server_hostname=args.host)
    except OSError as exc:
        print(f"Connection failed: {exc}", file=sys.stderr)
        try:
            raw_sock.close()
        except OSError:
            pass
        return 1
    except ssl.SSLError as exc:
        print(f"TLS handshake failed: {exc}", file=sys.stderr)
        try:
            raw_sock.close()
        except OSError:
            pass
        return 1

    last_progress = time.monotonic()
    xfer_start: float | None = None
    sent_body = 0

    try:
        header = HEADER_STRUCT.pack(total_size, chunk_size)
        _send_all(ssl_sock, header)

        with open(filepath, "rb") as in_f:
            while sent_body < total_size:
                to_read = min(chunk_size, total_size - sent_body)
                block = in_f.read(to_read)
                if len(block) != to_read:
                    print("Unexpected end of file while reading.", file=sys.stderr)
                    return 1
                if xfer_start is None:
                    xfer_start = time.monotonic()
                _send_all(ssl_sock, block)
                sent_body += len(block)

                now = time.monotonic()
                if now - last_progress >= 5.0 and total_size > 0:
                    pct = 100.0 * sent_body / total_size
                    print(
                        f"Progress: {pct:.2f}% ({sent_body}/{total_size} bytes)",
                        file=sys.stderr,
                    )
                    last_progress = now

        digest = hash_file(filepath)
        _send_all(ssl_sock, digest.encode("ascii"))
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

    except (BrokenPipeError, ConnectionResetError, ssl.SSLError, OSError) as exc:
        print(f"Transfer error: {exc}", file=sys.stderr)
        return 1
    finally:
        try:
            ssl_sock.close()
        except OSError:
            pass


if __name__ == "__main__":
    raise SystemExit(main())
