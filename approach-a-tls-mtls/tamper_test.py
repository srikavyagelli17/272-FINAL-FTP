#!/usr/bin/env python3
"""Automated tamper / failure scenarios for Approach A (mTLS file transfer).

Test 2 copies ``test_4gb.bin``, flips one byte (assignment), then uses a helper
subprocess that streams those bytes but sends a deliberately wrong SHA-256 hex
string. The stock ``sender.py`` always hashes the bytes it sends, so it cannot
produce an on-wire / digest mismatch by itself.
"""

from __future__ import annotations

import argparse
import importlib.util
import os
import shutil
import signal
import socket
import ssl
import subprocess
import sys
import tempfile
import time
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent
TEST_4GB = REPO_ROOT / "test_4gb.bin"
CA = SCRIPT_DIR / "certs" / "ca.crt"
SERVER_CRT = SCRIPT_DIR / "certs" / "server.crt"
SERVER_KEY = SCRIPT_DIR / "certs" / "server.key"
CLIENT_CRT = SCRIPT_DIR / "certs" / "client.crt"
CLIENT_KEY = SCRIPT_DIR / "certs" / "client.key"
RECEIVER = [sys.executable, str(SCRIPT_DIR / "receiver.py")]
SENDER = [sys.executable, str(SCRIPT_DIR / "sender.py")]
FLIP_OFFSET = 1_000_000


def _free_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    _, port = s.getsockname()
    s.close()
    return int(port)


def _openssl_bin() -> str:
    if os.path.isfile("/usr/bin/openssl"):
        return "/usr/bin/openssl"
    return "openssl"


def _recv_cmd(port: int, output: Path) -> list[str]:
    return RECEIVER + [
        "--host",
        "127.0.0.1",
        "--port",
        str(port),
        "--output",
        str(output),
        "--cert",
        str(SERVER_CRT),
        "--key",
        str(SERVER_KEY),
        "--ca",
        str(CA),
    ]


def _sender_cmd(port: int, filepath: Path, cert: Path, key: Path) -> list[str]:
    return SENDER + [
        "--host",
        "127.0.0.1",
        "--port",
        str(port),
        "--file",
        str(filepath),
        "--cert",
        str(cert),
        "--key",
        str(key),
        "--ca",
        str(CA),
        "--chunk-size",
        "1048576",
    ]


def _load_sender_module():
    spec = importlib.util.spec_from_file_location("approach_a_sender", SCRIPT_DIR / "sender.py")
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


def wrong_digest_worker_main(raw: list[str]) -> int:
    """Stream *corrupted* bytes but send a valid wrong SHA-256 hex (integrity failure on receiver)."""
    p = argparse.ArgumentParser(prog="tamper_test wrong-digest worker")
    p.add_argument("--corrupted", required=True)
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, required=True)
    p.add_argument("--cert", required=True)
    p.add_argument("--key", required=True)
    p.add_argument("--ca", required=True)
    p.add_argument("--chunk-size", type=int, default=1 << 20)
    args = p.parse_args(raw)

    corrupted = args.corrupted
    total_size = os.path.getsize(corrupted)
    chunk_size = args.chunk_size
    # Valid 64-hex string that will not match the received payload hash (avoids an extra full-disk hash read).
    bad_digest = "a" * 64

    sm = _load_sender_module()
    ctx = sm._ssl_client_context(ca=args.ca, cert=args.cert, key=args.key)

    raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ssl_sock: ssl.SSLSocket | None = None
    try:
        raw_sock.connect((args.host, args.port))
        ssl_sock = ctx.wrap_socket(raw_sock, server_hostname=args.host)
    except OSError:
        try:
            raw_sock.close()
        except OSError:
            pass
        return 1
    except ssl.SSLError:
        try:
            raw_sock.close()
        except OSError:
            pass
        return 1

    try:
        assert ssl_sock is not None
        sm._send_all(ssl_sock, sm.HEADER_STRUCT.pack(total_size, chunk_size))
        sent = 0
        with open(corrupted, "rb") as f:
            while sent < total_size:
                n = min(chunk_size, total_size - sent)
                block = f.read(n)
                if len(block) != n:
                    return 1
                sm._send_all(ssl_sock, block)
                sent += len(block)
        sm._send_all(ssl_sock, bad_digest.encode("ascii"))
        return 0
    finally:
        if ssl_sock is not None:
            try:
                ssl_sock.close()
            except OSError:
                pass


def test_wrong_client_cert() -> bool:
    if not CA.is_file():
        print("SKIP: certs not generated (missing CA).", file=sys.stderr)
        return False
    port = _free_port()
    with tempfile.TemporaryDirectory() as td:
        tdir = Path(td)
        out = tdir / "out.bin"
        bad_key = tdir / "bad.key"
        bad_crt = tdir / "bad.crt"
        subprocess.run(
            [
                _openssl_bin(),
                "req",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-keyout",
                str(bad_key),
                "-x509",
                "-days",
                "1",
                "-out",
                str(bad_crt),
                "-subj",
                "/CN=wrong-client-selfsigned",
            ],
            check=True,
            capture_output=True,
            cwd=td,
        )

        small = tdir / "tiny.bin"
        small.write_bytes(b"x")

        recv = subprocess.Popen(
            _recv_cmd(port, out),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        time.sleep(0.4)
        send = subprocess.run(
            _sender_cmd(port, small, bad_crt, bad_key),
            capture_output=True,
            text=True,
            timeout=60,
        )
        try:
            _, _ = recv.communicate(timeout=60)
        except subprocess.TimeoutExpired:
            recv.kill()
            return False

        if out.exists():
            return False
        # Handshake must fail closed (either side non-zero); do not require a specific substring
        # because stderr may be dominated by harmless warnings.
        return send.returncode != 0 or recv.returncode != 0


def test_byte_flip() -> bool:
    if not TEST_4GB.is_file():
        print("SKIP: test_4gb.bin not found at repo root.", file=sys.stderr)
        return False
    port = _free_port()
    with tempfile.TemporaryDirectory() as td:
        tdir = Path(td)
        corrupt = tdir / "corrupt.bin"
        out = tdir / "received.bin"
        shutil.copyfile(TEST_4GB, corrupt, follow_symlinks=True)
        with corrupt.open("r+b") as f:
            f.seek(FLIP_OFFSET)
            b = f.read(1)
            if len(b) != 1:
                return False
            f.seek(FLIP_OFFSET)
            f.write(bytes([b[0] ^ 0xFF]))

        err_log = tdir / "receiver.stderr.log"
        el = err_log.open("w", encoding="utf-8")
        try:
            recv = subprocess.Popen(
                _recv_cmd(port, out),
                stdout=subprocess.DEVNULL,
                stderr=el,
            )
            time.sleep(0.4)
            worker = [
                sys.executable,
                str(Path(__file__).resolve()),
                "--wrong-digest-worker",
                "--corrupted",
                str(corrupt),
                "--host",
                "127.0.0.1",
                "--port",
                str(port),
                "--cert",
                str(CLIENT_CRT),
                "--key",
                str(CLIENT_KEY),
                "--ca",
                str(CA),
                "--chunk-size",
                "1048576",
            ]
            send = subprocess.run(worker, capture_output=True, text=True, timeout=1800)
            try:
                recv.wait(timeout=1800)
            except subprocess.TimeoutExpired:
                recv.kill()
                try:
                    recv.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    pass
                return False
        finally:
            el.close()

        r_err = err_log.read_text(encoding="utf-8", errors="replace")
        r_out = ""

        if recv.returncode != 1:
            return False
        if out.exists():
            return False
        tmp_path = out.parent / f"{out.name}.tmp"
        if tmp_path.exists():
            return False
        if "INTEGRITY" not in (r_err + r_out):
            return False
        return True


def test_mid_transfer_kill() -> bool:
    if not TEST_4GB.is_file():
        print("SKIP: test_4gb.bin not found at repo root.", file=sys.stderr)
        return False
    port = _free_port()
    with tempfile.TemporaryDirectory() as td:
        tdir = Path(td)
        out = tdir / "received.bin"
        err_log = tdir / "receiver.stderr.log"
        el = err_log.open("w", encoding="utf-8")
        try:
            recv = subprocess.Popen(
                _recv_cmd(port, out),
                stdout=subprocess.DEVNULL,
                stderr=el,
            )
            time.sleep(0.4)
            send = subprocess.Popen(
                _sender_cmd(port, TEST_4GB, CLIENT_CRT, CLIENT_KEY),
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            time.sleep(10)
            send.send_signal(signal.SIGKILL)
            try:
                send.wait(timeout=30)
            except subprocess.TimeoutExpired:
                send.kill()

            try:
                recv.wait(timeout=120)
            except subprocess.TimeoutExpired:
                recv.kill()
                try:
                    recv.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    pass
                return False
        finally:
            el.close()

        r_err = err_log.read_text(encoding="utf-8", errors="replace")
        r_out = ""

        if recv.returncode != 1:
            return False
        if out.exists():
            return False
        tmp_path = out.parent / f"{out.name}.tmp"
        if tmp_path.exists():
            return False
        if "INCOMPLETE" not in (r_err + r_out):
            return False
        return True


def main() -> int:
    if not CA.is_file():
        print("FAIL: run gen_certs.sh first (missing certs).", file=sys.stderr)
        return 1

    t1 = test_wrong_client_cert()
    print("Test 1 (wrong client cert):", "PASS" if t1 else "FAIL", flush=True)

    t2 = test_byte_flip()
    print("Test 2 (byte-flip / wrong digest):", "PASS" if t2 else "FAIL", flush=True)

    t3 = test_mid_transfer_kill()
    print("Test 3 (mid-transfer SIGKILL):", "PASS" if t3 else "FAIL", flush=True)

    return 0 if (t1 and t2 and t3) else 1


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--wrong-digest-worker":
        raise SystemExit(wrong_digest_worker_main(sys.argv[2:]))
    raise SystemExit(main())
