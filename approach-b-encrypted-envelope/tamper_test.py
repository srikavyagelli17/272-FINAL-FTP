#!/usr/bin/env python3
"""Tamper / failure scenarios for Approach B (encrypted envelope over plain TCP)."""

from __future__ import annotations

import argparse
import socket
import struct
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat, PublicFormat

SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent
REAL_PUB = SCRIPT_DIR / "keys" / "receiver_public.key"
REAL_PRIV = SCRIPT_DIR / "keys" / "receiver_private.key"
RECEIVER = [sys.executable, str(SCRIPT_DIR / "receiver.py")]
SENDER = [sys.executable, str(SCRIPT_DIR / "sender.py")]

SESSION_NONCE_LEN = 32
EPHEMERAL_PUB_RAW_LEN = 32
PREAMBLE_LEN = SESSION_NONCE_LEN + EPHEMERAL_PUB_RAW_LEN + 8 + 8


def _free_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    _, p = s.getsockname()
    s.close()
    return int(p)


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        b = sock.recv(min(1 << 20, n - len(buf)))
        if not b:
            raise EOFError("short read")
        buf += b
    return bytes(buf)


def _write_x25519_pair(directory: Path, stem: str) -> None:
    priv = X25519PrivateKey.generate()
    pub = priv.public_key()
    directory.joinpath(f"{stem}_private.key").write_bytes(
        priv.private_bytes(
            encoding=Encoding.PEM,
            format=PrivateFormat.PKCS8,
            encryption_algorithm=NoEncryption(),
        )
    )
    directory.joinpath(f"{stem}_public.key").write_bytes(
        pub.public_bytes(
            encoding=Encoding.PEM,
            format=PublicFormat.SubjectPublicKeyInfo,
        )
    )


def flip_offset_chunk1_ct_byte100(total_size: int, chunk_size: int) -> int:
    """Global TCP byte index of ciphertext byte 100 inside chunk 1 (0-based chunks)."""
    l0 = min(chunk_size, total_size)
    chunk0_wire = 8 + 12 + l0 + 16
    return PREAMBLE_LEN + chunk0_wire + 8 + 12 + 100


def _receiver_cmd(port: int, output: Path, privkey: Path) -> list[str]:
    return RECEIVER + [
        "--host",
        "127.0.0.1",
        "--port",
        str(port),
        "--output",
        str(output),
        "--privkey",
        str(privkey),
    ]


def _sender_cmd(port: int, filepath: Path, pubkey: Path, chunk_size: int) -> list[str]:
    return SENDER + [
        "--host",
        "127.0.0.1",
        "--port",
        str(port),
        "--file",
        str(filepath),
        "--receiver-pubkey",
        str(pubkey),
        "--chunk-size",
        str(chunk_size),
    ]


def flip_proxy_main(raw: list[str]) -> int:
    p = argparse.ArgumentParser(prog="tamper_test flip-proxy")
    p.add_argument("--listen-port", type=int, required=True)
    p.add_argument("--recv-host", default="127.0.0.1")
    p.add_argument("--recv-port", type=int, required=True)
    p.add_argument("--flip-offset", type=int, required=True)
    args = p.parse_args(raw)

    listen = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listen.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listen.bind(("127.0.0.1", args.listen_port))
    listen.listen(1)
    client, _ = listen.accept()
    listen.close()
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.connect((args.recv_host, args.recv_port))
    pos = 0
    try:
        while True:
            data = client.recv(262144)
            if not data:
                break
            ba = bytearray(data)
            for i in range(len(ba)):
                if pos + i == args.flip_offset:
                    ba[i] ^= 0xFF
            server.sendall(ba)
            pos += len(ba)
        try:
            server.shutdown(socket.SHUT_WR)
        except OSError:
            pass
        return 0
    finally:
        try:
            client.close()
        except OSError:
            pass
        try:
            server.close()
        except OSError:
            pass


def _read_frame(sock: socket.socket) -> bytes:
    hdr = _recv_exact(sock, 8)
    _ix, ln = struct.unpack("!II", hdr)
    body = _recv_exact(sock, 12 + ln + 16)
    return hdr + body


def swap_chunk_proxy_main(raw: list[str]) -> int:
    p = argparse.ArgumentParser(prog="tamper_test swap-chunk-proxy")
    p.add_argument("--listen-port", type=int, required=True)
    p.add_argument("--recv-port", type=int, required=True)
    args = p.parse_args(raw)

    listen = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listen.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listen.bind(("127.0.0.1", args.listen_port))
    listen.listen(1)
    sender_sock, _ = listen.accept()
    listen.close()
    recv_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    recv_sock.connect(("127.0.0.1", args.recv_port))
    try:
        pre = _recv_exact(sender_sock, PREAMBLE_LEN)
        recv_sock.sendall(pre)
        f0 = _read_frame(sender_sock)
        f1 = _read_frame(sender_sock)
        recv_sock.sendall(f1)
        recv_sock.sendall(f0)
        while True:
            try:
                f = _read_frame(sender_sock)
            except EOFError:
                break
            recv_sock.sendall(f)
        try:
            recv_sock.shutdown(socket.SHUT_WR)
        except OSError:
            pass
        return 0
    finally:
        try:
            sender_sock.close()
        except OSError:
            pass
        try:
            recv_sock.close()
        except OSError:
            pass


def test_wrong_private_key() -> bool:
    if not REAL_PUB.is_file() or not REAL_PRIV.is_file():
        print("SKIP: generate keys with gen_keys.py first.", file=sys.stderr)
        return False
    port = _free_port()
    with tempfile.TemporaryDirectory() as td:
        tdir = Path(td)
        _write_x25519_pair(tdir, "other")
        wrong_priv = tdir / "other_private.key"
        out = tdir / "out.bin"
        err_log = tdir / "recv.err"
        el = err_log.open("w", encoding="utf-8")
        try:
            recv = subprocess.Popen(
                _receiver_cmd(port, out, wrong_priv),
                stdout=subprocess.DEVNULL,
                stderr=el,
            )
            time.sleep(0.35)
            small = tdir / "small.bin"
            small.write_bytes(b"probe-wrong-key")
            send = subprocess.run(
                _sender_cmd(port, small, REAL_PUB, 64),
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=60,
            )
            recv.wait(timeout=60)
        finally:
            el.close()

        if recv.returncode != 1:
            return False
        if send.returncode not in (0, 1):
            return False
        if out.exists():
            return False
        if (out.parent / f"{out.name}.tmp").exists():
            return False
        err = err_log.read_text(encoding="utf-8", errors="replace")
        if "authentication" not in err.lower() and "chunk" not in err.lower():
            return False
        return True


def test_ciphertext_flip() -> bool:
    if not REAL_PUB.is_file() or not REAL_PRIV.is_file():
        return False
    chunk_size = 64
    payload = b"c" * 200
    flip_off = flip_offset_chunk1_ct_byte100(len(payload), chunk_size)

    with tempfile.TemporaryDirectory() as td:
        tdir = Path(td)
        plain = tdir / "plain.bin"
        plain.write_bytes(payload)

        # 1) Clean transfer
        port1 = _free_port()
        out1 = tdir / "ok.bin"
        err1 = tdir / "e1.log"
        e1 = err1.open("w", encoding="utf-8")
        try:
            r1 = subprocess.Popen(
                _receiver_cmd(port1, out1, REAL_PRIV),
                stdout=subprocess.DEVNULL,
                stderr=e1,
            )
            time.sleep(0.25)
            s1 = subprocess.run(
                _sender_cmd(port1, plain, REAL_PUB, chunk_size),
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=120,
            )
            r1.wait(timeout=120)
        finally:
            e1.close()
        if s1.returncode != 0 or r1.returncode != 0 or not out1.is_file():
            return False
        if out1.read_bytes() != payload:
            return False

        # 2) MITM flip one ciphertext byte in chunk 1
        recv_port = _free_port()
        proxy_port = _free_port()
        out2 = tdir / "bad.bin"
        err2 = tdir / "e2.log"
        e2 = err2.open("w", encoding="utf-8")
        proxy_cmd = [
            sys.executable,
            str(SCRIPT_DIR / "tamper_test.py"),
            "--flip-proxy",
            "--listen-port",
            str(proxy_port),
            "--recv-host",
            "127.0.0.1",
            "--recv-port",
            str(recv_port),
            "--flip-offset",
            str(flip_off),
        ]
        try:
            proxy = subprocess.Popen(
                proxy_cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            time.sleep(0.35)
            r2 = subprocess.Popen(
                _receiver_cmd(recv_port, out2, REAL_PRIV),
                stdout=subprocess.DEVNULL,
                stderr=e2,
            )
            time.sleep(0.25)
            s2 = subprocess.run(
                _sender_cmd(proxy_port, plain, REAL_PUB, chunk_size),
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=120,
            )
            proxy.wait(timeout=120)
            r2.wait(timeout=120)
        finally:
            e2.close()

        if s2.returncode not in (0, 1):
            return False
        if r2.returncode != 1:
            return False
        if out2.exists():
            return False
        if (out2.parent / f"{out2.name}.tmp").exists():
            return False
        return True


def test_chunk_reorder() -> bool:
    if not REAL_PUB.is_file() or not REAL_PRIV.is_file():
        return False
    chunk_size = 64
    payload = b"r" * 200
    recv_port = _free_port()
    proxy_port = _free_port()
    with tempfile.TemporaryDirectory() as td:
        tdir = Path(td)
        plain = tdir / "plain.bin"
        plain.write_bytes(payload)
        out = tdir / "out.bin"
        err = tdir / "recv.err"
        el = err.open("w", encoding="utf-8")
        proxy_cmd = [
            sys.executable,
            str(SCRIPT_DIR / "tamper_test.py"),
            "--swap-chunk-proxy",
            "--listen-port",
            str(proxy_port),
            "--recv-port",
            str(recv_port),
        ]
        try:
            proxy = subprocess.Popen(
                proxy_cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            time.sleep(0.35)
            recv = subprocess.Popen(
                _receiver_cmd(recv_port, out, REAL_PRIV),
                stdout=subprocess.DEVNULL,
                stderr=el,
            )
            time.sleep(0.25)
            send = subprocess.run(
                _sender_cmd(proxy_port, plain, REAL_PUB, chunk_size),
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=120,
            )
            proxy.wait(timeout=120)
            recv.wait(timeout=120)
        finally:
            el.close()

        if send.returncode not in (0, 1):
            return False
        if recv.returncode != 1:
            return False
        if out.exists():
            return False
        if (out.parent / f"{out.name}.tmp").exists():
            return False
        txt = err.read_text(encoding="utf-8", errors="replace")
        if "order" not in txt.lower():
            return False
        return True


def main() -> int:
    if not REAL_PUB.is_file() or not REAL_PRIV.is_file():
        print("FAIL: run gen_keys.py first.", file=sys.stderr)
        return 1

    t1 = test_wrong_private_key()
    print("Test 1 (wrong private key):", "PASS" if t1 else "FAIL", flush=True)

    t2 = test_ciphertext_flip()
    print("Test 2 (ciphertext flip via proxy):", "PASS" if t2 else "FAIL", flush=True)

    t3 = test_chunk_reorder()
    print("Test 3 (chunk reorder via proxy):", "PASS" if t3 else "FAIL", flush=True)

    return 0 if (t1 and t2 and t3) else 1


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--flip-proxy":
        raise SystemExit(flip_proxy_main(sys.argv[2:]))
    if len(sys.argv) > 1 and sys.argv[1] == "--swap-chunk-proxy":
        raise SystemExit(swap_chunk_proxy_main(sys.argv[2:]))
    raise SystemExit(main())
