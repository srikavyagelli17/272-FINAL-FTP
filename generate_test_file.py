#!/usr/bin/env python3
"""Write a large deterministic test file (zero-filled) in fixed-size chunks."""

from __future__ import annotations

import argparse
import hashlib
import sys

# Write in 64 MiB chunks (spec).
CHUNK_BYTES = 64 << 20
BYTES_PER_GIB = 1024**3


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Generate a zero-filled test file for transfer benchmarks.",
    )
    p.add_argument(
        "--size-gb",
        type=float,
        default=4.0,
        help="Logical size in GiB (1024^3 bytes per unit). Default: 4",
    )
    p.add_argument(
        "--output",
        default="test_4gb.bin",
        help="Output path. Default: test_4gb.bin",
    )
    return p.parse_args()


def main() -> int:
    args = parse_args()
    total = int(args.size_gb * BYTES_PER_GIB)
    if total <= 0:
        print("--size-gb must yield a positive byte count.", file=sys.stderr)
        return 2

    zero_chunk = bytes(CHUNK_BYTES)
    h = hashlib.sha256()
    remaining = total

    with open(args.output, "wb") as f:
        while remaining > 0:
            n = min(CHUNK_BYTES, remaining)
            if n == CHUNK_BYTES:
                f.write(zero_chunk)
                h.update(zero_chunk)
            else:
                block = zero_chunk[:n]
                f.write(block)
                h.update(block)
            remaining -= n

    print(h.hexdigest())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
