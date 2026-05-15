# Throughput measurements (TASK 11)

Measurements were taken on **loopback** (`127.0.0.1`) on one developer machine, using a **256 MiB** payload file generated with:

`python generate_test_file.py --size-gb 0.25 --output bench_256mb.bin`

## Approach A — mTLS streaming (1 MiB TLS payload chunks)

| Role | Metric | Value |
|------|--------|------:|
| Sender | `Throughput: X.XX MB/s` | **277.25 MB/s** |
| Receiver | `Receive throughput: X.XX MB/s` | **236.97 MB/s** |

## Approach B — Encrypted envelope (4 MiB plaintext chunks)

| Role | Metric | Value |
|------|--------|------:|
| Sender | `Throughput: X.XX MB/s` | **363.89 MB/s** |
| Receiver | `Receive throughput: X.XX MB/s` | **297.24 MB/s** |

## Why one approach looks faster or slower here

On this run, **Approach B reported higher MB/s** than Approach A, even though B does explicit X25519, HKDF, and ChaCha20-Poly1305 in Python for every chunk. That is partly an artifact of **how throughput is defined** (file bytes divided by wall time from first file byte sent/received through digest handling) and partly **chunk sizing**: B used **4 MiB** plaintext chunks versus A’s **1 MiB** reads over TLS, so B amortizes framing and Python-level loop overhead across more bytes per iteration. Approach A also carries **mTLS and TLS record framing** on the wire; the stack still handles bulk data very well, but smaller application read sizes and the extra TLS machinery can shift the numbers on localhost. On a wide-area link or a CPU-bound host, **B’s per-chunk cryptography in userspace** could flip the ranking relative to a highly optimized TLS data path. Treat these figures as **order-of-magnitude loopback baselines**, not a universal ranking.
