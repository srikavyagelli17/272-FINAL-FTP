# Approach B: Application-Layer Encrypted Envelope over Plain TCP

## Architecture Diagram (ASCII)

```
  [Sender]                         [Plain TCP]                    [Receiver]
      |                                 |                             |
      |--- TCP connect (no TLS) ------>|                             |
      |                                 |---- same bytes ----------->|
      |                                 |                             |
      |  App-layer crypto:              |                             |
      |  - X25519 ECDHE (eph + static   |                             |
      |    receiver pubkey)             |                             |
      |  - HKDF -> chunk AEAD key       |                             |
      |  - ChaCha20-Poly1305 / chunk    |                             |
      |                                 |                             |
      v                                 v                             v
  sender.py                      bytes on wire                receiver.py
  (only receiver_public.key)     are ciphertext + framing    (receiver_private.key)
```

The TCP socket carries **no TLS**. Confidentiality and per-chunk integrity come entirely from the envelope (`sender.py` / `receiver.py`). The receiver’s **private** key never leaves the receiver host; the sender only loads `receiver_public.key` (`sender.py` **`_load_receiver_public`** lines **41–46**).

## Key Exchange & Management

- **Protocol:** X25519 static-ephemeral ECDHE each transfer — `X25519PrivateKey.generate()` and `exchange(receiver_pub)` in `sender.py` **98–100**; matching `priv.exchange(eph_pub)` in `receiver.py` **140–141**.
- **KDF:** HKDF-SHA256, 32-byte output, `salt = session_nonce` (32 random bytes from `os.urandom`), `info = b"chunk-encryption"` — `_derive_chunk_key` in `sender.py` **49–56** and `receiver.py` **62–69** (`HKDF_INFO` constant **28** / **25**).
- **Encryption:** ChaCha20-Poly1305 AEAD per chunk (`ChaCha20Poly1305` in `sender.py` **104**, **138**; `receiver.py` **143**, **165**). Nonce = 4-byte big-endian chunk index concatenated with first 8 bytes of `session_nonce` (`sender.py` **135–136**; receiver reads sender’s nonce from the wire **159**).
- **Receiver private key:** Loaded only in `receiver.py` **`_load_receiver_private`** (**54–59**) from `--privkey`; `sender.py` never opens `receiver_private.key`.

## Chunking & Framing

- **Chunk size:** 4 MiB default (`CHUNK_SIZE = 4 << 20` in `gen_keys.py` **21**), passed on the wire as `uint64` in the preamble (`sender.py` **117**; `receiver.py` **133–135**) and overridable with `--chunk-size`.
- **Preamble (80 bytes):** `session_nonce` (32) + raw ephemeral public key (32) + `!QQ` total size and chunk size (`sender.py` **114–118**; `receiver.py` **130–136**).
- **Per-chunk frame:** `chunk_index` (4 BE) + `chunk_length` (4 BE) + `nonce` (12) + `ciphertext||tag` (`chunk_length + 16` bytes) — `sender.py` **139–142**; `receiver.py` **150–161**.
- **Ordering:** `expected_index` must match each frame’s `chunk_index` (`receiver.py` **146**, **157–158**); otherwise abort with `abort(...)` (**121–124**).

## Exact Algorithms

- **Key exchange:** X25519 (Curve25519), PyCA `cryptography.hazmat.primitives.asymmetric.x25519`.
- **KDF:** HKDF with SHA-256 (`hashes.SHA256()` in `_derive_chunk_key`).
- **AEAD:** ChaCha20-Poly1305, 256-bit key, 96-bit (12-byte) nonce.
- **End-to-end hash:** SHA-256 hex (64 ASCII chars) over the original plaintext file — `hash_file` in `sender.py` **146**; `hash_file(temp_path)` in `receiver.py` **194** compared to wire digest **195–198**.

## Threat Model Response Table

Threats are aligned with the assessment **CIAA** goals.

| Threat (Section 6 / CIAA) | Mechanism in this codebase |
|---------------------------|------------------------------|
| **C — Eavesdropper reads file bytes on TCP** | Plaintext never sent on the wire: each chunk is `aead.encrypt(...)` (`sender.py` **138–142**). Preamble exposes only public material (`session_nonce`, ephemeral pubkey, sizes); the symmetric `chunk_key` is derived and never logged. |
| **I — Bit-flip or forgery inside a chunk** | ChaCha20-Poly1305 tag verification — `aead.decrypt` raises `InvalidTag` (`receiver.py` **164–167**), triggering `abort`, temp file deletion (**121–123**), exit code 1. |
| **I — Wrong end-to-end file or truncated transfer** | After all chunks, `hash_file(temp_path)` must equal the 64-byte wire digest (`receiver.py` **194–198**); mismatch deletes temp and errors. Short reads raise `EOFError` (**214–215**). `chunk_len` cannot exceed remaining plaintext bytes (**154–156**). |
| **A — Wrong peer / wrong static key** | If the receiver uses a different private key than the sender’s assumed public key, ECDHE still produces garbage bytes and **first-chunk** `decrypt` fails with `InvalidTag` (same **164–167** path as `tamper_test.py` wrong-key scenario). |
| **A — Replay or reorder chunks** | Strict `chunk_index == expected_index` (`receiver.py` **157–158**). Out-of-order frames abort before writing bad plaintext. |
| **A — Availability / silent partial output** | Writes go to `<output>.tmp` only (`receiver.py` **148**, **200**); `os.rename` to final path only after digest match (**200**). Any `abort` or exception path deletes the temp file (**121–123**, **196**, **214–217**). |
