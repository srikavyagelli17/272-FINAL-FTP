# Approach A: Mutually-Authenticated TLS Streaming

## Architecture Diagram (ASCII)

```
  [Sender]                              [Receiver]
      |                                     |
      |-------- TCP connect ---------------->|
      |                                     |
      |<====== TLS handshake (1.2/1.3) ===>|
      |   ServerHello + cert chain          |
      |   ClientHello + client cert           |
      |   ECDHE key share (in handshake)    |
      |   Finished / verify peer certs      |
      |                                     |
      |-- TLS app data: 16B header -------->|
      |   (total_size || chunk_size BE)     |
      |-- TLS app data: file chunks ------->|
      |   (1 MiB reads, AEAD inside TLS)   |
      |-- TLS app data: 64B SHA-256 hex --->|
      |                                     |
      v                                     v
  sender.py                            receiver.py
  (client, mTLS)                       (server, mTLS)
```

Certificates are issued offline by `gen_certs.sh` (CA → server + client). Both processes load PEM material from disk; the CA key is encrypted at rest.

## Key Exchange & Management

- **Protocol:** TLS 1.3 preferred, TLS 1.2 minimum (`ssl.TLSProtocol.TLS_SERVER` / `PROTOCOL_TLS_SERVER` and `minimum_version = TLSv1_2`, options disabling TLS 1.0/1.1 in `receiver.py` `_ssl_server_context` lines **31–32** and `sender.py` `_ssl_client_context` lines **30–31**).
- **Key exchange:** Ephemeral ECDHE as negotiated by the Python/OpenSSL stack (e.g. X25519 or P-256 in TLS 1.3); forward secrecy comes from TLS, not from application code.
- **Authentication:** X.509 **mutual** TLS — server presents `load_cert_chain` (`receiver.py` **35**), client presents `load_cert_chain` (`sender.py` **35**); peer verification uses `verify_mode = CERT_REQUIRED` and `load_verify_locations(ca)` (`receiver.py` **33–34**, `sender.py` **32–34**). `sender.py` sets `check_hostname = True` and passes `server_hostname` to `wrap_socket` (**33**, **82**) so hostname/SAN verification is never disabled.
- **Key material:** Session keys and IVs are internal to the TLS stack; the application never prints or logs them (see project hard rules).

## Chunking & Framing

- **Chunk size:** 1 MiB (`1 << 20`), constant `DEFAULT_CHUNK_SIZE` in `sender.py` line **14**; overridable via `--chunk-size`.
- **Framing header:** 16 bytes = two big-endian `uint64` values (`struct.Struct("!QQ")`, `sender.py` **22**, **103–104**; `receiver.py` **21**, **112–113**): total file size, then chunk size hint for reads.
- **TLS record layer:** Each `send`/`recv` of application data is protected by the negotiated AEAD cipher suite (e.g. AES-256-GCM or ChaCha20-Poly1305 under TLS 1.3).

## Exact Algorithms

- **Cipher (bulk):** TLS 1.3 ciphers such as `TLS_AES_256_GCM_SHA384` or `TLS_CHACHA20_POLY1305_SHA256` (chosen by the stack at handshake); 256-bit AEAD keys at the record layer.
- **Key length:** 256-bit AEAD keys inside TLS.
- **End-to-end file hash:** SHA-256 over the plaintext file (`shared/hash_utils.hash_file`), `sender.py` **127** (digest sent), `receiver.py` **152** (recomputed on temp file and compared **153–156**).
- **Certificates:** RSA 2048-bit server/client keys, 4096-bit CA, SHA-256 signatures — see `gen_certs.sh` / OpenSSL invocations used to generate PEMs.

## Threat Model Response Table

Threats are aligned with the assessment **CIAA** goals (confidentiality, integrity, authenticity, availability on the wire and on disk).

| Threat (Section 6 / CIAA) | Mechanism in this codebase |
|---------------------------|------------------------------|
| **C — Eavesdropper learns file contents on the network** | After the TLS handshake, all application bytes (header, payload, digest) travel inside TLS ciphertext (`sender.py` `_send_all` on `ssl_sock` **104–116**, **128**; `receiver.py` `_recv_exact` on `ssl_sock` **112–129**, **144**). TLS 1.2+ AEAD record encryption provides confidentiality on the wire. |
| **I — Attacker tampers with ciphertext in flight** | TLS AEAD tag verification fails at the record layer; the connection errors (`sender.py` **141** `ssl.SSLError`; `receiver.py` **172** catches `SSLError` / `EOFError` and `fail_incomplete`). Any surviving application-level inconsistency is caught by comparing `hash_file(temp_path)` to the sender’s 64-byte digest (`receiver.py` **152–156**). |
| **I — Truncation or wrong final digest** | If fewer than `total_size` bytes arrive or the digest does not match, the temp file is deleted and the process exits with an error (`receiver.py` **124–125**, **149–150**, **153–156**; messages `INCOMPLETE TRANSFER` / `INTEGRITY FAILURE` in **108**, **155**). |
| **A — Fake server or client (MITM / impersonation)** | Mutual TLS: `CERT_REQUIRED` and CA bundle on both sides (`receiver.py` **33–34**; `sender.py` **32–34**). Wrong or untrusted peer certs cause handshake failure (`receiver.py` **88–93**; `sender.py` **90–96**). Hostname verification on the client (`sender.py` **33**, **82**). |
| **A — Availability / silent partial file** | Payload is written only to `<output>.tmp` until SHA-256 matches; then `os.rename` to the final path (`receiver.py` **118**, **158**). On failure, `_delete_if_exists(temp_path)` runs (`receiver.py` **106–107**, **154**, **172–173**). |
