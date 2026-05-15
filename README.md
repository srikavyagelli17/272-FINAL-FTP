<<<<<<< HEAD
# 272-FINAL-FTP
=======
# Secure 4 GB File Transfer

## Prerequisites

- **Python:** 3.10 or newer (3.12+ recommended).
- **Packages:** `cryptography`, `PyNaCl` (install via pip below).
- **OpenSSL:** `openssl` on your `PATH` (used by `approach-a-tls-mtls/gen_certs.sh`). On macOS, `/usr/bin/openssl` (LibreSSL) is preferred if your default `openssl` mishandles encrypted keys in non-interactive mode.

## Setup

### 1. Install dependencies

```bash
pip install cryptography PyNaCl
```

### 2. Generate test file

```bash
python generate_test_file.py --size-gb 4 --output test_4gb.bin
```

## Approach A — Mutually-Authenticated TLS Streaming

### Setup (run once)

```bash
bash approach-a-tls-mtls/gen_certs.sh
```

### Run

```bash
# Terminal 1 (receiver):
cd approach-a-tls-mtls && python receiver.py --host 127.0.0.1 --port 9000 --output received_a.bin --cert certs/server.crt --key certs/server.key --ca certs/ca.crt

# Terminal 2 (sender):
cd approach-a-tls-mtls && python sender.py --host 127.0.0.1 --port 9000 --file ../test_4gb.bin --cert certs/client.crt --key certs/client.key --ca certs/ca.crt --chunk-size 1048576
```

### Verify

```bash
python -c "from shared.hash_utils import verify_files_match; verify_files_match('test_4gb.bin','approach-a-tls-mtls/received_a.bin')"
```

## Approach B — Application-Layer Encrypted Envelope

### Setup (run once)

```bash
cd approach-b-encrypted-envelope && python gen_keys.py
```

### Run

```bash
# Terminal 1 (receiver):
cd approach-b-encrypted-envelope && python receiver.py --host 127.0.0.1 --port 9001 --output received_b.bin --privkey keys/receiver_private.key

# Terminal 2 (sender):
cd approach-b-encrypted-envelope && python sender.py --host 127.0.0.1 --port 9001 --file ../test_4gb.bin --receiver-pubkey keys/receiver_public.key --chunk-size 4194304
```

### Verify

```bash
python -c "from shared.hash_utils import verify_files_match; verify_files_match('test_4gb.bin','approach-b-encrypted-envelope/received_b.bin')"
```

## Running Tamper Tests

```bash
cd approach-a-tls-mtls && python tamper_test.py
cd approach-b-encrypted-envelope && python tamper_test.py
```
>>>>>>> 3a04c4e (Initial deployment)
