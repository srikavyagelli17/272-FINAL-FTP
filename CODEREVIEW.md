# Task 15 — Code review (replicable steps)

**Repository root:** the `secure-transfer` directory itself—the folder that contains `README.md`, `shared/`, `approach-a-tls-mtls/`, and `approach-b-encrypted-envelope/`. Treat this as your Git root as well (put `.git` here so `git grep` runs from the same place as the rest of the steps).

Use this checklist after any code change. Open a terminal and:

```bash
cd /path/to/secure-transfer
```

Use whatever absolute path leads to **that** folder on your machine.

---

## 0. Tools

1. Install [ripgrep](https://github.com/BurntSushi/ripgrep) (`rg`) if you do not have it; the steps below use `rg` for fast recursive search.
2. With Git initialized **in `secure-transfer`**, use the assignment’s `git grep` command in §1. If there is no `.git` here yet, use the `rg` equivalent in the same section.

---

## 1. “No secrets in source” (TASK 15 table)

**Goal:** No accidental embedding of secrets; matches only identifiers, PEM loaders, and similar.

### Step 1.1 — From Git root (matches prompt wording)

Run exactly from **`secure-transfer`** (your repo root):

```bash
git grep -E "(key|secret|password)" -- '*.py'
```

**Expected:** Hits are only things like `--key`, `--privkey`, `password=None` for PEM parsing, path strings such as `certs/server.key`, comments like “KEEP … SECRET”, and variable names (`chunk_key`, etc.). There must be **no** literal passphrases, hex keys, or base64 key blobs in source.

### Step 1.2 — Without Git (recursive from repo root)

If `.git` is not in `secure-transfer`, run from the same directory:

```bash
rg -n -E "(key|secret|password)" --glob "*.py" .
```

**Expected:** Same manual inspection as in Step 1.1.

### Step 1.3 — Optional stricter scan for high-entropy literals

```bash
rg -n "-----BEGIN" --glob "*.py" .
```

**Expected:** Either no matches, or only documentation strings that are clearly placeholders (prefer none in `.py` files).

---

## 2. “No broken primitives” (TASK 15 table)

These searches implement the spirit of the checklist: **no CBC without MAC, no MD5, no ECB, no custom KDF**, and align with the prompt’s **Hard Rules** where they overlap.

Run each step. **Every command should print “no matches” (exit code 1 from `rg`) unless noted otherwise.**

### Step 2.1 — Forbidden SSL client/server shortcuts

```bash
rg -n "CERT_NONE|check_hostname\s*=\s*False" --glob "*.py" .
```

**Expected:** No matches in production transfer code.

### Step 2.2 — Forbidden hash / cipher names

```bash
rg -n "MD5|md5\(|AES-CBC|AES_CBC|AES-ECB|AES_ECB|SHA-1|sha1\(" --glob "*.py" .
```

**Expected:** No matches used for integrity or file crypto (incidental comments should be absent or justified).

### Step 2.3 — Forbidden PyCryptodome import

```bash
rg -n "from Crypto|import Crypto" --glob "*.py" .
```

**Expected:** No matches (use `cryptography` / PyNaCl only).

### Step 2.4 — AEAD usage for application-layer file encryption (Approach B)

```bash
rg -n "ChaCha20Poly1305|AESGCM" --glob "*.py" approach-b-encrypted-envelope/
```

**Expected:** At least one real use (e.g. encrypt/decrypt paths) in sender/receiver; not removed by mistake.

### Step 2.5 — KDF: library HKDF only (no ad-hoc KDF)

```bash
rg -n "HKDF|hkdf" --glob "*.py" approach-b-encrypted-envelope/
```

**Expected:** Uses `cryptography.hazmat.primitives.kdf.hkdf` (or equivalent documented API), not a hand-rolled extract-and-expand.

### Step 2.6 — Raw CTR / stream cipher without MAC (red flag)

```bash
rg -n "CTR|ChaCha20\(" --glob "*.py" approach-b-encrypted-envelope/
```

**Expected:** If `CTR` or `ChaCha20` appears, it must be **Poly1305 AEAD** (`ChaCha20Poly1305`), not raw stream-only modes for file bytes.

---

## 3. Hard Rules cross-check (automation where possible)

### Step 3.1 — Nonce / counter discipline (Approach B)

```bash
rg -n "nonce|counter" --glob "*.py" approach-b-encrypted-envelope/sender.py approach-b-encrypted-envelope/receiver.py
```

**Expected (manual):** Per-chunk nonces derived from a counter (or unique construction); no reuse of the same `(key, nonce)` for two different chunk ciphertexts.

### Step 3.2 — Fail-closed and temp files

```bash
rg -n "\.tmp|unlink|remove|os\.remove|Path\(.*\)\.unlink" --glob "*.py" approach-a-tls-mtls/receiver.py approach-b-encrypted-envelope/receiver.py
```

**Expected (manual):** Final output path is not committed until end-to-end integrity checks pass; on failure, temporary files are removed and process exits non-zero.

### Step 3.3 — No logging of key material

```bash
rg -n "print\(.*(key|nonce|secret|shared)" --glob "*.py" .
```

**Expected:** No matches that print raw keying material or nonces (progress-only prints are fine).

### Step 3.4 — Keys from files / arguments, not literals

```bash
rg -n "load_pem|load_cert|argparse.*key|add_argument.*cert" --glob "*.py" approach-a-tls-mtls/ approach-b-encrypted-envelope/
```

**Expected (manual):** Certificates and keys are loaded from paths supplied on the CLI (or env), not pasted into the source.

---

## 4. After the searches — quick manual read (same “code review” session)

1. Open `approach-a-tls-mtls/receiver.py` and `sender.py` and confirm `ssl.SSLContext` uses `CERT_REQUIRED` (or equivalent) for peer verification in the mTLS path.
2. Open `approach-b-encrypted-envelope/sender.py` and `receiver.py` and confirm file payload encryption uses **AEAD** only (e.g. ChaCha20-Poly1305) for chunks.
3. Confirm `shared/hash_utils.py` uses **SHA-256** for the end-to-end file digest.

---

## 5. Optional: re-run the same runtime checks as TASK 15

These are not “grep” code review, but they complete replication of the full TASK 15 matrix after edits. Run each block **from repo root** (`secure-transfer`).

1. **Prereq:** `./test_4gb.bin` exists next to `README.md` (see `README.md` § Setup).

2. **Approach A tamper suite:**

   ```bash
   cd approach-a-tls-mtls && python3 tamper_test.py && cd ..
   ```

   **Expected:** Three lines ending in `PASS`.

3. **Approach B tamper suite** (use the same interpreter you installed `cryptography` for):

   ```bash
   cd approach-b-encrypted-envelope && python3 tamper_test.py && cd ..
   ```

   **Expected:** Three lines ending in `PASS`.

4. **Full transfers and digest check** — follow `README.md` “Run” and “Verify” for Approach A, then Approach B, or from repo root use the verify one-liners:

   ```bash
   python3 -c "from shared.hash_utils import verify_files_match; verify_files_match('test_4gb.bin','approach-a-tls-mtls/received_a.bin')"
   python3 -c "from shared.hash_utils import verify_files_match; verify_files_match('test_4gb.bin','approach-b-encrypted-envelope/received_b.bin')"
   ```

   **Expected:** Both complete without raising (hashes match).

---

## 6. Sign-off template

Record date and result when you finish:

| Section | Command block | Result (pass / fail / N/A) |
|--------|-----------------|----------------------------|
| 1 Secrets scan | Steps 1.1–1.3 | |
| 2 Broken primitives | Steps 2.1–2.6 | |
| 3 Hard rules | Steps 3.1–3.4 + §4 manual | |
| 5 Runtime (optional) | Step 5 | |
