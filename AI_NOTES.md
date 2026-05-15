## Parts written end-to-end by AI

Nothing in this tree was merged without at least a quick human read. The pieces that were closest to “drop in from the model with little or no rewrite” were: the initial project skeleton under `secure-transfer/` (empty approach folders plus early stubs), `generate_test_file.py`, the first pass of `shared/hash_utils.py` (streaming SHA-256 and `verify_files_match`), the structure and prose of `approach-a-tls-mtls/DESIGN.md` and `approach-b-encrypted-envelope/DESIGN.md` (diagrams and threat tables, later adjusted to cite real line numbers), `THROUGHPUT.md` as a reporting shell, `approach-b-encrypted-envelope/smoke_test.py`, and the final `README.md` section layout for TASK 13. Core transfer logic in both `sender.py` / `receiver.py` paths was AI-drafted but then edited for TLS/mTLS settings, temp-file discipline, progress and throughput reporting, and tamper-test subprocess behavior.

## Where AI proposed something insecure or wrong (give 1+ concrete example)

**OpenSSL invocation for encrypted CA keys (Approach A setup).** An early version of `gen_certs.sh` passed `-passin` to convert or use an encrypted PKCS#8 key. With some `openssl` builds (notably certain Conda-packaged ones on macOS), `-passin` was ignored or mishandled in non-interactive use, which would have left key material in a confusing state or encouraged turning off encryption “to make the script work.” That weakens **confidentiality** of long-lived signing keys (anyone with the repo or backups could use a predictable or empty password path) and undermines **integrity** of the PKI story if operators bypass protections. The fix was to prefer the system `/usr/bin/openssl` when present and to document an `OPENSSL` override so the script always runs against a known-good CLI.

**Tamper / harness subprocesses and pipes.** Early tamper-test ideas ran the stock sender in-process or with stdout/stderr left on default pipes while also driving a proxy; that pattern risks **deadlock** (not a CIAA crypto failure, but it breaks **availability** of the test and can hide real failures). The correction was to redirect child stderr/stdout to files where needed, wait on processes in a safe order, and use a dedicated worker for byte-flip cases so the sender’s bytes on the wire diverge from its digest, matching the assignment’s “tamper on the wire” intent.

*(TLS “ease of testing” shortcuts such as `CERT_NONE` / `check_hostname=False` were explicitly rejected whenever they appeared; that would violate **authenticity (A)** in CIAA by accepting arbitrary peers.)*

## One thing AI did better than expected / one thing it did worse

**Better:** Turning the execution prompt into a coherent multi-file layout (shared hashing, two approaches, tamper harnesses, and design write-ups) in one pass, including reasonable constant names and AEAD choices, which saved a lot of mechanical typing.

**Worse:** Defaulting to “generic Linux `openssl`” behavior without calling out macOS/Homebrew/Conda differences until failures showed up in real runs—platform-specific tooling needed explicit guardrails.

## Role of AI tools used

**Cursor (Composer-style agent in the editor)** was used for almost all implementation and documentation: Python modules, shell scripts, markdown design and throughput notes, test harnesses, and the final README. **Cursor Chat** was used sporadically for small clarifications. No other AI products were used for this repository.
