#!/usr/bin/env bash
# Generate self-signed CA and mTLS server/client certificates for Approach A.
#
# Security:
#   - The CA private key is encrypted (AES-256). We never use -nodes here; the CA
#     key must remain passphrase-protected.
#   - Server and client keys are generated without encryption (equivalent to using
#     -nodes in openssl req flows) so receiver/sender scripts can load keys non-interactively.
#
# Optional: set CA_KEY_PASS in the environment to choose the CA encryption passphrase
# (default is suitable for local development only).
# Optional: set OPENSSL to a specific openssl binary if your default one mishandles -passin.

set -euo pipefail

# Prefer $OPENSSL; else macOS /usr/bin/openssl when present. Some Python distros ship an
# OpenSSL 3.6 build that ignores -passin for encrypted PKCS#8 keys and tries to open a TTY.
if [ -n "${OPENSSL-}" ]; then
  OPENSSL_BIN="${OPENSSL}"
elif [ -x /usr/bin/openssl ]; then
  OPENSSL_BIN=/usr/bin/openssl
else
  OPENSSL_BIN=openssl
fi

echo "Using ${OPENSSL_BIN} ($("${OPENSSL_BIN}" version 2>&1 | head -1))"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CERT_DIR="${SCRIPT_DIR}/certs"
EXT_FILE="${SCRIPT_DIR}/openssl-ext.cnf"
mkdir -p "${CERT_DIR}"
cd "${CERT_DIR}"

# Passphrase for the encrypted CA key (non-interactive).
export CA_KEY_PASS="${CA_KEY_PASS:-dev-only-change-me}"

rm -f ca.key ca.crt server.key server.crt client.key client.crt \
  server.csr client.csr ca.srl 2>/dev/null || true

# --- CA: 4096-bit RSA, encrypted private key, SHA-256, 10-year self-signed cert ---
"${OPENSSL_BIN}" genrsa -aes256 -passout env:CA_KEY_PASS -out ca.key 4096
"${OPENSSL_BIN}" req -new -x509 -days 3650 -sha256 \
  -key ca.key -passin env:CA_KEY_PASS \
  -out ca.crt \
  -subj "/O=SecureTransfer Lab/CN=Development CA"

# --- Server: 2048-bit RSA, CN=localhost, SAN 127.0.0.1 (plaintext key for automation) ---
"${OPENSSL_BIN}" genrsa -out server.key 2048
"${OPENSSL_BIN}" req -new -key server.key -out server.csr -subj "/CN=localhost"
"${OPENSSL_BIN}" x509 -req -days 3650 -sha256 \
  -in server.csr \
  -CA ca.crt -CAkey ca.key -passin env:CA_KEY_PASS \
  -CAcreateserial \
  -out server.crt \
  -extfile "${EXT_FILE}" -extensions v3_server

# --- Client: 2048-bit RSA, signed by same CA (plaintext key for automation) ---
"${OPENSSL_BIN}" genrsa -out client.key 2048
"${OPENSSL_BIN}" req -new -key client.key -out client.csr -subj "/CN=secure-transfer-client"
"${OPENSSL_BIN}" x509 -req -days 3650 -sha256 \
  -in client.csr \
  -CA ca.crt -CAkey ca.key -passin env:CA_KEY_PASS \
  -CAserial ca.srl \
  -out client.crt \
  -extfile "${EXT_FILE}" -extensions v3_client

rm -f server.csr client.csr

echo "Certificates written to ${CERT_DIR}"
echo "CA key is encrypted. Reuse the same CA_KEY_PASS when signing additional certs."
