#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CRATE="$ROOT/rust-regex-validator"
OUTPUT="$ROOT/src/regex_validator.wasm"
IMAGE="rust:1.88.0-bookworm"

CA_ARGS=()
CA_BUNDLE=""
cleanup() {
  [[ -z "$CA_BUNDLE" ]] || rm -f "$CA_BUNDLE"
}
trap cleanup EXIT

if command -v security >/dev/null 2>&1; then
  CA_BUNDLE="$(mktemp)"
  [[ ! -f /etc/ssl/cert.pem ]] || cat /etc/ssl/cert.pem >> "$CA_BUNDLE"
  security find-certificate -a -p /Library/Keychains/System.keychain >> "$CA_BUNDLE"
  security find-certificate -a -p /System/Library/Keychains/SystemRootCertificates.keychain >> "$CA_BUNDLE"
  CA_ARGS+=(
    -v "$CA_BUNDLE:/host-ca/cert.pem:ro"
    -e CARGO_HTTP_CAINFO=/host-ca/cert.pem
    -e SSL_CERT_FILE=/host-ca/cert.pem
  )
elif [[ -f /etc/ssl/certs/ca-certificates.crt ]]; then
  CA_ARGS+=(
    -v "/etc/ssl/certs/ca-certificates.crt:/host-ca/cert.pem:ro"
    -e CARGO_HTTP_CAINFO=/host-ca/cert.pem
    -e SSL_CERT_FILE=/host-ca/cert.pem
  )
fi

docker run --rm \
  --platform linux/amd64 \
  -v "$CRATE:/work" \
  "${CA_ARGS[@]}" \
  -w /work \
  "$IMAGE" \
  bash -ceu 'rustup target add wasm32-unknown-unknown && cargo build --release --locked --target wasm32-unknown-unknown'

cp "$CRATE/target/wasm32-unknown-unknown/release/rust_regex_validator.wasm" "$OUTPUT"
SHA="$(shasum -a 256 "$OUTPUT" | awk '{print $1}')"
SIZE="$(wc -c < "$OUTPUT" | tr -d ' ')"
printf 'Built %s\nSHA-256: %s\nSize: %s bytes\n' "$OUTPUT" "$SHA" "$SIZE"
