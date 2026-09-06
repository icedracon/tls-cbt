# Changelog

All notable changes to `tls-cbt` are documented here. Follows
[Keep a Changelog](https://keepachangelog.com); uses SemVer.

## [0.1.0-beta.1] — unreleased

Initial release. Unstable API (0.x + beta) — expect small breaks before 0.1.0.

### Added
- RFC 5929 `tls-server-end-point` channel-binding hash of a DER-encoded
  server certificate.
- Automatic hash selection from the certificate's own signatureAlgorithm,
  with MD5 / SHA-1 upgraded to SHA-256 per RFC 5929 §4.1.
- Recognizes RSA PKCS#1 (`sha{256,384,512}WithRSA`) and ECDSA
  (`ecdsa-with-SHA{256,384,512}`); unknown algorithms fall back to SHA-256.
- Inline DER walk for the signature-algorithm OID — no full X.509 parser
  dependency.

### Dependencies
- `sha2` (already in the ADhammer ecosystem's dependency graph — no
  net-new third-party crate).

### Validated
- 8 unit tests + one doctest cover DER walk, hash selection, malformed
  input, and end-to-end hash length.
- 100k random inputs — DER walk never panics (`tests/fuzz.rs`).
- Windows reference: extracted `sha256WithRSA` from a real Windows Server
  2025 DC's LDAPS certificate and produced a `tls-server-end-point` hash
  that byte-matches Windows' own SHA-256 of the DER.
