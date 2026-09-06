# tls-cbt

RFC 5929 **`tls-server-end-point`** channel-binding tokens for Rust.

The channel-binding data is the hash of the server's certificate, taken with
the hash from the certificate's own `signatureAlgorithm` — with MD5 and SHA-1
upgraded to SHA-256 (RFC 5929 §4.1). `tls-cbt` computes exactly that, using a
tiny inline DER walk to read the signature-algorithm OID, so it needs **no
X.509 parser** — only `sha2`.

Useful for any client that must present channel bindings to an EPA-enforcing
server (LDAPS, HTTPS, SASL/GSS) — for example, deriving the value an NTLM
`MsvAvChannelBindings` or a SASL `gs2-cb` field wraps.

## Scope

- **In:** given a DER server certificate → the `tls-server-end-point` hash.
- **Out:** GSS `gss_channel_bindings_struct` framing and the NTLM
  `MsvAvChannelBindings` MD5 — those belong to the consuming auth layer. This
  crate returns the cert hash; the caller wraps it.

## Example

```rust
let cb = tls_cbt::tls_server_end_point(cert_der)?;
// prefix with "tls-server-end-point:" for the SASL/GSS application-data field.
# Ok::<(), tls_cbt::Error>(())
```

## Validation

- **Property-fuzzed**: `tests/fuzz.rs` throws 100k random inputs at the DER
  walk — it never panics.
- **Windows reference**: validated against a live Windows Server 2025 domain
  controller's LDAPS certificate — the extracted signature-algorithm OID and
  the `tls-server-end-point` hash **byte-match** the Windows-computed reference.

## Status

`0.x` — unstable API. Recognizes the common RSA-PKCS#1 and ECDSA signature
OIDs; everything else falls back to SHA-256 per the RFC.

## License

MIT.
