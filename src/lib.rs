//! `tls-cbt` — RFC 5929 `tls-server-end-point` channel-binding tokens.
//!
//! The channel-binding data for `tls-server-end-point` is the hash of the
//! server's certificate, computed with the hash algorithm named by the
//! certificate's own `signatureAlgorithm` — except that MD5 and SHA-1 are
//! upgraded to SHA-256 (RFC 5929 §4.1). This crate does exactly that, with a
//! tiny inline DER walk to read the signature-algorithm OID (no full X.509
//! parser dependency).
//!
//! It does **not** wrap the hash into a GSS `gss_channel_bindings_struct` or
//! the NTLM `MsvAvChannelBindings` MD5 — that framing belongs to the consumer
//! (e.g. an NTLM/SASL layer). This crate produces the cert hash, which is the
//! `tls-server-end-point` cb-data.
//!
//! ```no_run
//! // `cert_der` is the server leaf certificate in DER form (e.g. from the
//! // TLS handshake's peer-certificate).
//! # let cert_der: &[u8] = &[];
//! let cb = tls_cbt::tls_server_end_point(cert_der).unwrap();
//! // `cb` is the 32/48/64-byte hash; prefix with "tls-server-end-point:" for
//! // the SASL/GSS application-data field.
//! ```
#![deny(missing_docs)]

use sha2::{Digest, Sha256, Sha384, Sha512};

/// The hash chosen for the channel binding.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CbHash {
    /// SHA-256 — the RFC 5929 fallback and the modern default.
    Sha256,
    /// SHA-384 — chosen when the cert's signature algorithm is a 384-bit family.
    Sha384,
    /// SHA-512 — chosen when the cert's signature algorithm is a 512-bit family.
    Sha512,
}

/// A malformed certificate encoding.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Error(pub &'static str);

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "tls-cbt: {}", self.0)
    }
}

impl std::error::Error for Error {}

/// Compute the RFC 5929 `tls-server-end-point` channel-binding hash of a
/// DER-encoded server certificate.
pub fn tls_server_end_point(cert_der: &[u8]) -> Result<Vec<u8>, Error> {
    let oid = extract_sig_alg_oid(cert_der)?;
    Ok(match hash_for_sig_alg(&oid) {
        CbHash::Sha256 => Sha256::digest(cert_der).to_vec(),
        CbHash::Sha384 => Sha384::digest(cert_der).to_vec(),
        CbHash::Sha512 => Sha512::digest(cert_der).to_vec(),
    })
}

/// Map a certificate `signatureAlgorithm` OID to the channel-binding hash.
/// MD5 / SHA-1 (and anything unrecognized) map to SHA-256 per RFC 5929 §4.1.
pub fn hash_for_sig_alg(oid: &[u32]) -> CbHash {
    // RSA PKCS#1: 1.2.840.113549.1.1.{11,12,13} = sha{256,384,512}WithRSA.
    // ECDSA:      1.2.840.10045.4.3.{2,3,4}      = ecdsa-with-SHA{256,384,512}.
    const RSA: [u32; 6] = [1, 2, 840, 113549, 1, 1];
    const ECDSA: [u32; 6] = [1, 2, 840, 10045, 4, 3];
    if oid.len() == 7 && oid[..6] == RSA {
        match oid[6] {
            12 => return CbHash::Sha384,
            13 => return CbHash::Sha512,
            _ => return CbHash::Sha256, // 11 = sha256; 4/5 = md5/sha1 → sha256
        }
    }
    if oid.len() == 7 && oid[..6] == ECDSA {
        match oid[6] {
            3 => return CbHash::Sha384,
            4 => return CbHash::Sha512,
            _ => return CbHash::Sha256,
        }
    }
    CbHash::Sha256
}

/// Read `Certificate.signatureAlgorithm.algorithm` (the OID) from a DER cert.
///
/// `Certificate ::= SEQUENCE { tbsCertificate SEQUENCE, signatureAlgorithm
/// SEQUENCE { algorithm OID, .. }, signatureValue BIT STRING }` — so we take
/// the outer SEQUENCE, skip element 1 (tbs), and read the OID at the head of
/// element 2.
pub fn extract_sig_alg_oid(cert_der: &[u8]) -> Result<Vec<u32>, Error> {
    let (tag, body, _) = read_tlv(cert_der, 0)?;
    if tag != 0x30 {
        return Err(Error("certificate is not a SEQUENCE"));
    }
    // element 1: tbsCertificate — skip.
    let (_t1, _c1, after_tbs) = read_tlv(body, 0)?;
    // element 2: signatureAlgorithm SEQUENCE.
    let (t2, sig_alg, _after) = read_tlv(body, after_tbs)?;
    if t2 != 0x30 {
        return Err(Error("signatureAlgorithm is not a SEQUENCE"));
    }
    // first field: algorithm OID.
    let (t_oid, oid_content, _) = read_tlv(sig_alg, 0)?;
    if t_oid != 0x06 {
        return Err(Error("signatureAlgorithm.algorithm is not an OID"));
    }
    decode_oid(oid_content)
}

/// Read one DER TLV at `off` in `buf`. Returns `(tag, content, next_off)`.
fn read_tlv(buf: &[u8], off: usize) -> Result<(u8, &[u8], usize), Error> {
    let tag = *buf.get(off).ok_or(Error("truncated tag"))?;
    let (len, len_end) = read_len(buf, off + 1)?;
    let content_end = len_end.checked_add(len).ok_or(Error("length overflow"))?;
    if content_end > buf.len() {
        return Err(Error("content past buffer"));
    }
    Ok((tag, &buf[len_end..content_end], content_end))
}

fn read_len(buf: &[u8], off: usize) -> Result<(usize, usize), Error> {
    let first = *buf.get(off).ok_or(Error("truncated length"))?;
    if first < 0x80 {
        return Ok((first as usize, off + 1));
    }
    let n = (first & 0x7F) as usize;
    if n == 0 || n > 4 {
        return Err(Error("unsupported DER length form"));
    }
    let mut len = 0usize;
    let mut i = off + 1;
    for _ in 0..n {
        len = (len << 8) | *buf.get(i).ok_or(Error("truncated length octets"))? as usize;
        i += 1;
    }
    Ok((len, i))
}

fn decode_oid(content: &[u8]) -> Result<Vec<u32>, Error> {
    if content.is_empty() {
        return Err(Error("empty OID"));
    }
    let mut out = Vec::new();
    let first = content[0] as u32;
    out.push(first / 40);
    out.push(first % 40);
    let mut i = 1;
    while i < content.len() {
        let mut v: u64 = 0;
        loop {
            let b = *content.get(i).ok_or(Error("truncated OID subid"))?;
            i += 1;
            v = (v << 7) | (b & 0x7F) as u64;
            if v > u32::MAX as u64 {
                return Err(Error("OID subid overflows u32"));
            }
            if b & 0x80 == 0 {
                break;
            }
        }
        out.push(v as u32);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Minimal DER helpers for building a certificate-shaped fixture.
    fn der(tag: u8, content: &[u8]) -> Vec<u8> {
        let mut out = vec![tag];
        if content.len() < 0x80 {
            out.push(content.len() as u8);
        } else {
            let mut b = Vec::new();
            let mut v = content.len();
            while v > 0 {
                b.push((v & 0xFF) as u8);
                v >>= 8;
            }
            b.reverse();
            out.push(0x80 | b.len() as u8);
            out.extend_from_slice(&b);
        }
        out.extend_from_slice(content);
        out
    }

    fn oid_der(oid: &[u32]) -> Vec<u8> {
        let mut c = vec![(oid[0] * 40 + oid[1]) as u8];
        for &sub in &oid[2..] {
            let mut tmp = Vec::new();
            let mut v = sub;
            tmp.push((v & 0x7F) as u8);
            v >>= 7;
            while v > 0 {
                tmp.push(((v & 0x7F) as u8) | 0x80);
                v >>= 7;
            }
            tmp.reverse();
            c.extend_from_slice(&tmp);
        }
        der(0x06, &c)
    }

    fn cert_with_sig_alg(oid: &[u32]) -> Vec<u8> {
        let tbs = der(0x30, &der(0x02, &[0x01])); // dummy tbs
        let sig_alg = der(0x30, &oid_der(oid));
        let sig_val = der(0x03, &[0x00, 0xAB, 0xCD]); // dummy BIT STRING
        let mut body = tbs;
        body.extend_from_slice(&sig_alg);
        body.extend_from_slice(&sig_val);
        der(0x30, &body)
    }

    #[test]
    fn extracts_rsa_sha256_oid() {
        let cert = cert_with_sig_alg(&[1, 2, 840, 113549, 1, 1, 11]);
        assert_eq!(
            extract_sig_alg_oid(&cert).unwrap(),
            vec![1, 2, 840, 113549, 1, 1, 11]
        );
        assert_eq!(
            hash_for_sig_alg(&[1, 2, 840, 113549, 1, 1, 11]),
            CbHash::Sha256
        );
    }

    #[test]
    fn sha384_and_sha512_selected() {
        assert_eq!(
            hash_for_sig_alg(&[1, 2, 840, 113549, 1, 1, 12]),
            CbHash::Sha384
        );
        assert_eq!(
            hash_for_sig_alg(&[1, 2, 840, 113549, 1, 1, 13]),
            CbHash::Sha512
        );
        assert_eq!(
            hash_for_sig_alg(&[1, 2, 840, 10045, 4, 3, 3]),
            CbHash::Sha384
        );
    }

    #[test]
    fn sha1_and_unknown_map_to_sha256() {
        assert_eq!(
            hash_for_sig_alg(&[1, 2, 840, 113549, 1, 1, 5]),
            CbHash::Sha256
        ); // sha1WithRSA
        assert_eq!(hash_for_sig_alg(&[9, 9, 9]), CbHash::Sha256); // unknown
    }

    #[test]
    fn end_point_hash_is_sha256_of_whole_cert() {
        let cert = cert_with_sig_alg(&[1, 2, 840, 113549, 1, 1, 11]);
        let cb = tls_server_end_point(&cert).unwrap();
        assert_eq!(cb.len(), 32);
        assert_eq!(cb, Sha256::digest(&cert).to_vec());
    }

    #[test]
    fn end_point_hash_is_sha512_for_sha512_cert() {
        let cert = cert_with_sig_alg(&[1, 2, 840, 113549, 1, 1, 13]);
        let cb = tls_server_end_point(&cert).unwrap();
        assert_eq!(cb.len(), 64);
    }

    #[test]
    fn malformed_certs_err() {
        assert!(extract_sig_alg_oid(&[]).is_err());
        assert!(extract_sig_alg_oid(&[0x02, 0x01, 0x00]).is_err()); // not a SEQUENCE
        assert!(extract_sig_alg_oid(&[0x30, 0x7F, 0x00]).is_err()); // len past buffer
    }
}
