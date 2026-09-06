//! Deterministic no-panic fuzz for the certificate DER walk.
use tls_cbt::{extract_sig_alg_oid, tls_server_end_point};
fn xs(s: &mut u64) -> u64 {
    *s ^= *s << 13;
    *s ^= *s >> 7;
    *s ^= *s << 17;
    *s
}
#[test]
fn never_panics_on_hostile_input() {
    let mut s: u64 = 0xDEAD_BEEF_CAFE_1234;
    for _ in 0..100_000 {
        let n = (xs(&mut s) % 128) as usize;
        let b: Vec<u8> = (0..n).map(|_| (xs(&mut s) & 0xff) as u8).collect();
        let _ = extract_sig_alg_oid(&b);
        let _ = tls_server_end_point(&b);
    }
}
