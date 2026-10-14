//! Feeds arbitrary bytes to the DER-to-compact signature conversion.
//!
//! Anything accepted must be strict DER of an in-range (R, S), and the output
//! must carry the same R and the low form of S.

#![no_main]

use host_tests::sig::der_to_compact_low_s;
use libfuzzer_sys::fuzz_target;

const N: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
    0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41,
];
const HALF: [u8; 32] = [
    0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0x5d, 0x57, 0x6e, 0x73, 0x57, 0xa4, 0x50, 0x1d, 0xdf, 0xe9, 0x2f, 0x46, 0x68, 0x1b, 0x20, 0xa0,
];

fn sub_from_n(x: &[u8; 32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut borrow = 0i16;
    for i in (0..32).rev() {
        let d = N[i] as i16 - x[i] as i16 - borrow;
        borrow = (d < 0) as i16;
        out[i] = d.rem_euclid(256) as u8;
    }
    out
}

fn der_int(v: &[u8]) -> Vec<u8> {
    let mut v: Vec<u8> = v.iter().copied().skip_while(|&b| b == 0).collect();
    if v.is_empty() || v[0] >= 0x80 {
        v.insert(0, 0);
    }
    let mut out = vec![0x02, v.len() as u8];
    out.extend(v);
    out
}

fn der(r: &[u8], s: &[u8]) -> Vec<u8> {
    let body = [der_int(r), der_int(s)].concat();
    let mut out = vec![0x30, body.len() as u8];
    out.extend(body);
    out
}

fuzz_target!(|data: &[u8]| {
    let Ok(sig) = der_to_compact_low_s(data) else {
        return;
    };
    let r: [u8; 32] = sig[..32].try_into().unwrap();
    let s: [u8; 32] = sig[32..].try_into().unwrap();
    assert!(r != [0; 32] && r < N);
    assert!(s != [0; 32] && s <= HALF);
    // The input was the strict DER of (R, S) or (R, n - S).
    assert!(
        data == der(&r, &s).as_slice() || data == der(&r, &sub_from_n(&s)).as_slice(),
        "accepted non-strict DER"
    );
});
