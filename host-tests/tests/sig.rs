use host_tests::sig::{der_to_compact_low_s, InvalidSignature};

const N: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
    0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41,
];
const HALF: [u8; 32] = [
    0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0x5d, 0x57, 0x6e, 0x73, 0x57, 0xa4, 0x50, 0x1d, 0xdf, 0xe9, 0x2f, 0x46, 0x68, 0x1b, 0x20, 0xa0,
];

/// Minimal DER INTEGER for a big-endian unsigned value.
fn int(v: &[u8]) -> Vec<u8> {
    let mut v: Vec<u8> = v.iter().copied().skip_while(|&b| b == 0).collect();
    if v.is_empty() || v[0] >= 0x80 {
        v.insert(0, 0);
    }
    let mut out = vec![0x02, v.len() as u8];
    out.extend(v);
    out
}

fn der(r: &[u8], s: &[u8]) -> Vec<u8> {
    let body = [int(r), int(s)].concat();
    let mut out = vec![0x30, body.len() as u8];
    out.extend(body);
    out
}

fn add_one(mut v: [u8; 32]) -> [u8; 32] {
    for b in v.iter_mut().rev() {
        let (n, carry) = b.overflowing_add(1);
        *b = n;
        if !carry {
            break;
        }
    }
    v
}

#[test]
fn full_width_and_short_integers() {
    let r = [0x80u8; 32];
    let s = [0x11u8; 32];
    let sig = der_to_compact_low_s(&der(&r, &s)).unwrap();
    assert_eq!(&sig[..32], &r);
    assert_eq!(&sig[32..], &s);

    // Integers shorter than 32 bytes are left-padded.
    let sig = der_to_compact_low_s(&der(&[0x01, 0x02], &[0x7f])).unwrap();
    assert_eq!(sig[30..32], [0x01, 0x02]);
    assert!(sig[..30].iter().all(|&b| b == 0));
    assert_eq!(sig[63], 0x7f);
}

#[test]
fn s_is_normalised_to_the_lower_half() {
    let r = [0x01u8; 32];
    // S = (n-1)/2 is already low and stays as is.
    let sig = der_to_compact_low_s(&der(&r, &HALF)).unwrap();
    assert_eq!(&sig[32..], &HALF);
    // S = (n+1)/2 becomes n - S = (n-1)/2.
    let sig = der_to_compact_low_s(&der(&r, &add_one(HALF))).unwrap();
    assert_eq!(&sig[32..], &HALF);
    // S = n - 1 becomes 1.
    let mut n_minus_one = N;
    n_minus_one[31] -= 1;
    let sig = der_to_compact_low_s(&der(&r, &n_minus_one)).unwrap();
    assert_eq!(sig[63], 1);
    assert!(sig[32..63].iter().all(|&b| b == 0));
}

#[test]
fn rejects_anything_but_strict_der() {
    let r = [0x01u8; 32];
    let s = [0x02u8; 32];
    let good = der(&r, &s);
    let reject = |bytes: &[u8]| {
        assert_eq!(
            der_to_compact_low_s(bytes),
            Err(InvalidSignature),
            "{bytes:x?}"
        )
    };

    // Zero or out-of-range scalars.
    reject(&der(&[0], &s));
    reject(&der(&r, &[0]));
    reject(&der(&N, &s));
    reject(&der(&r, &N));
    // Non-minimal or negative integers.
    reject(&[0x30, 0x08, 0x02, 0x02, 0x00, 0x01, 0x02, 0x02, 0x00, 0x01]);
    reject(&[0x30, 0x06, 0x02, 0x01, 0x81, 0x02, 0x01, 0x01]);
    reject(&[0x30, 0x06, 0x02, 0x00, 0x02, 0x02, 0x01, 0x01]);
    // Framing: wrong lengths, trailing data, long-form length, wrong tags.
    let mut long = good.clone();
    long[1] += 1;
    reject(&long);
    let mut trailing = good.clone();
    trailing.push(0);
    reject(&trailing);
    let mut extra_int = good.clone();
    extra_int[1] += 3;
    extra_int.extend([0x02, 0x01, 0x01]);
    reject(&extra_int);
    reject(&[0x30, 0x81, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01]);
    let mut tag = good.clone();
    tag[0] = 0x31;
    reject(&tag);
    reject(&[]);
}
