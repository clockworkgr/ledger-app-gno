//! Conversion of SDK ECDSA signatures to the form tm2 verifies.
//!
//! No SDK dependency, so `host-tests` checks it on the host.

pub const SIGNATURE_LEN: usize = 64;

/// The secp256k1 group order `n`.
const ORDER: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
    0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41,
];
/// `(n - 1) / 2`, the largest S tm2 accepts.
const HALF_ORDER: [u8; 32] = [
    0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0x5d, 0x57, 0x6e, 0x73, 0x57, 0xa4, 0x50, 0x1d, 0xdf, 0xe9, 0x2f, 0x46, 0x68, 0x1b, 0x20, 0xa0,
];

#[derive(Debug, PartialEq, Eq)]
pub struct InvalidSignature;

/// Converts a DER ECDSA signature to `R || S`, normalising S to the lower half
/// of the group order as tm2's verifier requires.
///
/// Only strict DER is accepted: minimal positive integers, `0 < R, S < n`, and
/// no trailing bytes. Anything else means the signing call misbehaved.
pub fn der_to_compact_low_s(der: &[u8]) -> Result<[u8; SIGNATURE_LEN], InvalidSignature> {
    let body = match der {
        [0x30, len, rest @ ..] if *len < 0x80 && *len as usize == rest.len() => rest,
        _ => return Err(InvalidSignature),
    };
    let (r, rest) = integer(body)?;
    let (s, rest) = integer(rest)?;
    if !rest.is_empty() {
        return Err(InvalidSignature);
    }
    let mut sig = [0u8; SIGNATURE_LEN];
    sig[..32].copy_from_slice(&scalar(r)?);
    sig[32..].copy_from_slice(&scalar(s)?);
    if sig[32..] > HALF_ORDER[..] {
        let mut borrow = 0i16;
        for i in (0..32).rev() {
            let d = ORDER[i] as i16 - sig[32 + i] as i16 - borrow;
            borrow = (d < 0) as i16;
            sig[32 + i] = d.rem_euclid(256) as u8;
        }
    }
    Ok(sig)
}

/// Splits one DER INTEGER off the front, requiring minimal positive encoding.
fn integer(der: &[u8]) -> Result<(&[u8], &[u8]), InvalidSignature> {
    let (len, rest) = match der {
        [0x02, len, rest @ ..] if *len < 0x80 && (*len as usize) <= rest.len() => {
            (*len as usize, rest)
        }
        _ => return Err(InvalidSignature),
    };
    let (int, rest) = rest.split_at(len);
    match int {
        [] => return Err(InvalidSignature),
        // A leading zero is only allowed to clear the sign bit.
        [0x00, next, ..] if *next < 0x80 => return Err(InvalidSignature),
        [0x00] => return Err(InvalidSignature),
        [first, ..] if *first >= 0x80 => return Err(InvalidSignature),
        _ => {}
    }
    Ok((int, rest))
}

/// Left-pads a DER integer to 32 bytes and checks `0 < x < n`.
fn scalar(int: &[u8]) -> Result<[u8; 32], InvalidSignature> {
    let int = match int {
        [0x00, rest @ ..] => rest,
        _ => int,
    };
    if int.len() > 32 {
        return Err(InvalidSignature);
    }
    let mut out = [0u8; 32];
    out[32 - int.len()..].copy_from_slice(int);
    if out == [0u8; 32] || out >= ORDER {
        return Err(InvalidSignature);
    }
    Ok(out)
}
