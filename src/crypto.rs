use crate::bip32::Bip32Path;
use crate::tx::{self, encoding};
use crate::AppSW;
use ledger_device_sdk::ecc::{Secp256k1, SeedDerive};
use ledger_device_sdk::hash::{ripemd::Ripemd160, sha2::Sha2_256, HashInit};

pub const PUBKEY_LEN: usize = 33;
pub const SIGNATURE_LEN: usize = 64;

/// The secp256k1 group order's upper half, `(n - 1) / 2`.
const HALF_ORDER: [u8; 32] = [
    0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0x5d, 0x57, 0x6e, 0x73, 0x57, 0xa4, 0x50, 0x1d, 0xdf, 0xe9, 0x2f, 0x46, 0x68, 0x1b, 0x20, 0xa0,
];
const ORDER: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
    0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41,
];

/// SHA-256 through the SDK.
///
/// A failing hash update means the SDK context is corrupt; there is no safe
/// way to continue, so it panics, which exits the app.
pub struct DeviceSha256(Sha2_256);

impl tx::Sha256 for DeviceSha256 {
    fn new() -> Self {
        DeviceSha256(Sha2_256::new())
    }
    fn update(&mut self, data: &[u8]) {
        if self.0.update(data).is_err() {
            panic!("sha256 update");
        }
    }
    fn finalize(mut self) -> [u8; 32] {
        let mut out = [0u8; 32];
        if self.0.finalize(&mut out).is_err() {
            panic!("sha256 finalize");
        }
        out
    }
}

pub struct DeviceHashes;

impl tx::Hashes for DeviceHashes {
    type Sha256 = DeviceSha256;
    fn hash160(data: &[u8]) -> [u8; 20] {
        let mut sha = [0u8; 32];
        let mut out = [0u8; 20];
        if Sha2_256::new().hash(data, &mut sha).is_err()
            || Ripemd160::new().hash(&sha, &mut out).is_err()
        {
            panic!("hash160");
        }
        out
    }
}

/// Derives the 33-byte compressed public key for `path`.
pub fn public_key(path: &Bip32Path) -> Result<[u8; PUBKEY_LEN], AppSW> {
    let key = Secp256k1::derive_from_path(path.as_ref());
    let point = key.public_key().map_err(|_| AppSW::KeyDeriveFail)?.pubkey;
    let mut compressed = [0u8; PUBKEY_LEN];
    compressed[0] = 0x02 | (point[64] & 1);
    compressed[1..].copy_from_slice(&point[1..33]);
    Ok(compressed)
}

/// The `g1...` address of a compressed public key.
pub fn address(pubkey: &[u8; PUBKEY_LEN]) -> [u8; encoding::ADDRESS_LEN] {
    use tx::Hashes;
    encoding::encode_address(&DeviceHashes::hash160(pubkey))
}

/// Signs a SHA-256 digest, returning tm2's 64-byte `R || S` with low S.
pub fn sign(path: &Bip32Path, digest: &[u8; 32]) -> Result<[u8; SIGNATURE_LEN], AppSW> {
    let (der, len, _) = Secp256k1::derive_from_path(path.as_ref())
        .deterministic_sign(digest)
        .map_err(|_| AppSW::TxSignFail)?;
    der_to_compact_low_s(der.get(..len as usize).ok_or(AppSW::TxSignFail)?)
}

/// Converts a DER ECDSA signature to `R || S`, normalising S to the lower half
/// of the group order as tm2's verifier requires.
fn der_to_compact_low_s(der: &[u8]) -> Result<[u8; SIGNATURE_LEN], AppSW> {
    fn integer(der: &[u8]) -> Result<(&[u8], &[u8]), AppSW> {
        match der {
            [0x02, len, rest @ ..] if (*len as usize) <= rest.len() => {
                Ok(rest.split_at(*len as usize))
            }
            _ => Err(AppSW::TxSignFail),
        }
    }
    fn to_32(int: &[u8], out: &mut [u8]) -> Result<(), AppSW> {
        let int = match int {
            [0x00, rest @ ..] => rest,
            _ => int,
        };
        if int.is_empty() || int.len() > 32 {
            return Err(AppSW::TxSignFail);
        }
        out[32 - int.len()..].copy_from_slice(int);
        Ok(())
    }

    let body = match der {
        [0x30, len, rest @ ..] if *len as usize == rest.len() => rest,
        _ => return Err(AppSW::TxSignFail),
    };
    let (r, rest) = integer(body)?;
    let (s, rest) = integer(rest)?;
    if !rest.is_empty() {
        return Err(AppSW::TxSignFail);
    }
    let mut sig = [0u8; SIGNATURE_LEN];
    to_32(r, &mut sig[..32])?;
    to_32(s, &mut sig[32..])?;
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
