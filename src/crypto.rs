use crate::bip32::Bip32Path;
use crate::sig;
use crate::tx::{self, encoding};
use crate::AppSW;
use ledger_device_sdk::ecc::{Secp256k1, SeedDerive};
use ledger_device_sdk::hash::{ripemd::Ripemd160, sha2::Sha2_256, HashInit};

pub const PUBKEY_LEN: usize = 33;
use crate::sig::SIGNATURE_LEN;

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
    let der = der.get(..len as usize).ok_or(AppSW::TxSignFail)?;
    sig::der_to_compact_low_s(der).map_err(|_| AppSW::TxSignFail)
}
