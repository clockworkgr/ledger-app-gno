use crate::AppSW;

const HARDENED: u32 = 0x8000_0000;
const PURPOSE: u32 = 44 | HARDENED;
const COIN_TYPE: u32 = 118 | HARDENED;
pub const PATH_LEN: usize = 5;

/// A tm2 account path, `m/44'/118'/account'/0/index`.
///
/// Only this shape is accepted: it is what gnokey derives, and the app's
/// install parameters grant nothing outside `44'/118'`.
pub struct Bip32Path([u32; PATH_LEN]);

impl Bip32Path {
    /// `m/44'/118'/account'/0/index`. Both numbers must be below 2^31, as
    /// the APDU parser requires: the account is then hardened here.
    pub fn address(account: u32, index: u32) -> Result<Self, AppSW> {
        if account >= HARDENED || index >= HARDENED {
            return Err(AppSW::InvalidPath);
        }
        Ok(Bip32Path([
            PURPOSE,
            COIN_TYPE,
            account | HARDENED,
            0,
            index,
        ]))
    }
}

impl AsRef<[u32]> for Bip32Path {
    fn as_ref(&self) -> &[u32] {
        &self.0
    }
}

impl TryFrom<&[u8]> for Bip32Path {
    type Error = AppSW;

    /// Parses `[count=5][5 x u32 big-endian]`.
    fn try_from(data: &[u8]) -> Result<Self, Self::Error> {
        if data.len() != 1 + 4 * PATH_LEN || data[0] as usize != PATH_LEN {
            return Err(AppSW::WrongApduLength);
        }
        let mut path = [0u32; PATH_LEN];
        for (p, chunk) in path.iter_mut().zip(data[1..].chunks_exact(4)) {
            *p = u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        }
        let [purpose, coin, account, change, index] = path;
        if purpose != PURPOSE
            || coin != COIN_TYPE
            || account < HARDENED
            || change != 0
            || index >= HARDENED
        {
            return Err(AppSW::InvalidPath);
        }
        Ok(Bip32Path(path))
    }
}
