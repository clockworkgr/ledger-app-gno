//! Compiles the device's transaction parser for the host.
//!
//! The modules are included by path rather than through a library crate, so
//! the device binary keeps a single source of truth and needs no workspace.

extern crate alloc;

#[path = "../../src/tx/mod.rs"]
pub mod tx;

use sha2::Digest;

pub struct HostSha256(sha2::Sha256);

impl tx::Sha256 for HostSha256 {
    fn new() -> Self {
        HostSha256(sha2::Sha256::new())
    }
    fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }
    fn finalize(self) -> [u8; 32] {
        self.0.finalize().into()
    }
}

pub struct HostHashes;

impl tx::Hashes for HostHashes {
    type Sha256 = HostSha256;
    fn hash160(data: &[u8]) -> [u8; 20] {
        ripemd::Ripemd160::digest(sha2::Sha256::digest(data)).into()
    }
}
