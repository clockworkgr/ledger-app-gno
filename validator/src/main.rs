/*****************************************************************************
 *   Ledger App Gno Validator.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *****************************************************************************/

//! Benchmark build of the gno validator signer: measures Ed25519 signing on
//! the device. It signs any message without confirmation, so it uses a key
//! reserved for benchmarking, never the one a validator will run with.

#![no_std]
#![no_main]

use ledger_device_sdk::ecc::{CxError, ECPrivateKey, Ed25519};
use ledger_device_sdk::include_gif;
use ledger_device_sdk::io::{self, init_comm, ApduHeader, Command, CommandResponse, Reply};
use ledger_device_sdk::nbgl::{NbglGlyph, NbglHomeAndSettings};
use ledger_device_sdk::sys::{cx_edwards_compress_point_no_throw, CX_CURVE_Ed25519, CX_OK};

ledger_device_sdk::set_panic!(ledger_device_sdk::exiting_panic);

ledger_device_sdk::define_comm!(COMM);

const APP_NAME: &str = "Gno Validator";

#[cfg(target_os = "apex_p")]
const HOME_GLYPH: NbglGlyph =
    NbglGlyph::from_include(include_gif!("../glyphs/gno_48x48.png", NBGL));
#[cfg(any(target_os = "stax", target_os = "flex"))]
const HOME_GLYPH: NbglGlyph =
    NbglGlyph::from_include(include_gif!("../glyphs/gno_64x64.gif", NBGL));
#[cfg(any(target_os = "nanosplus", target_os = "nanox"))]
const HOME_GLYPH: NbglGlyph = NbglGlyph::from_include(include_gif!("../icons/gno_14x14.gif", NBGL));

const HARDENED: u32 = 0x8000_0000;
/// SLIP-10 needs every level hardened. Account 9999' keeps the benchmark key
/// apart from any key a validator will use.
const BENCH_PATH: [u32; 5] = [
    44 | HARDENED,
    118 | HARDENED,
    9999 | HARDENED,
    HARDENED,
    HARDENED,
];

const CLA: u8 = 0xe0;
const INS_GET_VERSION: u8 = 0x03;
const INS_GET_APP_NAME: u8 = 0x04;
const INS_GET_PUBLIC_KEY: u8 = 0x05;
const INS_SIGN: u8 = 0x10;
const INS_BENCH: u8 = 0x7f;

const KEY_DERIVE: u8 = 0x00;
const KEY_CACHED: u8 = 0x01;

#[repr(u16)]
#[derive(Clone, Copy)]
enum AppSW {
    WrongP1P2 = 0x6A86,
    InsNotSupported = 0x6D00,
    ClaNotSupported = 0x6E00,
    WrongApduLength = 0x6E03,
    CommError = 0x6F00,
    SignFail = 0xB008,
    KeyDeriveFail = 0xB009,
    VersionParsingFail = 0xB00A,
    Ok = 0x9000,
}

impl From<AppSW> for Reply {
    fn from(sw: AppSW) -> Reply {
        Reply(sw as u16)
    }
}

impl From<io::CommError> for AppSW {
    fn from(_e: io::CommError) -> Self {
        AppSW::CommError
    }
}

enum Instruction {
    GetVersion,
    GetAppName,
    GetPubkey,
    /// Signs the APDU data once.
    Sign {
        cached: bool,
    },
    /// Signs the APDU data `iterations` times and returns the last signature,
    /// so the host can time signing without USB round trips.
    Bench {
        iterations: u8,
        cached: bool,
    },
}

impl TryFrom<ApduHeader> for Instruction {
    type Error = AppSW;

    fn try_from(h: ApduHeader) -> Result<Self, Self::Error> {
        if h.cla != CLA {
            return Err(AppSW::ClaNotSupported);
        }
        match (h.ins, h.p1, h.p2) {
            (INS_GET_VERSION, 0, 0) => Ok(Instruction::GetVersion),
            (INS_GET_APP_NAME, 0, 0) => Ok(Instruction::GetAppName),
            (INS_GET_PUBLIC_KEY, 0, 0) => Ok(Instruction::GetPubkey),
            (INS_SIGN, KEY_DERIVE | KEY_CACHED, 0) => Ok(Instruction::Sign {
                cached: h.p1 == KEY_CACHED,
            }),
            (INS_BENCH, 1..=u8::MAX, KEY_DERIVE | KEY_CACHED) => Ok(Instruction::Bench {
                iterations: h.p1,
                cached: h.p2 == KEY_CACHED,
            }),
            (
                INS_GET_VERSION | INS_GET_APP_NAME | INS_GET_PUBLIC_KEY | INS_SIGN | INS_BENCH,
                _,
                _,
            ) => Err(AppSW::WrongP1P2),
            (_, _, _) => Err(AppSW::InsNotSupported),
        }
    }
}

/// The benchmark key, derived on demand or kept for `KEY_CACHED` requests.
struct Signer {
    cached: Option<ECPrivateKey<32, 'E'>>,
}

impl Signer {
    fn derive() -> ECPrivateKey<32, 'E'> {
        Ed25519::derive_from_path_slip10(&BENCH_PATH)
    }

    fn sign(&mut self, msg: &[u8], cached: bool) -> Result<[u8; 64], AppSW> {
        let sign = |key: &ECPrivateKey<32, 'E'>| {
            key.sign(msg)
                .map(|(sig, _)| sig)
                .map_err(|_| AppSW::SignFail)
        };
        match cached {
            true => sign(self.cached.get_or_insert_with(Self::derive)),
            false => sign(&Self::derive()),
        }
    }
}

fn public_key() -> Result<[u8; 32], CxError> {
    let mut pk = Signer::derive().public_key()?;
    // SAFETY: `pk.pubkey` holds the uncompressed point the SDK just computed,
    // `keylength` bytes long, and is compressed in place.
    let err = unsafe {
        cx_edwards_compress_point_no_throw(CX_CURVE_Ed25519, pk.pubkey.as_mut_ptr(), pk.keylength)
    };
    if err != CX_OK {
        return Err(err.into());
    }
    // The compressed point follows a format byte.
    let mut out = [0u8; 32];
    out.copy_from_slice(&pk.pubkey[1..33]);
    Ok(out)
}

fn version() -> Option<[u8; 3]> {
    let mut parts = env!("CARGO_PKG_VERSION").split('.');
    let mut out = [0u8; 3];
    for b in out.iter_mut() {
        *b = parts.next()?.parse().ok()?;
    }
    Some(out)
}

fn handle<'a>(
    command: Command<'a>,
    ins: Instruction,
    signer: &mut Signer,
) -> Result<CommandResponse<'a>, AppSW> {
    let data = command.get_data();
    let mut out = [0u8; 64];
    let reply: &[u8] = match ins {
        Instruction::GetVersion | Instruction::GetAppName | Instruction::GetPubkey
            if !data.is_empty() =>
        {
            return Err(AppSW::WrongApduLength);
        }
        Instruction::GetVersion => {
            out[..3].copy_from_slice(&version().ok_or(AppSW::VersionParsingFail)?);
            &out[..3]
        }
        Instruction::GetAppName => APP_NAME.as_bytes(),
        Instruction::GetPubkey => {
            out[..32].copy_from_slice(&public_key().map_err(|_| AppSW::KeyDeriveFail)?);
            &out[..32]
        }
        Instruction::Sign { .. } | Instruction::Bench { .. } if data.is_empty() => {
            return Err(AppSW::WrongApduLength);
        }
        Instruction::Sign { cached } => {
            out = signer.sign(data, cached)?;
            &out
        }
        Instruction::Bench { iterations, cached } => {
            for _ in 0..iterations {
                out = signer.sign(data, cached)?;
            }
            &out
        }
    };
    let mut response = command.into_response();
    response.append(reply)?;
    Ok(response)
}

#[no_mangle]
extern "C" fn sample_main(_arg0: u32) {
    let comm = init_comm(&COMM);
    let mut signer = Signer { cached: None };

    // Kept alive for as long as NBGL shows it.
    let mut home = NbglHomeAndSettings::new()
        .glyph(&HOME_GLYPH)
        .tagline("Benchmark build")
        .infos(
            APP_NAME,
            env!("CARGO_PKG_VERSION"),
            env!("CARGO_PKG_AUTHORS"),
        );
    home.show_and_return();

    loop {
        let command = comm.next_command();
        let ins = match command.decode::<Instruction>() {
            Ok(ins) => ins,
            Err(sw) => {
                let _ = comm.send(&[], sw);
                continue;
            }
        };
        match handle(command, ins, &mut signer) {
            Ok(reply) => {
                let _ = reply.send(AppSW::Ok);
            }
            Err(sw) => {
                let _ = comm.send(&[], sw);
            }
        }
    }
}
