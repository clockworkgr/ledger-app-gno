/*****************************************************************************
 *   Ledger App Gno.
 *   Derived from Ledger App Boilerplate Rust, (c) 2023 Ledger SAS.
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

#![no_std]
#![no_main]

mod app_ui;
mod bip32;
mod crypto;
mod handlers {
    pub mod get_public_key;
    pub mod get_version;
    pub mod sign_tx;
}
mod settings;
mod sig;
mod tx;

use app_ui::menu::ui_menu_main;
use handlers::{
    get_public_key::handler_get_public_key,
    get_version::handler_get_version,
    sign_tx::{handler_sign_tx, TxContext},
};
use ledger_device_sdk::io::{self, init_comm, ApduHeader, Comm, Command, Reply, StatusWords};
use ledger_device_sdk::nbgl::{NbglReviewStatus, StatusType};

ledger_device_sdk::set_panic!(ledger_device_sdk::exiting_panic);

extern crate alloc;

ledger_device_sdk::define_comm!(COMM);

const APP_NAME: &str = "Gno";

const CLA: u8 = 0xe0;
const INS_GET_VERSION: u8 = 0x03;
const INS_GET_APP_NAME: u8 = 0x04;
const INS_GET_PUBLIC_KEY: u8 = 0x05;
const INS_SIGN_TX: u8 = 0x06;

const P1_PUBKEY_SILENT: u8 = 0x00;
const P1_PUBKEY_DISPLAY: u8 = 0x01;
const P1_SIGN_TX_FIRST: u8 = 0x00;
const P1_SIGN_TX_NEXT: u8 = 0x01;
const P2_SIGN_TX_LAST: u8 = 0x00;
const P2_SIGN_TX_MORE: u8 = 0x80;

/// Status words returned over the wire. docs/APDU.md lists the same values.
#[repr(u16)]
#[derive(Clone, Copy, PartialEq)]
pub enum AppSW {
    Deny = 0x6985,
    WrongP1P2 = 0x6A86,
    InsNotSupported = 0x6D00,
    ClaNotSupported = 0x6E00,
    CommError = 0x6F00,
    AddrDisplayFail = 0xB002,
    TxParsingFail = 0xB005,
    TxSignFail = 0xB008,
    KeyDeriveFail = 0xB009,
    VersionParsingFail = 0xB00A,
    InvalidPath = 0xB00B,
    TxNoSession = 0xB00C,
    TxWrongSigner = 0xB00D,
    TxTooLarge = 0xB00E,
    PackageTxDisabled = 0xB00F,
    WrongApduLength = StatusWords::BadLen as u16,
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

/// Possible input commands received through APDUs.
#[derive(Debug)]
pub enum Instruction {
    GetVersion,
    GetAppName,
    GetPubkey { display: bool },
    SignTx { first: bool, more: bool },
}

impl TryFrom<ApduHeader> for Instruction {
    type Error = AppSW;

    /// Validates CLA, INS, P1 and P2; handlers receive only well-formed
    /// commands. CLA is checked here rather than by the SDK so that a wrong
    /// one, like any malformed header, also closes an open signing session.
    fn try_from(value: ApduHeader) -> Result<Self, Self::Error> {
        if value.cla != CLA {
            return Err(AppSW::ClaNotSupported);
        }
        match (value.ins, value.p1, value.p2) {
            (INS_GET_VERSION, 0, 0) => Ok(Instruction::GetVersion),
            (INS_GET_APP_NAME, 0, 0) => Ok(Instruction::GetAppName),
            (INS_GET_PUBLIC_KEY, P1_PUBKEY_SILENT, 0) => {
                Ok(Instruction::GetPubkey { display: false })
            }
            (INS_GET_PUBLIC_KEY, P1_PUBKEY_DISPLAY, 0) => {
                Ok(Instruction::GetPubkey { display: true })
            }
            // The path chunk opens a session, so a payload always follows it.
            (INS_SIGN_TX, P1_SIGN_TX_FIRST, P2_SIGN_TX_MORE) => Ok(Instruction::SignTx {
                first: true,
                more: true,
            }),
            (INS_SIGN_TX, P1_SIGN_TX_NEXT, P2_SIGN_TX_MORE) => Ok(Instruction::SignTx {
                first: false,
                more: true,
            }),
            (INS_SIGN_TX, P1_SIGN_TX_NEXT, P2_SIGN_TX_LAST) => Ok(Instruction::SignTx {
                first: false,
                more: false,
            }),
            (INS_GET_VERSION | INS_GET_APP_NAME | INS_GET_PUBLIC_KEY | INS_SIGN_TX, _, _) => {
                Err(AppSW::WrongP1P2)
            }
            (_, _, _) => Err(AppSW::InsNotSupported),
        }
    }
}

fn show_status_and_home_if_needed(
    comm: &mut Comm,
    ins: &Instruction,
    tx_ctx: &mut TxContext,
    status: &AppSW,
) {
    let (show_status, status_type) = match (ins, status) {
        (Instruction::GetPubkey { display: true }, AppSW::Deny | AppSW::Ok) => {
            (true, StatusType::Address)
        }
        (Instruction::SignTx { .. }, AppSW::Deny | AppSW::Ok) if tx_ctx.finished() => {
            (true, StatusType::Transaction)
        }
        (Instruction::SignTx { .. }, AppSW::PackageTxDisabled) => {
            tx_ctx.home.show_and_return();
            return;
        }
        (_, _) => (false, StatusType::Transaction),
    };

    if show_status {
        let success = *status == AppSW::Ok;
        NbglReviewStatus::new()
            .status_type(status_type)
            .show(comm, success);
        tx_ctx.home.show_and_return();
    }
}

#[no_mangle]
extern "C" fn sample_main(_arg0: u32) {
    let comm = init_comm(&COMM);

    let mut tx_ctx = TxContext::new();
    tx_ctx.home = ui_menu_main(comm);
    tx_ctx.home.show_and_return();

    loop {
        let command = comm.next_command();
        let decoded = command.decode::<Instruction>();
        // A signing session survives only its own chunks: any malformed or
        // unrelated command closes it, so the host must start over.
        let Ok(ins) = decoded else {
            tx_ctx.close_session();
            let _ = comm.send(&[], decoded.unwrap_err());
            continue;
        };
        if !matches!(ins, Instruction::SignTx { .. }) {
            tx_ctx.close_session();
        }

        let status = match handle_apdu(command, &ins, &mut tx_ctx) {
            Ok(reply) => {
                let _ = reply.send(AppSW::Ok);
                AppSW::Ok
            }
            Err(sw) => {
                let _ = comm.send(&[], sw);
                sw
            }
        };
        show_status_and_home_if_needed(comm, &ins, &mut tx_ctx, &status);
    }
}

fn handle_apdu<'a>(
    command: Command<'a>,
    ins: &Instruction,
    ctx: &mut TxContext,
) -> Result<io::CommandResponse<'a>, AppSW> {
    match ins {
        Instruction::GetAppName => {
            if !command.get_data().is_empty() {
                return Err(AppSW::WrongApduLength);
            }
            let mut response = command.into_response();
            response.append(APP_NAME.as_bytes())?;
            Ok(response)
        }
        Instruction::GetVersion => handler_get_version(command),
        Instruction::GetPubkey { display } => handler_get_public_key(command, *display),
        Instruction::SignTx { first, more } => handler_sign_tx(command, *first, *more, ctx),
    }
}
