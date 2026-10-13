use crate::app_ui::sign::{ui_display_package_disabled, ui_display_tx};
use crate::bip32::Bip32Path;
use crate::crypto::{self, DeviceHashes, DeviceSha256};
use crate::settings::{Settings, SETTING_PACKAGE_TX};
use crate::tx::{self, Parser, Sha256};
use crate::AppSW;
use alloc::boxed::Box;
use ledger_device_sdk::io::{Command, CommandResponse};
use ledger_device_sdk::log;
use ledger_device_sdk::nbgl::NbglHomeAndSettings;

/// A signing session, open from the path chunk until the last chunk.
struct Session {
    path: Bip32Path,
    parser: Parser<DeviceHashes>,
    /// Digest of the payload, which is what gets signed.
    digest: DeviceSha256,
}

pub struct TxContext {
    /// Boxed so the parser lives on the heap while parsing and is freed before
    /// the review: Nano X has too little stack for it next to NBGL.
    session: Option<Box<Session>>,
    review_finished: bool,
    pub home: NbglHomeAndSettings,
}

impl TxContext {
    pub fn new() -> TxContext {
        TxContext {
            session: None,
            review_finished: false,
            home: Default::default(),
        }
    }

    pub fn finished(&self) -> bool {
        self.review_finished
    }
}

fn parse_error(e: tx::Error) -> AppSW {
    log::debug!("sign doc rejected: {:?}", e);
    match e {
        tx::Error::SignerMismatch => AppSW::TxWrongSigner,
        tx::Error::ValueTooLong | tx::Error::ReviewTooLarge | tx::Error::TooManyMessages => {
            AppSW::TxTooLarge
        }
        _ => AppSW::TxParsingFail,
    }
}

/// Handles one SIGN_TX chunk.
///
/// The first chunk carries the derivation path and opens a session; every
/// later chunk is hashed and parsed as it arrives, so the payload is never
/// held in memory. Any error closes the session: a host that wants to retry
/// starts again from the path chunk.
pub fn handler_sign_tx<'a>(
    command: Command<'a>,
    first: bool,
    more: bool,
    ctx: &mut TxContext,
) -> Result<CommandResponse<'a>, AppSW> {
    ctx.review_finished = false;
    if first {
        ctx.session = None;
        let path: Bip32Path = command.get_data().try_into()?;
        let signer = crypto::address(&crypto::public_key(&path)?);
        ctx.session = Some(Box::new(Session {
            path,
            parser: Parser::new(signer),
            digest: DeviceSha256::new(),
        }));
        return Ok(command.into_response());
    }

    let mut session = ctx.session.take().ok_or(AppSW::TxNoSession)?;
    let data = command.get_data();
    session.digest.update(data);
    session.parser.feed(data).map_err(parse_error)?;
    if more {
        ctx.session = Some(session);
        return Ok(command.into_response());
    }

    let review = session.parser.finish().map_err(parse_error)?;
    // The rest of the session, parser included, is freed at the end of the block.
    let (path, digest) = {
        let session = session;
        (session.path, session.digest.finalize())
    };
    let comm = command.into_comm();
    ctx.review_finished = true;

    if review.blind && Settings.get_element(SETTING_PACKAGE_TX) == 0 {
        ui_display_package_disabled(comm);
        return Err(AppSW::PackageTxDisabled);
    }
    if !ui_display_tx(comm, &review)? {
        return Err(AppSW::Deny);
    }
    let signature = crypto::sign(&path, &digest)?;
    let mut response = comm.begin_response();
    response.append(&signature)?;
    Ok(response)
}
