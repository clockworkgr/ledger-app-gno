use crate::app_ui::address::ui_display_address;
use crate::bip32::Bip32Path;
use crate::crypto;
use crate::AppSW;
use ledger_device_sdk::io::{Command, CommandResponse};

/// Returns `[33][compressed pubkey][40][g1 address]`, optionally after the user
/// has confirmed the address on screen.
pub fn handler_get_public_key(
    command: Command<'_>,
    display: bool,
) -> Result<CommandResponse<'_>, AppSW> {
    let path: Bip32Path = command.get_data().try_into()?;
    let pubkey = crypto::public_key(&path)?;
    let address = crypto::address(&pubkey);

    let comm = command.into_comm();
    if display && !ui_display_address(comm, &address)? {
        return Err(AppSW::Deny);
    }

    let mut response = comm.begin_response();
    response.append(&[pubkey.len() as u8])?;
    response.append(&pubkey)?;
    response.append(&[address.len() as u8])?;
    response.append(&address)?;
    Ok(response)
}
