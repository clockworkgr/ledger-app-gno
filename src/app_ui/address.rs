use super::APP_GLYPH;
use crate::AppSW;
use ledger_device_sdk::io::Comm;
use ledger_device_sdk::nbgl::NbglAddressReview;

pub fn ui_display_address(comm: &mut Comm, address: &[u8]) -> Result<bool, AppSW> {
    let address = core::str::from_utf8(address).map_err(|_| AppSW::AddrDisplayFail)?;
    Ok(NbglAddressReview::new()
        .glyph(&APP_GLYPH)
        .review_title("Verify Gno address")
        .show(comm, address))
}
