use super::APP_GLYPH;
use crate::tx::Review;
use crate::AppSW;
use alloc::vec::Vec;
use ledger_device_sdk::io::Comm;
use ledger_device_sdk::nbgl::{Field, NbglReview, NbglStatus};

/// Shows the review and returns whether the user approved it.
///
/// Payloads carrying source code use the SDK's blind-signing flow, which
/// warns before the review that the content cannot be fully verified.
pub fn ui_display_tx(comm: &mut Comm, review: &Review) -> Result<bool, AppSW> {
    let fields: Vec<Field> = review
        .fields
        .iter()
        .map(|f| Field {
            name: f.name.as_str(),
            value: f.value.as_str(),
        })
        .collect();

    let mut nbgl = NbglReview::new()
        .titles(
            "Review transaction\nto sign on Gno",
            "",
            "Sign transaction\non Gno?",
        )
        .glyph(&APP_GLYPH);
    if review.blind {
        nbgl = nbgl.blind();
    }
    Ok(nbgl.show(comm, &fields))
}

pub fn ui_display_package_disabled(comm: &mut Comm) {
    NbglStatus::new()
        .text("Enable Packages\nin Settings")
        .show(comm, false);
}
