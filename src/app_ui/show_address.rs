//! "Show address", started from the home screen: the user types an address
//! index and the device shows the address at `m/44'/118'/0'/0/index`, with no
//! host involved.
//!
//! The flow starts from a home screen callback, which runs inside
//! `Comm::next_command`, so it cannot borrow the `Comm` that the SDK's blocking
//! screens need. It chains NBGL's asynchronous use cases instead, keeping what
//! they point to in statics, and ends on the home screen.

use super::menu::show_home;
use super::APP_GLYPH;
use crate::bip32::Bip32Path;
use crate::crypto;
use crate::tx::encoding::ADDRESS_LEN;
use core::ptr::{addr_of, addr_of_mut};
use ledger_device_sdk::sys::{
    nbgl_contentTagValueList_t, nbgl_contentTagValue_t, nbgl_icon_details_t,
    nbgl_useCaseAddressReview, nbgl_useCaseKeypad, nbgl_useCaseReviewStatus, nbgl_useCaseStatus,
    STATUS_TYPE_ADDRESS_REJECTED, STATUS_TYPE_ADDRESS_VERIFIED,
};

/// Indices up to 9,999,999. Nano's keypad keeps the digits in 8 bytes and
/// shows them as a C string, so 7 is the most every device can take.
const MAX_DIGITS: u8 = 7;
const PATH_PREFIX: &[u8] = b"m/44'/118'/0'/0/";

/// What the address review points to while it is on screen.
struct Review {
    address: [u8; ADDRESS_LEN + 1],
    path: [u8; PATH_PREFIX.len() + MAX_DIGITS as usize + 1],
    icon: nbgl_icon_details_t,
    pair: nbgl_contentTagValue_t,
    list: nbgl_contentTagValueList_t,
}

// Zeroed rather than an `Option`: the device's link script refuses `.data`.
// SAFETY: every field is an integer, a bool or a raw pointer, all valid as zero.
static mut REVIEW: Review = unsafe { core::mem::zeroed() };

/// The home screen action: asks for the index.
pub fn start() {
    // SAFETY: the title is a static C string and the callbacks match NBGL's
    // signatures.
    unsafe {
        nbgl_useCaseKeypad(
            c"Address index".as_ptr(),
            1,
            MAX_DIGITS,
            false,
            false,
            Some(on_index),
            Some(go_home),
        );
    }
}

unsafe extern "C" fn on_index(digits: *const u8, len: u8) {
    // SAFETY: NBGL passes its entry buffer and the number of digits in it.
    let digits = unsafe { core::slice::from_raw_parts(digits, len as usize) };
    if show(digits).is_none() {
        // SAFETY: a static C string, and a callback matching NBGL's signature.
        unsafe { nbgl_useCaseStatus(c"Invalid address index".as_ptr(), false, Some(go_home)) };
    }
}

/// Parses the ASCII digits the keypad returns, at most `MAX_DIGITS`.
fn parse_index(digits: &[u8]) -> Option<u32> {
    if digits.is_empty() || digits.len() > MAX_DIGITS as usize {
        return None;
    }
    digits.iter().try_fold(0u32, |n, &d| {
        if !d.is_ascii_digit() {
            return None;
        }
        n.checked_mul(10)?.checked_add((d - b'0') as u32)
    })
}

fn show(digits: &[u8]) -> Option<()> {
    let index = parse_index(digits)?;
    let path = Bip32Path::address_index(index).ok()?;
    let address = crypto::address(&crypto::public_key(&path).ok()?);

    let mut new = Review {
        address: [0; ADDRESS_LEN + 1],
        path: [0; PATH_PREFIX.len() + MAX_DIGITS as usize + 1],
        icon: (&APP_GLYPH).into(),
        pair: nbgl_contentTagValue_t::default(),
        list: nbgl_contentTagValueList_t::default(),
    };
    new.address[..ADDRESS_LEN].copy_from_slice(&address);
    new.path[..PATH_PREFIX.len()].copy_from_slice(PATH_PREFIX);
    // The keypad's digits, minus leading zeros, are the index in decimal.
    let first = digits
        .iter()
        .position(|&d| d != b'0')
        .unwrap_or(digits.len() - 1);
    new.path[PATH_PREFIX.len()..][..digits.len() - first].copy_from_slice(&digits[first..]);

    // SAFETY: NBGL keeps these pointers until the next use case starts, so
    // they point into a static that only this flow writes, and only between
    // screens.
    unsafe {
        let review = &mut *addr_of_mut!(REVIEW);
        *review = new;
        review.pair.item = c"Path".as_ptr();
        review.pair.value = review.path.as_ptr().cast();
        review.list.pairs = addr_of!(review.pair);
        review.list.nbPairs = 1;
        nbgl_useCaseAddressReview(
            review.address.as_ptr().cast(),
            addr_of!(review.list),
            addr_of!(review.icon),
            c"Verify Gno address".as_ptr(),
            core::ptr::null(),
            Some(on_review),
        );
    }
    Some(())
}

unsafe extern "C" fn on_review(confirmed: bool) {
    let status = match confirmed {
        true => STATUS_TYPE_ADDRESS_VERIFIED,
        false => STATUS_TYPE_ADDRESS_REJECTED,
    };
    // SAFETY: a callback matching NBGL's signature.
    unsafe { nbgl_useCaseReviewStatus(status, Some(go_home)) };
}

unsafe extern "C" fn go_home() {
    show_home();
}
