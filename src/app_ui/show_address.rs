//! "Show address", started from the home screen: the user types an account
//! and an address index, and the device shows the address at
//! `m/44'/118'/account'/0/index`, with no host involved.
//!
//! The flow starts from a home screen callback, which runs inside
//! `Comm::next_command`, so it cannot borrow the `Comm` that the SDK's blocking
//! screens need. It chains NBGL's asynchronous use cases instead, keeping what
//! they point to in static variables, and ends on the home screen.

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

/// Accounts and indices up to 9,999,999. Nano's keypad keeps the digits in
/// 8 bytes and shows them as a C string, so 7 is the most every device takes.
const MAX_DIGITS: u8 = 7;
const PATH_PREFIX: &[u8] = b"m/44'/118'/";
const PATH_MIDDLE: &[u8] = b"'/0/";
const PATH_LEN: usize = PATH_PREFIX.len() + PATH_MIDDLE.len() + 2 * MAX_DIGITS as usize;

/// What the address review points to while it is on screen.
struct Review {
    address: [u8; ADDRESS_LEN + 1],
    path: [u8; PATH_LEN + 1],
    icon: nbgl_icon_details_t,
    pair: nbgl_contentTagValue_t,
    list: nbgl_contentTagValueList_t,
}

// Zeroed rather than an `Option`: the device's link script refuses `.data`.
// SAFETY: every field is an integer, a bool or a raw pointer, all valid as zero.
static mut REVIEW: Review = unsafe { core::mem::zeroed() };

/// The account typed on the first keypad, while the second one is up.
static mut ACCOUNT: u32 = 0;

/// The home screen action: asks for the account, then the index.
pub fn start() {
    // SAFETY: the title is a static C string and the callbacks match NBGL's
    // signatures.
    unsafe {
        nbgl_useCaseKeypad(
            c"Account".as_ptr(),
            1,
            MAX_DIGITS,
            false,
            false,
            Some(on_account),
            Some(go_home),
        );
    }
}

unsafe extern "C" fn on_account(digits: *const u8, len: u8) {
    // SAFETY: NBGL passes its entry buffer and the number of digits in it.
    let digits = unsafe { core::slice::from_raw_parts(digits, len as usize) };
    let Some(account) = parse_number(digits) else {
        // SAFETY: a static C string, and a callback matching NBGL's signature.
        unsafe { nbgl_useCaseStatus(c"Invalid account".as_ptr(), false, Some(go_home)) };
        return;
    };
    // SAFETY: only this flow touches ACCOUNT, between screens; the title is a
    // static C string and the callbacks match NBGL's signatures.
    unsafe {
        *addr_of_mut!(ACCOUNT) = account;
        nbgl_useCaseKeypad(
            c"Address index".as_ptr(),
            1,
            MAX_DIGITS,
            false,
            false,
            Some(on_index),
            Some(back_to_account),
        );
    }
}

unsafe extern "C" fn on_index(digits: *const u8, len: u8) {
    // SAFETY: NBGL passes its entry buffer and the number of digits in it.
    let digits = unsafe { core::slice::from_raw_parts(digits, len as usize) };
    // SAFETY: set by `on_account` before this keypad was shown.
    let account = unsafe { *addr_of!(ACCOUNT) };
    if show(account, digits).is_none() {
        // SAFETY: a static C string, and a callback matching NBGL's signature.
        unsafe { nbgl_useCaseStatus(c"Invalid address index".as_ptr(), false, Some(go_home)) };
    }
}

/// Parses the ASCII digits the keypad returns, at most `MAX_DIGITS`.
fn parse_number(digits: &[u8]) -> Option<u32> {
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

/// Writes `n` in decimal at the start of `out`, returning the length.
fn write_decimal(out: &mut [u8], mut n: u32) -> usize {
    let mut digits = [0u8; 10];
    let mut len = 0;
    loop {
        digits[len] = b'0' + (n % 10) as u8;
        len += 1;
        n /= 10;
        if n == 0 {
            break;
        }
    }
    for (o, d) in out.iter_mut().zip(digits[..len].iter().rev()) {
        *o = *d;
    }
    len
}

/// `m/44'/118'/account'/0/index`, NUL-terminated.
fn path_text(account: u32, index: u32) -> [u8; PATH_LEN + 1] {
    let mut out = [0u8; PATH_LEN + 1];
    let mut at = PATH_PREFIX.len();
    out[..at].copy_from_slice(PATH_PREFIX);
    at += write_decimal(&mut out[at..], account);
    out[at..][..PATH_MIDDLE.len()].copy_from_slice(PATH_MIDDLE);
    at += PATH_MIDDLE.len();
    write_decimal(&mut out[at..], index);
    out
}

fn show(account: u32, digits: &[u8]) -> Option<()> {
    let index = parse_number(digits)?;
    let path = Bip32Path::address(account, index).ok()?;
    let address = crypto::address(&crypto::public_key(&path).ok()?);

    let mut new = Review {
        address: [0; ADDRESS_LEN + 1],
        path: path_text(account, index),
        icon: (&APP_GLYPH).into(),
        pair: nbgl_contentTagValue_t::default(),
        list: nbgl_contentTagValueList_t::default(),
    };
    new.address[..ADDRESS_LEN].copy_from_slice(&address);

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
            c"Verify Gno.land address".as_ptr(),
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

unsafe extern "C" fn back_to_account() {
    start();
}

unsafe extern "C" fn go_home() {
    show_home();
}
