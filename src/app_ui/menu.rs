//! The home screen: app info, the Packages switch and the "Show address"
//! button.
//!
//! Built on `nbgl_useCaseHomeAndSettings` rather than the SDK's
//! `NbglHomeAndSettings`, which passes the action button's descriptor from its
//! own stack. Nano NBGL keeps that pointer and reads it again when the user
//! scrolls to the button. Everything NBGL points to lives in static variables here.

use super::show_address;
use crate::settings::{Settings, SETTINGS_STRINGS, SETTING_PACKAGE_TX};
use core::ffi::{c_char, c_int};
use core::ptr::{addr_of, addr_of_mut};
use ledger_device_sdk::include_gif;
use ledger_device_sdk::nbgl::NbglGlyph;
use ledger_device_sdk::sys::{
    exit_app, nbgl_contentInfoList_t, nbgl_contentSwitch_t, nbgl_content_t, nbgl_content_u,
    nbgl_genericContents_t, nbgl_genericContents_t__bindgen_ty_1, nbgl_homeAction_t,
    nbgl_icon_details_t, nbgl_pageSwitchesList_s, nbgl_useCaseHomeAndSettings, FIRST_USER_TOKEN,
    INIT_HOME_PAGE, OFF_STATE, ON_STATE, SOFT_HOME_ACTION, SWITCHES_LIST, TUNE_TAP_CASUAL,
};

#[cfg(target_os = "apex_p")]
const HOME_GLYPH: NbglGlyph = NbglGlyph::from_include(include_gif!("glyphs/gno_48x48.png", NBGL));
#[cfg(any(target_os = "stax", target_os = "flex"))]
const HOME_GLYPH: NbglGlyph = NbglGlyph::from_include(include_gif!("glyphs/gno_64x64.gif", NBGL));
#[cfg(any(target_os = "nanosplus", target_os = "nanox"))]
const HOME_GLYPH: NbglGlyph =
    NbglGlyph::from_include(include_gif!("glyphs/home_nano_nbgl.png", NBGL));

/// The SDK's Nano eye icon (`lib_nbgl/glyphs/nano/icon_eye.gif`).
#[cfg(any(target_os = "nanosplus", target_os = "nanox"))]
const ACTION_GLYPH: NbglGlyph = NbglGlyph::from_include(include_gif!("glyphs/eye_14x14.gif", NBGL));

const VERSION: &str = concat!(env!("CARGO_PKG_VERSION"), "\0");
const AUTHORS: &str = concat!(env!("CARGO_PKG_AUTHORS"), "\0");
const PACKAGES_TOKEN: u8 = FIRST_USER_TOKEN as u8;

struct Screens {
    icon: nbgl_icon_details_t,
    switch: nbgl_contentSwitch_t,
    content: nbgl_content_t,
    settings: nbgl_genericContents_t,
    info_types: [*const c_char; 2],
    info_contents: [*const c_char; 2],
    infos: nbgl_contentInfoList_t,
    action_icon: nbgl_icon_details_t,
    action: nbgl_homeAction_t,
}

// Zeroed rather than built in a const: pointers into the binary are only
// valid once taken at run time, and the device's link script refuses `.data`.
// SAFETY: every field is an integer, a bool, a raw pointer or an optional
// function pointer, all valid as zero.
static mut SCREENS: Screens = unsafe { core::mem::zeroed() };

/// Shows the home screen, which stays up until another flow replaces it.
pub fn show_home() {
    // SAFETY: NBGL keeps pointers into SCREENS while the home screen is up.
    // They are rewritten here only, before NBGL is handed them again, and
    // nothing else writes SCREENS except the switch callback, which NBGL
    // calls for that purpose.
    unsafe {
        let s = &mut *addr_of_mut!(SCREENS);
        s.icon = (&HOME_GLYPH).into();
        s.switch = nbgl_contentSwitch_t {
            text: SETTINGS_STRINGS[SETTING_PACKAGE_TX][0].as_ptr(),
            subText: SETTINGS_STRINGS[SETTING_PACKAGE_TX][1].as_ptr(),
            initState: match Settings.get_element(SETTING_PACKAGE_TX) {
                0 => OFF_STATE,
                _ => ON_STATE,
            },
            token: PACKAGES_TOKEN,
            tuneId: TUNE_TAP_CASUAL,
        };
        s.content = nbgl_content_t {
            content: nbgl_content_u {
                switchesList: nbgl_pageSwitchesList_s {
                    switches: addr_of!(s.switch),
                    nbSwitches: 1,
                },
            },
            contentActionCallback: Some(on_switch),
            type_: SWITCHES_LIST,
        };
        s.settings = nbgl_genericContents_t {
            callbackCallNeeded: false,
            __bindgen_anon_1: nbgl_genericContents_t__bindgen_ty_1 {
                contentsList: addr_of!(s.content),
            },
            nbContents: 1,
        };
        s.info_types = [c"Version".as_ptr(), c"Developer".as_ptr()];
        s.info_contents = [VERSION.as_ptr().cast(), AUTHORS.as_ptr().cast()];
        s.infos = nbgl_contentInfoList_t {
            infoTypes: s.info_types.as_ptr(),
            infoContents: s.info_contents.as_ptr(),
            nbInfos: s.info_types.len() as u8,
            infoExtensions: core::ptr::null(),
            token: 0,
            withExtensions: false,
        };
        s.action = nbgl_homeAction_t {
            text: c"Show address".as_ptr(),
            icon: action_icon(&mut s.action_icon),
            callback: Some(on_show_address),
            style: SOFT_HOME_ACTION,
        };
        nbgl_useCaseHomeAndSettings(
            c"Gno".as_ptr(),
            addr_of!(s.icon),
            core::ptr::null(),
            INIT_HOME_PAGE as u8,
            addr_of!(s.settings),
            addr_of!(s.infos),
            addr_of!(s.action),
            Some(on_quit),
        );
    }
}

/// Nano draws a home step's text in bold only under an icon, as on the
/// settings, info and quit steps; touch devices show the action as a text
/// button.
#[cfg(any(target_os = "nanosplus", target_os = "nanox"))]
fn action_icon(slot: &mut nbgl_icon_details_t) -> *const nbgl_icon_details_t {
    *slot = (&ACTION_GLYPH).into();
    slot
}

#[cfg(not(any(target_os = "nanosplus", target_os = "nanox")))]
fn action_icon(_slot: &mut nbgl_icon_details_t) -> *const nbgl_icon_details_t {
    core::ptr::null()
}

unsafe extern "C" fn on_switch(token: c_int, _index: u8, _page: c_int) {
    if token != PACKAGES_TOKEN as c_int {
        return;
    }
    // SAFETY: see `show_home`; NBGL redraws the switch from `initState`.
    let switch = unsafe { &mut (*addr_of_mut!(SCREENS)).switch };
    let (state, value) = match switch.initState {
        OFF_STATE => (ON_STATE, 1),
        _ => (OFF_STATE, 0),
    };
    switch.initState = state;
    Settings.set_element(SETTING_PACKAGE_TX, value);
}

unsafe extern "C" fn on_show_address() {
    show_address::start();
}

unsafe extern "C" fn on_quit() {
    exit_app(0);
}
