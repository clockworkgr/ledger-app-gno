pub mod address;
pub mod menu;
pub mod show_address;
pub mod sign;

use ledger_device_sdk::include_gif;
use ledger_device_sdk::nbgl::NbglGlyph;

#[cfg(target_os = "apex_p")]
pub const APP_GLYPH: NbglGlyph =
    NbglGlyph::from_include(include_gif!("glyphs/gno_48x48.png", NBGL));
#[cfg(any(target_os = "stax", target_os = "flex"))]
pub const APP_GLYPH: NbglGlyph =
    NbglGlyph::from_include(include_gif!("glyphs/gno_64x64.gif", NBGL));
#[cfg(any(target_os = "nanosplus", target_os = "nanox"))]
pub const APP_GLYPH: NbglGlyph = NbglGlyph::from_include(include_gif!("icons/gno_14x14.gif", NBGL));
