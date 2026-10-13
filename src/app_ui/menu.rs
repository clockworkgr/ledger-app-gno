use crate::settings::{Settings, SETTINGS_STRINGS};
use ledger_device_sdk::include_gif;
use ledger_device_sdk::io::Comm;
use ledger_device_sdk::nbgl::{NbglGlyph, NbglHomeAndSettings};

pub fn ui_menu_main(_: &mut Comm) -> NbglHomeAndSettings {
    #[cfg(target_os = "apex_p")]
    const HOME: NbglGlyph = NbglGlyph::from_include(include_gif!("glyphs/gno_48x48.png", NBGL));
    #[cfg(any(target_os = "stax", target_os = "flex"))]
    const HOME: NbglGlyph = NbglGlyph::from_include(include_gif!("glyphs/gno_64x64.gif", NBGL));
    #[cfg(any(target_os = "nanosplus", target_os = "nanox"))]
    const HOME: NbglGlyph =
        NbglGlyph::from_include(include_gif!("glyphs/home_nano_nbgl.png", NBGL));

    let mut settings = Settings;
    NbglHomeAndSettings::new()
        .glyph(&HOME)
        .settings(settings.get_mut(), &SETTINGS_STRINGS)
        .infos("Gno", env!("CARGO_PKG_VERSION"), env!("CARGO_PKG_AUTHORS"))
}
