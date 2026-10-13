//! Feeds arbitrary bytes to the package source scanner.
//!
//! The scanner must never panic, its findings must not depend on how the
//! source is chunked, and they must respect its limits.

#![no_main]

use app_gno_fuzz::chunks;
use host_tests::tx::source::{Findings, Scanner, MAX_ADDRESSES, MAX_IMPORTS, MAX_IMPORT_LEN};
use libfuzzer_sys::fuzz_target;

fn scan(parts: &[&[u8]]) -> Findings {
    let mut s = Scanner::new();
    for part in parts {
        s.feed(part);
    }
    s.finish()
}

fn summary(f: &Findings) -> (Vec<Vec<u8>>, Vec<[u8; 40]>, bool, bool, bool) {
    (
        f.imports.clone(),
        f.addresses.clone(),
        f.more_imports,
        f.more_addresses,
        f.long_import,
    )
}

fuzz_target!(|data: &[u8]| {
    let Some((&n, rest)) = data.split_first() else {
        return;
    };
    let n = (n as usize % 8).min(rest.len());
    let (sizes, source) = rest.split_at(n);

    let whole = scan(&[source]);
    let chunked = scan(&chunks(source, sizes));
    assert_eq!(
        summary(&whole),
        summary(&chunked),
        "findings depend on chunking"
    );
    assert!(whole.imports.len() <= MAX_IMPORTS);
    assert!(whole.imports.iter().all(|p| p.len() <= MAX_IMPORT_LEN));
    assert!(whole.addresses.len() <= MAX_ADDRESSES);
    for a in &whole.addresses {
        host_tests::tx::encoding::validate_address(a).expect("listed an invalid address");
    }
});
