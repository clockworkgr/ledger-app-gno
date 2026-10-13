//! Feeds arbitrary bytes to the sign-doc parser.
//!
//! Input: one control byte giving how many chunk sizes follow, those sizes,
//! then the payload. Checks that parsing never panics, that the result does not
//! depend on how the payload is chunked, and that anything accepted is a
//! canonical gno sign doc whose review stays within the device's limits and
//! shows only printable ASCII.

#![no_main]

use app_gno_fuzz::{chunks, go_json, SIGNER};
use host_tests::tx::{Error, Parser, Review, MAX_REVIEW_BYTES, MAX_REVIEW_FIELDS};
use host_tests::HostHashes;
use libfuzzer_sys::fuzz_target;

type Outcome = Result<(Vec<(String, String)>, bool, bool), Error>;

fn parse(parts: &[&[u8]]) -> Result<Review, Error> {
    let mut p = Parser::<HostHashes>::new(*SIGNER);
    for part in parts {
        p.feed(part)?;
    }
    p.finish()
}

fn outcome(r: &Result<Review, Error>) -> Outcome {
    r.as_ref()
        .map(|r| {
            let fields = r
                .fields
                .iter()
                .map(|f| (f.name.to_string(), f.value.clone()))
                .collect();
            (fields, r.blind, r.runs_code)
        })
        .map_err(|e| *e)
}

fuzz_target!(|data: &[u8]| {
    let Some((&n, rest)) = data.split_first() else {
        return;
    };
    let n = (n as usize % 8).min(rest.len());
    let (sizes, doc) = rest.split_at(n);

    let whole = parse(&[doc]);
    let chunked = parse(&chunks(doc, sizes));
    assert_eq!(
        outcome(&whole),
        outcome(&chunked),
        "result depends on chunking"
    );

    let Ok(review) = whole else {
        return;
    };
    assert!(review.fields.len() <= MAX_REVIEW_FIELDS);
    let bytes: usize = review
        .fields
        .iter()
        .map(|f| f.name.len() + f.value.len() + 2)
        .sum();
    assert!(bytes <= MAX_REVIEW_BYTES, "review of {bytes} bytes");
    assert_eq!(review.fields[0].name, "Signer");
    for f in &review.fields {
        assert!(
            f.name
                .bytes()
                .chain(f.value.bytes())
                .all(|b| (0x20..0x7f).contains(&b)),
            "unprintable review text in {:?}",
            f.name
        );
    }
    assert!(!review.blind || review.runs_code, "blind payload not gated");

    let value: serde_json::Value =
        serde_json::from_slice(doc).expect("accepted payload is not JSON");
    let mut canonical = String::new();
    go_json(&value, &mut canonical);
    assert_eq!(
        canonical.as_bytes(),
        doc,
        "accepted payload is not canonical"
    );
});
