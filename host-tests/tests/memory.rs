//! Peak heap use of the parser, measured with a counting allocator. Host
//! pointers are twice the device's, so the bounds are loose; they catch a
//! parser that buffers a payload or lets a hostile one grow the review.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;

use host_tests::tx::{encoding, Error, Parser};
use host_tests::HostHashes;
use serde_json::Value;

struct Counting;

static CURRENT: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);
/// Tests in this binary measure one at a time.
static SERIAL: Mutex<()> = Mutex::new(());

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let now = CURRENT.fetch_add(layout.size(), Ordering::SeqCst) + layout.size();
        PEAK.fetch_max(now, Ordering::SeqCst);
        unsafe { System.alloc(layout) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        CURRENT.fetch_sub(layout.size(), Ordering::SeqCst);
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static ALLOCATOR: Counting = Counting;

/// Parses `doc` in 250-byte chunks and returns the outcome and the peak heap
/// growth while doing so.
fn measure(signer: &str, doc: &[u8]) -> (Result<(), Error>, usize) {
    let signer: [u8; encoding::ADDRESS_LEN] = signer.as_bytes().try_into().unwrap();
    let base = CURRENT.load(Ordering::SeqCst);
    PEAK.store(base, Ordering::SeqCst);
    let result = (|| {
        let mut p = Parser::<HostHashes>::new(signer);
        for c in doc.chunks(250) {
            p.feed(c)?;
        }
        p.finish().map(drop)
    })();
    (result, PEAK.load(Ordering::SeqCst) - base)
}

fn vector(name: &str) -> (String, String) {
    let v: Value =
        serde_json::from_str(include_str!("../../tests/vectors/sign_docs.json")).unwrap();
    let doc = v["vectors"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == name)
        .unwrap()["sign_bytes"]
        .as_str()
        .unwrap()
        .to_owned();
    (v["address"].as_str().unwrap().to_owned(), doc)
}

const BOUND: usize = 24 * 1024;

#[test]
fn a_large_package_streams_without_buffering() {
    let _serial = SERIAL.lock().unwrap();
    let (signer, doc) = vector("run");
    let doc = doc.replace(
        "\"body\":\"package main",
        &format!("\"body\":\"// {}\\npackage main", "a".repeat(200_000)),
    );
    let (result, peak) = measure(&signer, doc.as_bytes());
    result.unwrap();
    assert!(peak < BOUND, "peak {peak}");
}

#[test]
fn hostile_payloads_are_refused_within_bounded_memory() {
    let _serial = SERIAL.lock().unwrap();
    let (signer, send) = vector("send");
    let coin = "{\"amount\":\"1000\",\"denom\":\"ugnot\"}";

    // Thousands of fee coins.
    let fees = send.replace(coin, &vec![coin; 5000].join(","));
    let (result, peak) = measure(&signer, fees.as_bytes());
    assert_eq!(result, Err(Error::InvalidCoins));
    assert!(peak < BOUND, "fee peak {peak}");

    // Long file names that escape to four times their size.
    let (signer, addpkg) = vector("addpkg");
    let start = addpkg.find("\"files\":[").unwrap() + "\"files\":[".len();
    let end = addpkg.find("],\"name\":\"hello\"").unwrap();
    let files: Vec<String> = (0..64)
        .map(|i| {
            format!(
                "{{\"body\":\"package hello\\n\",\"name\":\"{}f{i:02}.gno\"}}",
                "\\u0001".repeat(240)
            )
        })
        .collect();
    let doc = format!("{}{}{}", &addpkg[..start], files.join(","), &addpkg[end..]);
    let (result, peak) = measure(&signer, doc.as_bytes());
    assert_eq!(result, Err(Error::ReviewTooLarge));
    assert!(peak < BOUND, "file name peak {peak}");
}
