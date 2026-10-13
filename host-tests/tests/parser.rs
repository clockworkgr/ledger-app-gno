use host_tests::tx::{encoding, Error, Parser, Review};
use host_tests::HostHashes;
use serde_json::Value;
use sha2::{Digest, Sha256};

struct Vectors {
    address: String,
    pubkey: Vec<u8>,
    cases: Vec<(String, String)>,
}

fn vectors() -> Vectors {
    let raw = include_str!("../../tests/vectors/sign_docs.json");
    let v: Value = serde_json::from_str(raw).unwrap();
    Vectors {
        address: v["address"].as_str().unwrap().to_owned(),
        pubkey: hex(v["pubkey"].as_str().unwrap()),
        cases: v["vectors"]
            .as_array()
            .unwrap()
            .iter()
            .map(|c| {
                (
                    c["name"].as_str().unwrap().to_owned(),
                    c["sign_bytes"].as_str().unwrap().to_owned(),
                )
            })
            .collect(),
    }
}

fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn signer(address: &str) -> [u8; encoding::ADDRESS_LEN] {
    address.as_bytes().try_into().unwrap()
}

fn parse_chunked(address: &str, doc: &[u8], chunk: usize) -> Result<Review, Error> {
    let mut p = Parser::<HostHashes>::new(signer(address));
    for c in doc.chunks(chunk) {
        p.feed(c)?;
    }
    p.finish()
}

fn parse(address: &str, doc: &str) -> Result<Review, Error> {
    parse_chunked(address, doc.as_bytes(), 255)
}

/// The review without its leading Signer field, which every review starts
/// with (see `every_review_starts_with_the_signer`).
fn fields(r: &Review) -> Vec<(String, String)> {
    assert_eq!(r.fields[0].name, "Signer");
    r.fields[1..]
        .iter()
        .map(|f| (f.name.to_string(), f.value.clone()))
        .collect()
}

fn case(v: &Vectors, name: &str) -> String {
    v.cases.iter().find(|(n, _)| n == name).unwrap().1.clone()
}

fn pairs(list: &[(&str, &str)]) -> Vec<(String, String)> {
    list.iter()
        .map(|(a, b)| (a.to_string(), b.to_string()))
        .collect()
}

/// The fingerprint as docs/APDU.md defines it, computed independently of the
/// parser from the decoded payload.
fn reference_fingerprint(doc: &str) -> String {
    let v: Value = serde_json::from_str(doc).unwrap();
    let files = v["msgs"][0]["package"]["files"].as_array().unwrap();
    let mut h = Sha256::new();
    for f in files {
        let name = f["name"].as_str().unwrap().as_bytes();
        let body = f["body"].as_str().unwrap().as_bytes();
        h.update((name.len() as u32).to_be_bytes());
        h.update(name);
        h.update(Sha256::digest(body));
    }
    h.finalize().iter().map(|b| format!("{:02x}", b)).collect()
}

#[test]
fn derived_address_matches_gno() {
    let v = vectors();
    use host_tests::tx::Hashes;
    let addr = encoding::encode_address(&HostHashes::hash160(&v.pubkey));
    assert_eq!(std::str::from_utf8(&addr).unwrap(), v.address);
    encoding::validate_address(v.address.as_bytes()).unwrap();
}

#[test]
fn every_vector_parses_at_every_chunk_size() {
    let v = vectors();
    for (name, doc) in &v.cases {
        let whole = fields(&parse(&v.address, doc).unwrap_or_else(|e| panic!("{name}: {e:?}")));
        for chunk in [1, 2, 3, 7, 64, 255] {
            let r = parse_chunked(&v.address, doc.as_bytes(), chunk)
                .unwrap_or_else(|e| panic!("{name} chunk {chunk}: {e:?}"));
            assert_eq!(fields(&r), whole, "{name} chunk {chunk}");
        }
    }
}

#[test]
fn send_review() {
    let v = vectors();
    let r = parse(&v.address, &case(&v, "send")).unwrap();
    assert!(!r.blind);
    assert_eq!(
        fields(&r),
        pairs(&[
            ("Type", "Send"),
            ("To", "g1jg8mtutu9khhfwc4nxmuhcpftf0pajdhfvsqf5"),
            ("Amount", "1.234567 GNOT"),
            ("Fee", "0.001 GNOT"),
            ("Gas limit", "100000"),
            ("Chain ID", "test-chain"),
        ])
    );
}

#[test]
fn zero_fee_and_memo() {
    let v = vectors();
    let r = parse(&v.address, &case(&v, "send_zero_fee_memo")).unwrap();
    assert_eq!(
        fields(&r),
        pairs(&[
            ("Type", "Send"),
            ("To", "g1jg8mtutu9khhfwc4nxmuhcpftf0pajdhfvsqf5"),
            ("Amount", "0.000001 GNOT"),
            ("Memo", "thanks"),
            ("Fee", "None"),
            ("Gas limit", "100000"),
            ("Chain ID", "test-chain"),
        ])
    );
}

#[test]
fn call_review() {
    let v = vectors();
    let r = parse(&v.address, &case(&v, "call")).unwrap();
    assert_eq!(
        fields(&r)[..7],
        pairs(&[
            ("Type", "Call realm"),
            ("Realm", "gno.land/r/demo/boards"),
            ("Function", "CreateThread"),
            ("Arg 1", "1"),
            ("Arg 2", "Hello"),
            ("Arg 3", "World"),
            ("Send", "None"),
        ])[..]
    );
    assert_eq!(
        fields(&r)[7],
        ("Max deposit".into(), "Chain default".into())
    );

    let r = parse(&v.address, &case(&v, "call_send_no_args")).unwrap();
    let f = fields(&r);
    assert!(f.contains(&("Send".into(), "0.000005 GNOT".into())));
    assert!(f.contains(&("Max deposit".into(), "0.000007 GNOT".into())));
    assert!(!f.iter().any(|(n, _)| n.starts_with("Arg")));
}

#[test]
fn multiple_messages_are_numbered() {
    let v = vectors();
    let r = parse(&v.address, &case(&v, "two_msgs")).unwrap();
    let names: Vec<_> = fields(&r).into_iter().map(|(n, _)| n).collect();
    assert_eq!(
        &names[..6],
        ["Message 1", "To", "Amount", "Message 2", "To", "Amount"]
    );
}

#[test]
fn enable_and_reject_package() {
    let v = vectors();
    let f = fields(&parse(&v.address, &case(&v, "enable_pkg")).unwrap());
    assert_eq!(
        f[..4],
        pairs(&[
            ("Type", "Approve package"),
            ("Package", "gno.land/r/demo/hello"),
            (
                "Package hash",
                "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
            ),
            ("Submitted at", "block 42"),
        ])[..]
    );
    let f = fields(&parse(&v.address, &case(&v, "reject_pkg")).unwrap());
    assert_eq!(
        f[..2],
        pairs(&[
            ("Type", "Reject package"),
            ("Package", "gno.land/r/demo/hello")
        ])[..]
    );

    let unpinned = case(&v, "enable_pkg").replace("\"pkg_height\":\"42\"", "\"pkg_height\":\"0\"");
    let f = fields(&parse(&v.address, &unpinned).unwrap());
    assert_eq!(
        f[1],
        (
            "Warning".into(),
            "Approval is not pinned to a submission".into()
        )
    );
}

#[test]
fn sessions() {
    let v = vectors();
    let f = fields(&parse(&v.address, &case(&v, "create_session")).unwrap());
    let session_key = f
        .iter()
        .find(|(n, _)| n == "Session key")
        .unwrap()
        .1
        .clone();
    encoding::validate_address(session_key.as_bytes()).unwrap();
    assert_eq!(
        f[..6],
        pairs(&[
            ("Type", "Create session"),
            ("Session key", &session_key),
            ("Allowed", "vm/exec:gno.land/r/demo/boards"),
            ("Expires", "2027-01-01 00:00:00 UTC"),
            ("Spend limit", "5 GNOT"),
            ("Spend period", "86400 seconds"),
        ])[..]
    );

    let f = fields(&parse(&v.address, &case(&v, "create_session_minimal")).unwrap());
    assert_eq!(
        f[..7],
        pairs(&[
            ("Type", "Create session"),
            ("Warning", "Session may sign any message, scripts included"),
            ("Warning", "Session never expires"),
            ("Session key", &session_key),
            ("Allowed", "*"),
            ("Expires", "Never"),
            ("Spend limit", "None (cannot spend)"),
        ])[..]
    );

    let f = fields(&parse(&v.address, &case(&v, "revoke_session")).unwrap());
    assert_eq!(
        f[..2],
        pairs(&[("Type", "Revoke session"), ("Session key", &session_key)])[..]
    );
    let f = fields(&parse(&v.address, &case(&v, "revoke_all_sessions")).unwrap());
    assert_eq!(f[0], ("Type".into(), "Revoke all sessions".into()));
}

#[test]
fn package_messages_are_blind_with_fingerprint() {
    let v = vectors();
    for (name, title) in [("addpkg", "Deploy package"), ("run", "Run script")] {
        let doc = case(&v, name);
        let r = parse(&v.address, &doc).unwrap();
        assert!(r.blind, "{name}");
        let f = fields(&r);
        assert_eq!(f[0], ("Type".into(), title.into()));
        let fp = f.iter().find(|(n, _)| n == "Fingerprint").unwrap();
        assert_eq!(fp.1, reference_fingerprint(&doc), "{name}");
    }
    let f = fields(&parse(&v.address, &case(&v, "addpkg")).unwrap());
    assert_eq!(
        f[1..9],
        pairs(&[
            ("Package", "gno.land/r/demo/hello"),
            ("Package name", "hello"),
            ("Imports", "None"),
            ("Addresses in code", "None found"),
            ("Files", "2"),
            ("File", "gnomod.toml (45 bytes)"),
            ("File", "hello.gno (77 bytes)"),
            ("Source size", "122 bytes"),
        ])[..]
    );
    let f = fields(&parse(&v.address, &case(&v, "run")).unwrap());
    assert_eq!(
        f[1],
        (
            "Warning".into(),
            "Script can do anything your account can".into()
        )
    );
}

/// The package fields of a single-message review, between the type and `Send`.
fn package_fields(address: &str, doc: &str) -> Vec<(String, String)> {
    let f = fields(&parse(address, doc).unwrap());
    let end = f.iter().position(|(n, _)| n == "Send").unwrap();
    f[1..end].to_vec()
}

#[test]
fn package_review_highlights_executed_source() {
    let v = vectors();
    let doc = case(&v, "addpkg_highlights");
    let me = format!("{} (you)", v.address);
    // The README, the comment and the test file mention another address, and the
    // test file imports "testing"; none of them runs on chain.
    assert_eq!(
        package_fields(&v.address, &doc),
        pairs(&[
            ("Package", "gno.land/r/demo/tipjar"),
            ("Package name", "tipjar"),
            ("Import", "strings"),
            ("Import", "chain/banker"),
            ("Import", "chain/runtime"),
            ("Import", "gno.land/p/nt/ufmt"),
            (
                "Address in code",
                "g1jvelajgq7ue8ns4zjj32xvxwkazww89rf6cwuc"
            ),
            ("Address in code", &me),
            ("Files", "5"),
            ("File", "README.md (74 bytes)"),
            ("File", "gnomod.toml (46 bytes)"),
            ("File", "render.gno (97 bytes)"),
            ("File", "tipjar.gno (618 bytes)"),
            ("File", "tipjar_test.gno (132 bytes)"),
            ("Source size", "967 bytes"),
            (
                "Fingerprint",
                "3f83d1bccf693d2d372e2945140615abb1ad5beb5f3b739a04f1401fb59100c0"
            ),
        ])[..]
    );
    // Token state survives any chunking of the stream.
    for chunk in [1, 2, 3, 7, 64] {
        let r = parse_chunked(&v.address, doc.as_bytes(), chunk).unwrap();
        assert_eq!(fields(&r), fields(&parse(&v.address, &doc).unwrap()));
    }
}

#[test]
fn package_review_announces_what_it_cannot_list() {
    let v = vectors();
    let doc = case(&v, "addpkg_limits");
    let r = parse(&v.address, &doc).unwrap();
    let f = fields(&r);
    assert_eq!(
        f[1..3],
        pairs(&[
            ("Warning", "Over 16 imports, not all shown"),
            ("Warning", "Over 8 addresses in code, not all shown"),
        ])[..]
    );
    let count = |name: &str| f.iter().filter(|(n, _)| n == name).count();
    assert_eq!(count("Import"), host_tests::tx::source::MAX_IMPORTS);
    assert_eq!(
        count("Address in code"),
        host_tests::tx::source::MAX_ADDRESSES
    );
    assert_eq!(count("File"), host_tests::tx::MAX_LISTED_FILES + 1);
    assert!(f.contains(&("Files".into(), "20".into())));
    assert!(f.contains(&("File".into(), "and 4 more".into())));
}

/// Replaces the body of `render.gno` in the highlights vector.
fn with_render_body(v: &Vectors, body: &str) -> String {
    let doc = case(v, "addpkg_highlights");
    let start = doc
        .find("{\"body\":\"package tipjar\\n\\nimport \\\"strings")
        .unwrap()
        + 9;
    let end = start + doc[start..].find("\",\"name\":\"render.gno\"").unwrap();
    format!("{}{}{}", &doc[..start], body, &doc[end..])
}

fn highlights(v: &Vectors, render_body: &str) -> (Vec<String>, Vec<String>) {
    let f = package_fields(&v.address, &with_render_body(v, render_body));
    let get = |name: &str| {
        f.iter()
            .filter(|(n, _)| n == name)
            .map(|(_, val)| val.clone())
            .collect::<Vec<_>>()
    };
    (get("Import"), get("Address in code"))
}

#[test]
fn source_scanner_resists_evasion() {
    let v = vectors();
    let treasurer = "g1jvelajgq7ue8ns4zjj32xvxwkazww89rf6cwuc";
    let me = format!("{} (you)", v.address);
    let base = ["chain/banker", "chain/runtime", "gno.land/p/nt/ufmt"];
    let expect_imports = |extra: &[&str]| {
        let mut all: Vec<String> = extra.iter().map(|s| s.to_string()).collect();
        all.extend(base.iter().map(|s| s.to_string()));
        all
    };

    // An all-uppercase address is valid bech32 and is shown in lowercase.
    let upper = "g1cp40l329cp2w8xzgr5v8u2r7nxmjxgq6k0da9d".to_uppercase();
    let (_, addrs) = highlights(&v, &format!("package tipjar\\nvar x = \\\"{upper}\\\"\\n"));
    assert_eq!(addrs[0], "g1cp40l329cp2w8xzgr5v8u2r7nxmjxgq6k0da9d");
    // Mixed case is not an address, here or on chain.
    let mixed = "G1cp40l329cp2w8xzgr5v8u2r7nxmjxgq6k0da9d";
    let (_, addrs) = highlights(&v, &format!("package tipjar\\nvar x = \\\"{mixed}\\\"\\n"));
    assert_eq!(addrs, vec![treasurer.to_string(), me.clone()]);

    // Imports in every form; aliases are dropped, escapes are shown verbatim.
    let (imports, _) = highlights(
        &v,
        "package tipjar\\nimport . \\\"a\\\"\\nimport _ `b`\\nimport (/* ) */ c \\\"c\\\"; \\\"\\\\x73td\\\")\\n",
    );
    assert_eq!(imports, expect_imports(&["a", "b", "c", "\\\\x73td"]));

    // Neither identifiers containing "import" nor the word in strings, runes
    // or comments open an import.
    let (imports, _) = highlights(
        &v,
        "package tipjar\\nvar importer, my_import, importé = 1, 2, 3\\nvar s = \\\"import\\\" + \\\"x\\\"\\nvar r = '\\\"'\\n// import \\\"y\\\"\\n",
    );
    assert_eq!(imports, expect_imports(&[]));

    // An address glued to other word characters is not an address.
    let (_, addrs) = highlights(
        &v,
        &format!(
            "package tipjar\\nvar x = \\\"x{}\\\"\\n",
            "g1cp40l329cp2w8xzgr5v8u2r7nxmjxgq6k0da9d"
        ),
    );
    assert_eq!(addrs, vec![treasurer.to_string(), me.clone()]);

    // An import path too long to show refuses the transaction.
    let long = "p".repeat(host_tests::tx::source::MAX_IMPORT_LEN + 1);
    let doc = with_render_body(&v, &format!("package tipjar\\nimport \\\"{long}\\\"\\n"));
    assert_eq!(parse(&v.address, &doc).err(), Some(Error::ValueTooLong));
    let fits = "p".repeat(host_tests::tx::source::MAX_IMPORT_LEN);
    let (imports, _) = highlights(&v, &format!("package tipjar\\nimport \\\"{fits}\\\"\\n"));
    assert_eq!(imports, expect_imports(&[&fits]));
}

fn expect_err(v: &Vectors, name: &str, from: &str, to: &str, err: Error) {
    let doc = case(v, name);
    assert!(doc.contains(from), "{name}: {from}");
    let bad = doc.replacen(from, to, 1);
    assert_eq!(
        parse(&v.address, &bad).err(),
        Some(err),
        "{name}: {from} -> {to}"
    );
}

#[test]
fn rejects_hostile_payloads() {
    let v = vectors();
    let me = v.address.as_str();
    let other = "g1jg8mtutu9khhfwc4nxmuhcpftf0pajdhfvsqf5";

    // Structure.
    expect_err(
        &v,
        "send",
        "{\"account_number\"",
        "{ \"account_number\"",
        Error::Syntax,
    );
    expect_err(
        &v,
        "send",
        "\"sequence\":\"3\"}",
        "\"sequence\":3}",
        Error::Syntax,
    );
    expect_err(&v, "send", "\"memo\":\"\",", "", Error::MissingKey);
    expect_err(
        &v,
        "send",
        "\"memo\":\"\",",
        "\"memo\":\"\",\"memo\":\"\",",
        Error::UnknownKey,
    );
    expect_err(
        &v,
        "send",
        "\"chain_id\":\"test-chain\",",
        "\"chain_id\":\"test-chain\",\"extra\":\"x\",",
        Error::UnknownKey,
    );
    expect_err(
        &v,
        "send",
        "\"account_number\":\"7\",\"chain_id\":\"test-chain\"",
        "\"chain_id\":\"test-chain\",\"account_number\":\"7\"",
        Error::MissingKey,
    );
    expect_err(
        &v,
        "send",
        "\"sequence\":\"3\"",
        "\"sequence\":\"03\"",
        Error::InvalidNumber,
    );
    expect_err(
        &v,
        "send",
        "\"msgs\":[{",
        "\"msgs\":[],\"x\":[{",
        Error::MissingKey,
    );

    // Messages.
    expect_err(
        &v,
        "send",
        "/bank.MsgSend",
        "/bank.MsgMultiSend",
        Error::UnknownMessage,
    );
    expect_err(
        &v,
        "send",
        "{\"@type\":\"/bank.MsgSend\",",
        "{",
        Error::UnknownKey,
    );
    expect_err(
        &v,
        "send",
        &format!("\"from_address\":\"{me}\""),
        &format!("\"from_address\":\"{other}\""),
        Error::SignerMismatch,
    );
    expect_err(
        &v,
        "call",
        &format!("\"caller\":\"{me}\""),
        &format!("\"caller\":\"{other}\""),
        Error::SignerMismatch,
    );
    expect_err(
        &v,
        "send",
        other,
        "g1jg8mtutu9khhfwc4nxmuhcpftf0pajdhfvsqf6",
        Error::InvalidAddress,
    );
    expect_err(
        &v,
        "send",
        other,
        &other.to_uppercase(),
        Error::InvalidAddress,
    );
    expect_err(&v, "send", "1234567ugnot", "", Error::InvalidCoins);
    expect_err(&v, "send", "1234567ugnot", "-1ugnot", Error::InvalidCoins);
    expect_err(
        &v,
        "call",
        "\"args\":[\"1\",\"Hello\",\"World\"],",
        "\"args\":[],",
        Error::MissingKey,
    );
    expect_err(
        &v,
        "enable_pkg",
        "\"pkg_hash\":\"9f86",
        "\"pkg_hash\":\"9F86",
        Error::InvalidValue,
    );
    expect_err(
        &v,
        "create_session",
        "/tm.PubKeySecp256k1",
        "/tm.PubKeyEd25519",
        Error::InvalidValue,
    );
    expect_err(
        &v,
        "create_session",
        "\"spend_period\":\"86400\"",
        "\"spend_period\":\"0\"",
        Error::InvalidValue,
    );

    // Packages.
    expect_err(
        &v,
        "addpkg",
        "\"name\":\"gnomod.toml\"",
        "\"name\":\"zzz.toml\"",
        Error::UnsortedFiles,
    );
    expect_err(
        &v,
        "addpkg",
        "\"name\":\"hello\",",
        "\"info\":\"x\",\"name\":\"hello\",",
        Error::UnknownKey,
    );
    expect_err(
        &v,
        "addpkg",
        "\"value\":\"MPUserProd\"",
        "\"value\":\"MPStdlibAll\"",
        Error::InvalidValue,
    );

    // Truncation and trailing bytes.
    let send = case(&v, "send");
    assert_eq!(
        parse(me, &send[..send.len() - 1]).err(),
        Some(Error::Truncated)
    );
    assert_eq!(
        parse(me, &format!("{send} ")).err(),
        Some(Error::TrailingData)
    );
    assert_eq!(parse(me, "").err(), Some(Error::Truncated));
}

#[test]
fn display_escapes_unprintable_bytes() {
    let v = vectors();
    let doc = case(&v, "send_zero_fee_memo")
        .replace("\"memo\":\"thanks\"", "\"memo\":\"a\\nb\\\\c\u{e9}\"");
    let f = fields(&parse(&v.address, &doc).unwrap());
    let memo = f.iter().find(|(n, _)| n == "Memo").unwrap();
    assert_eq!(memo.1, "a\\x0ab\\\\c\\xc3\\xa9");
}

#[test]
fn rejects_oversized_values_instead_of_truncating() {
    let v = vectors();
    let long = "x".repeat(host_tests::tx::MAX_VALUE_LEN + 1);
    let doc = case(&v, "send_zero_fee_memo")
        .replace("\"memo\":\"thanks\"", &format!("\"memo\":\"{long}\""));
    assert_eq!(parse(&v.address, &doc).err(), Some(Error::ValueTooLong));
}

#[test]
fn large_package_streams_in_bounded_memory() {
    let v = vectors();
    let body = "a".repeat(200_000);
    let doc = case(&v, "run").replace(
        "\"body\":\"package main",
        &format!("\"body\":\"// {body}\\npackage main"),
    );
    let r = parse_chunked(&v.address, doc.as_bytes(), 250).unwrap();
    let fp = r.fields.iter().find(|f| f.name == "Fingerprint").unwrap();
    assert_eq!(fp.value, reference_fingerprint(&doc));
}

#[test]
fn encoding_helpers() {
    let mut s = String::new();
    encoding::write_amount(&mut s, 1_000_000, b"ugnot").unwrap();
    assert_eq!(s, "1 GNOT");
    assert_eq!(
        encoding::format_coins(b"5/gno.land/r/demo/foo:bar,10ugnot")
            .unwrap()
            .unwrap(),
        "5 /gno.land/r/demo/foo:bar, 0.00001 GNOT"
    );
    assert_eq!(encoding::format_utc(0), "1970-01-01 00:00:00 UTC");
    assert_eq!(encoding::format_utc(951_782_400), "2000-02-29 00:00:00 UTC");
    assert!(encoding::parse_u64(b"18446744073709551616").is_err());
    assert_eq!(
        encoding::parse_u64(b"18446744073709551615").unwrap(),
        u64::MAX
    );
    let mut out = [0u8; 3];
    assert!(encoding::decode_base64(b"AAAAAA==", &mut out).is_err());
    let mut out = [0u8; 4];
    encoding::decode_base64(b"AAAAAA==", &mut out).unwrap();
    let mut out = [0u8; 2];
    assert!(encoding::decode_base64(b"AAB=", &mut out).is_err());
    encoding::decode_base64(b"AAA=", &mut out).unwrap();
}

#[test]
fn review_near_memory_limit_fits() {
    // Mirrors near_limit_payload in the Ragger suite.
    let v = vectors();
    let dir = "very/long/import/path/for/limits";
    let near_limit = |padding: usize| {
        case(&v, "addpkg_limits")
            .replace(dir, &format!("{dir}{}", "/x".repeat(padding)))
            .replace(
                &format!("\"memo\":\"{}", "m".repeat(256)),
                &format!("\"memo\":\"{}", "m".repeat(512)),
            )
    };
    assert_eq!(
        parse(&v.address, &near_limit(30)).err(),
        Some(Error::ReviewTooLarge)
    );
    let r = parse(&v.address, &near_limit(5)).unwrap();
    assert!(r.fields.len() >= host_tests::tx::MAX_REVIEW_FIELDS - 1);
    let bytes: usize = r
        .fields
        .iter()
        .map(|f| f.name.len() + f.value.len() + 2)
        .sum();
    assert!(bytes > host_tests::tx::MAX_REVIEW_BYTES * 9 / 10, "{bytes}");
}

#[test]
fn every_review_starts_with_the_signer() {
    let v = vectors();
    for (name, doc) in &v.cases {
        let r = parse(&v.address, doc).unwrap();
        assert_eq!(r.fields[0].name, "Signer", "{name}");
        assert_eq!(r.fields[0].value, v.address, "{name}");
    }
}

fn memo_doc(v: &Vectors, memo_json: &str) -> String {
    case(v, "send_zero_fee_memo")
        .replace("\"memo\":\"thanks\"", &format!("\"memo\":\"{memo_json}\""))
}

#[test]
fn strings_must_be_encoded_as_gno_encodes_them() {
    let v = vectors();
    // gno's own rendering of every escaped class is accepted and displayed
    // byte for byte.
    let doc = case(&v, "memo_escapes");
    let decoded: Value = serde_json::from_str(&doc).unwrap();
    let mut expected = String::new();
    encoding::push_display(&mut expected, decoded["memo"].as_str().unwrap().as_bytes());
    let f = fields(&parse(&v.address, &doc).unwrap());
    assert_eq!(f.iter().find(|(n, _)| n == "Memo").unwrap().1, expected);

    // Other spellings of the same characters would be re-rendered differently
    // by gno, so the signature could never verify: refuse them.
    for memo in [
        "\\/",
        "\\u0041",
        "\\u001F",
        "\\u0008",
        "\\u000a",
        "\\ud83d\\ude00",
        "\\ufffd",
        "<",
        "&",
        "\u{2028}",
        "\u{1}",
    ] {
        assert_eq!(
            parse(&v.address, &memo_doc(&v, memo)).err(),
            Some(Error::InvalidEncoding),
            "{memo:?}"
        );
    }
    for memo in ["\\u001f", "\\b", "\\u003c", "\\u2029", "\u{e9}\u{1f600}"] {
        assert!(parse(&v.address, &memo_doc(&v, memo)).is_ok(), "{memo:?}");
    }

    // Raw bytes must be valid UTF-8: gno replaces anything else.
    let base = memo_doc(&v, "MEMO");
    let at = base.find("MEMO").unwrap();
    for bad in [
        &[0xffu8][..],
        &[0xc0, 0x80],
        &[0xed, 0xa0, 0x80],
        &[0xe2, 0x82],
        &[0xf5, 0x80, 0x80, 0x80],
    ] {
        let mut doc = base.as_bytes()[..at].to_vec();
        doc.extend_from_slice(bad);
        doc.extend_from_slice(&base.as_bytes()[at + 4..]);
        for chunk in [1, 255] {
            assert_eq!(
                parse_chunked(&v.address, &doc, chunk).err(),
                Some(Error::InvalidEncoding),
                "{bad:x?} chunk {chunk}"
            );
        }
    }
}

#[test]
fn coins_must_be_valid_tm2_coins() {
    let v = vectors();
    let send = |amount: &str| case(&v, "send").replace("1234567ugnot", amount);
    for bad in [
        "0ugnot",
        "1ugnot,2ugnot",
        "1zzz,1ugnot",
        "01ugnot",
        "1ugnot,",
    ] {
        assert_eq!(
            parse(&v.address, &send(bad)).err(),
            Some(Error::InvalidCoins),
            "{bad}"
        );
    }
    let f = fields(&parse(&v.address, &send("1ugnot,2zzz")).unwrap());
    assert!(f.contains(&("Amount".into(), "0.000001 GNOT, 2 zzz".into())));
}

#[test]
fn fee_is_one_positive_coin() {
    let v = vectors();
    let coin = "{\"amount\":\"1000\",\"denom\":\"ugnot\"}";
    let zero = case(&v, "send").replace(coin, "{\"amount\":\"0\",\"denom\":\"ugnot\"}");
    assert_eq!(parse(&v.address, &zero).err(), Some(Error::InvalidCoins));
    let two = case(&v, "send").replace(coin, &format!("{coin},{coin}"));
    assert_eq!(parse(&v.address, &two).err(), Some(Error::InvalidCoins));

    // A second coin is refused as soon as it is read, so an endless fee array
    // cannot grow the review before the payload ends.
    let mut p = Parser::<HostHashes>::new(signer(&v.address));
    let prefix = format!(
        "{{\"account_number\":\"7\",\"chain_id\":\"test-chain\",\"fee\":{{\"amount\":[{coin},{coin}"
    );
    assert_eq!(p.feed(prefix.as_bytes()).err(), Some(Error::InvalidCoins));
}

#[test]
fn max_deposit_is_an_explicit_ugnot_cap_or_the_default() {
    let v = vectors();
    let call = case(&v, "call");
    assert!(call.contains("\"max_deposit\":\"\""));
    // gno ignores every denom but ugnot and falls back to the chain default,
    // so showing these as caps would misstate what the chain enforces.
    for bad in ["1foo", "0ugnot", "1ugnot,1zzz", "ugnot"] {
        let doc = call.replace(
            "\"max_deposit\":\"\"",
            &format!("\"max_deposit\":\"{bad}\""),
        );
        assert_eq!(
            parse(&v.address, &doc).err(),
            Some(Error::InvalidCoins),
            "{bad}"
        );
    }
    let doc = call.replace("\"max_deposit\":\"\"", "\"max_deposit\":\"2500000ugnot\"");
    let f = fields(&parse(&v.address, &doc).unwrap());
    assert!(f.contains(&("Max deposit".into(), "2.5 GNOT".into())));
}

#[test]
fn sessions_that_can_run_code_need_the_packages_setting() {
    let v = vectors();
    let r = parse(&v.address, &case(&v, "create_session_run")).unwrap();
    assert!(r.runs_code && !r.blind);
    let f = fields(&r);
    assert_eq!(
        f[..2],
        pairs(&[
            ("Type", "Create session"),
            ("Warning", "Session may run any script as you"),
        ])[..]
    );
    assert!(f.contains(&("Allowed".into(), "vm/run".into())));

    assert!(
        parse(&v.address, &case(&v, "create_session_minimal"))
            .unwrap()
            .runs_code
    );
    assert!(
        !parse(&v.address, &case(&v, "create_session"))
            .unwrap()
            .runs_code
    );
    for name in ["addpkg", "run"] {
        let r = parse(&v.address, &case(&v, name)).unwrap();
        assert!(r.runs_code && r.blind, "{name}");
    }
    for name in ["send", "call", "enable_pkg"] {
        assert!(
            !parse(&v.address, &case(&v, name)).unwrap().runs_code,
            "{name}"
        );
    }
}

#[test]
fn lifetime_spend_limit_is_a_warning() {
    let v = vectors();
    let doc = case(&v, "create_session").replace(",\"spend_period\":\"86400\"", "");
    let f = fields(&parse(&v.address, &doc).unwrap());
    assert!(f.contains(&("Warning".into(), "Spend limit never resets".into())));
    assert!(f.contains(&("Spend period".into(), "Lifetime (never resets)".into())));
}

/// An addpkg whose files are replaced by `names`, each with a tiny body.
fn addpkg_with_files(v: &Vectors, names: &[String]) -> String {
    let doc = case(v, "addpkg");
    let start = doc.find("\"files\":[").unwrap() + "\"files\":[".len();
    let end = doc.find("],\"name\":\"hello\"").unwrap();
    let files: Vec<String> = names
        .iter()
        .map(|n| format!("{{\"body\":\"package hello\\n\",\"name\":\"{n}\"}}"))
        .collect();
    format!("{}{}{}", &doc[..start], files.join(","), &doc[end..])
}

#[test]
fn escaped_file_names_are_charged_before_they_are_kept() {
    let v = vectors();
    // Each name decodes to 200 NULs, which display as 800 characters.
    let names: Vec<String> = (0..16)
        .map(|i| format!("{}f{i:02}.gno", "\\u0000".repeat(200)))
        .collect();
    assert_eq!(
        parse(&v.address, &addpkg_with_files(&v, &names)).err(),
        Some(Error::ReviewTooLarge)
    );
}

#[test]
fn errors_do_not_depend_on_chunking() {
    // Found by fuzz_parser: an over-long memo followed by an invalid byte.
    let v = vectors();
    let doc = memo_doc(
        &v,
        &format!("{}\u{1}", "m".repeat(host_tests::tx::MAX_VALUE_LEN + 10)),
    );
    for chunk in [1, 7, 255, doc.len()] {
        assert_eq!(
            parse_chunked(&v.address, doc.as_bytes(), chunk).err(),
            Some(Error::ValueTooLong),
            "chunk {chunk}"
        );
    }
}
