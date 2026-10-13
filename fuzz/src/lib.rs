//! Shared oracles for the fuzz targets.

use serde_json::Value;

/// The address the gno vectors are signed with, so seeds pass the signer check.
pub const SIGNER: &[u8; 40] = b"g1lw3n03x3zcqgxncq866pl8np5spd2kpdy7x0vf";

/// Re-encodes a JSON value the way gno does: Go's `encoding/json`, keys in
/// their existing order, no whitespace. A sign doc the device accepts must be
/// byte for byte this encoding of itself.
pub fn go_json(v: &Value, out: &mut String) {
    match v {
        Value::Object(map) => {
            out.push('{');
            for (i, (k, v)) in map.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                go_string(k, out);
                out.push(':');
                go_json(v, out);
            }
            out.push('}');
        }
        Value::Array(items) => {
            out.push('[');
            for (i, v) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                go_json(v, out);
            }
            out.push(']');
        }
        Value::String(s) => go_string(s, out),
        // The device accepts no numbers, booleans or nulls.
        _ => out.push('\u{0}'),
    }
}

fn go_string(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{8}' => out.push_str("\\b"),
            '\t' => out.push_str("\\t"),
            '\n' => out.push_str("\\n"),
            '\u{c}' => out.push_str("\\f"),
            '\r' => out.push_str("\\r"),
            '<' | '>' | '&' | '\u{2028}' | '\u{2029}' => {
                out.push_str(&format!("\\u{:04x}", c as u32))
            }
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
}

/// Splits `data` into chunks whose sizes cycle through `sizes`.
pub fn chunks<'a>(data: &'a [u8], sizes: &[u8]) -> Vec<&'a [u8]> {
    let mut out = Vec::new();
    let mut rest = data;
    let mut i = 0;
    while !rest.is_empty() {
        let n = sizes
            .get(i % sizes.len().max(1))
            .map_or(255, |&s| s.max(1) as usize);
        let (head, tail) = rest.split_at(n.min(rest.len()));
        out.push(head);
        rest = tail;
        i += 1;
    }
    out
}
