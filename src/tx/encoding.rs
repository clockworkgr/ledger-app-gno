//! Text encodings the sign doc uses, and the display forms derived from them.

use alloc::string::String;
use core::fmt::Write;

use super::Error;

pub const ADDRESS_HRP: &str = "g";
/// `g1` + 32 data characters + 6 checksum characters.
pub const ADDRESS_LEN: usize = 40;

const BECH32_CHARSET: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const BECH32_GENERATOR: [u32; 5] = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];

fn bech32_polymod_step(chk: u32, value: u8) -> u32 {
    let top = chk >> 25;
    let mut chk = ((chk & 0x1ff_ffff) << 5) ^ value as u32;
    for (i, g) in BECH32_GENERATOR.iter().enumerate() {
        if (top >> i) & 1 == 1 {
            chk ^= g;
        }
    }
    chk
}

fn bech32_hrp_checksum_state(hrp: &[u8]) -> u32 {
    let mut chk = 1;
    for &c in hrp {
        chk = bech32_polymod_step(chk, c >> 5);
    }
    chk = bech32_polymod_step(chk, 0);
    for &c in hrp {
        chk = bech32_polymod_step(chk, c & 31);
    }
    chk
}

/// Regroups `addr` into the 32 five-bit values bech32 encodes.
fn address_to_u5(addr: &[u8; 20]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let (mut acc, mut bits, mut n) = (0u32, 0u32, 0usize);
    for &b in addr {
        acc = (acc << 8) | b as u32;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out[n] = ((acc >> bits) & 31) as u8;
            n += 1;
        }
    }
    out
}

/// Encodes a 20-byte account address as `g1...`.
pub fn encode_address(addr: &[u8; 20]) -> [u8; ADDRESS_LEN] {
    let data = address_to_u5(addr);
    let mut chk = bech32_hrp_checksum_state(ADDRESS_HRP.as_bytes());
    for &d in &data {
        chk = bech32_polymod_step(chk, d);
    }
    for _ in 0..6 {
        chk = bech32_polymod_step(chk, 0);
    }
    chk ^= 1;

    let mut out = [0u8; ADDRESS_LEN];
    out[0] = b'g';
    out[1] = b'1';
    for (o, &d) in out[2..34].iter_mut().zip(data.iter()) {
        *o = BECH32_CHARSET[d as usize];
    }
    for i in 0..6 {
        out[34 + i] = BECH32_CHARSET[((chk >> (5 * (5 - i))) & 31) as usize];
    }
    out
}

/// Checks that `s` is a lowercase `g1...` address with a valid checksum.
///
/// Uppercase is valid bech32, but gno renders addresses in lowercase, and
/// accepting both would let two different sign docs display identically.
pub fn validate_address(s: &[u8]) -> Result<(), Error> {
    if s.len() != ADDRESS_LEN || &s[..2] != b"g1" {
        return Err(Error::InvalidAddress);
    }
    let mut chk = bech32_hrp_checksum_state(ADDRESS_HRP.as_bytes());
    let mut data = [0u8; ADDRESS_LEN - 2];
    for (d, &c) in data.iter_mut().zip(&s[2..]) {
        *d = BECH32_CHARSET
            .iter()
            .position(|&x| x == c)
            .ok_or(Error::InvalidAddress)? as u8;
        chk = bech32_polymod_step(chk, *d);
    }
    if chk != 1 {
        return Err(Error::InvalidAddress);
    }
    // 32 five-bit groups carry 160 bits exactly, so there is no padding to check.
    Ok(())
}

/// Decodes standard, padded base64 into `out`, which it must fill exactly.
pub fn decode_base64(s: &[u8], out: &mut [u8]) -> Result<(), Error> {
    fn sextet(c: u8) -> Result<u32, Error> {
        Ok(match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => return Err(Error::InvalidEncoding),
        } as u32)
    }

    let padded_len = out.len().div_ceil(3) * 4;
    if s.len() != padded_len {
        return Err(Error::InvalidEncoding);
    }
    let pad = (3 - out.len() % 3) % 3;
    let mut n = 0;
    for (ci, chunk) in s.chunks(4).enumerate() {
        let last = ci == s.len() / 4 - 1;
        let mut acc = 0u32;
        for (j, &c) in chunk.iter().enumerate() {
            let v = if last && j >= 4 - pad {
                if c != b'=' {
                    return Err(Error::InvalidEncoding);
                }
                0
            } else {
                sextet(c)?
            };
            acc = (acc << 6) | v;
        }
        let bytes = acc.to_be_bytes();
        let take = if last { 3 - pad } else { 3 };
        // Non-canonical encodings put data in the bits padding discards.
        if last && (acc & ((1 << (8 * pad)) - 1)) != 0 {
            return Err(Error::InvalidEncoding);
        }
        out[n..n + take].copy_from_slice(&bytes[1..1 + take]);
        n += take;
    }
    Ok(())
}

/// Parses a canonical decimal: digits only, no sign, no leading zeros.
pub fn parse_u64(s: &[u8]) -> Result<u64, Error> {
    if s.is_empty() || (s.len() > 1 && s[0] == b'0') {
        return Err(Error::InvalidNumber);
    }
    s.iter().try_fold(0u64, |acc, &c| {
        if !c.is_ascii_digit() {
            return Err(Error::InvalidNumber);
        }
        acc.checked_mul(10)
            .and_then(|v| v.checked_add((c - b'0') as u64))
            .ok_or(Error::InvalidNumber)
    })
}

/// Parses a canonical decimal that also fits tm2's `int64`.
pub fn parse_i64_nonneg(s: &[u8]) -> Result<u64, Error> {
    let v = parse_u64(s)?;
    if v > i64::MAX as u64 {
        return Err(Error::InvalidNumber);
    }
    Ok(v)
}

/// Mirrors tm2's `reDnmString`, `[a-z/][a-z0-9_.:/-]{2,}`. A leading `/` marks
/// a realm-issued denom, which is why only the exact string `ugnot` is ever
/// rendered as GNOT.
fn valid_denom(d: &[u8]) -> bool {
    d.len() >= 3
        && matches!(d[0], b'a'..=b'z' | b'/')
        && d[1..]
            .iter()
            .all(|c| matches!(c, b'a'..=b'z' | b'0'..=b'9' | b'_' | b'.' | b':' | b'/' | b'-'))
}

/// Appends `amount` of `denom` to `out`, rendering ugnot as GNOT.
pub fn write_amount(out: &mut String, amount: u64, denom: &[u8]) -> Result<(), Error> {
    if !valid_denom(denom) {
        return Err(Error::InvalidCoins);
    }
    if denom == b"ugnot" {
        let whole = amount / 1_000_000;
        let frac = amount % 1_000_000;
        if frac == 0 {
            write!(out, "{} GNOT", whole).map_err(|_| Error::ReviewTooLarge)?;
        } else {
            let mut digits = [0u8; 6];
            let mut f = frac;
            for d in digits.iter_mut().rev() {
                *d = b'0' + (f % 10) as u8;
                f /= 10;
            }
            let end = 6 - digits.iter().rev().take_while(|&&d| d == b'0').count();
            let frac_str = core::str::from_utf8(&digits[..end]).map_err(|_| Error::InvalidCoins)?;
            write!(out, "{}.{} GNOT", whole, frac_str).map_err(|_| Error::ReviewTooLarge)?;
        }
    } else {
        let denom = core::str::from_utf8(denom).map_err(|_| Error::InvalidCoins)?;
        write!(out, "{} {}", amount, denom).map_err(|_| Error::ReviewTooLarge)?;
    }
    Ok(())
}

/// Renders a tm2 coins string (`"1000ugnot,5foo"`, or `""`) for display.
///
/// Returns `None` for the empty set so callers can say what empty means for
/// their field.
pub fn format_coins(s: &[u8]) -> Result<Option<String>, Error> {
    if s.is_empty() {
        return Ok(None);
    }
    let mut out = String::new();
    for (i, coin) in s.split(|&c| c == b',').enumerate() {
        let split = coin
            .iter()
            .position(|c| !c.is_ascii_digit())
            .ok_or(Error::InvalidCoins)?;
        let amount = parse_i64_nonneg(&coin[..split]).map_err(|_| Error::InvalidCoins)?;
        if i > 0 {
            out.push_str(", ");
        }
        write_amount(&mut out, amount, &coin[split..])?;
    }
    Ok(Some(out))
}

/// Renders a unix timestamp as `YYYY-MM-DD HH:MM:SS UTC`.
pub fn format_utc(ts: u64) -> String {
    let days = (ts / 86_400) as i64;
    let secs = ts % 86_400;
    // Civil-from-days, Howard Hinnant's algorithm, restricted to ts >= 0.
    let z = days + 719_468;
    let era = z / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + if month <= 2 { 1 } else { 0 };
    let mut out = String::new();
    let _ = write!(
        out,
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02} UTC",
        year,
        month,
        day,
        secs / 3600,
        (secs / 60) % 60,
        secs % 60
    );
    out
}

/// Renders arbitrary bytes as unambiguous printable ASCII.
///
/// Anything outside printable ASCII, and the backslash itself, is shown as
/// `\xNN`, so no two distinct values display alike and the device font never
/// meets a byte it cannot draw.
pub fn push_display(out: &mut String, bytes: &[u8]) {
    for &b in bytes {
        match b {
            b'\\' => out.push_str("\\\\"),
            0x20..=0x7e => out.push(b as char),
            _ => {
                let _ = write!(out, "\\x{:02x}", b);
            }
        }
    }
}

pub fn push_hex(out: &mut String, bytes: &[u8]) {
    for b in bytes {
        let _ = write!(out, "{:02x}", b);
    }
}

pub fn is_lower_hex(s: &[u8]) -> bool {
    s.iter().all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f'))
}
