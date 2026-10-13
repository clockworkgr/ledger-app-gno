//! Streaming parser for gno.land signature payloads.
//!
//! This module has no dependency on the device SDK: hashing is injected through
//! [`Hashes`], so the same code runs on the device and in host-side tests that
//! replay payloads rendered by upstream gno.

pub mod encoding;
pub mod json;
mod schema;
pub mod source;

use alloc::borrow::Cow;
use alloc::string::String;
use alloc::vec::Vec;

use encoding::ADDRESS_LEN;
use json::{Lexer, Sink};
use schema::{Entry, Leaf, MessageKind, Node, Typed};
use source::{Findings, Scanner};

/// Longest string value kept in RAM for validation or display.
pub const MAX_VALUE_LEN: usize = 512;
/// Upper bound on the review's total text, which NBGL copies once more. With
/// `MAX_REVIEW_FIELDS`, sized so the largest review fits Nano X's 16 KiB heap.
pub const MAX_REVIEW_BYTES: usize = 3072;
pub const MAX_REVIEW_FIELDS: usize = 56;
pub const MAX_MESSAGES: usize = 8;
/// Files named in a package review; the rest are counted.
pub const MAX_LISTED_FILES: usize = 16;
const MAX_FILE_NAME_LEN: usize = 256;
const SCHEMA_DEPTH: usize = 8;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Syntax,
    Truncated,
    TrailingData,
    TooDeep,
    UnknownKey,
    MissingKey,
    UnexpectedType,
    UnknownMessage,
    InvalidAddress,
    InvalidNumber,
    InvalidCoins,
    InvalidEncoding,
    InvalidValue,
    SignerMismatch,
    ValueTooLong,
    ReviewTooLarge,
    TooManyMessages,
    UnsortedFiles,
}

/// A SHA-256 context.
pub trait Sha256 {
    fn new() -> Self;
    fn update(&mut self, data: &[u8]);
    fn finalize(self) -> [u8; 32];
}

/// The hash primitives the parser needs, supplied by the platform.
pub trait Hashes {
    type Sha256: Sha256;
    /// `RIPEMD160(SHA256(data))`, the tm2 address of a public key.
    fn hash160(data: &[u8]) -> [u8; 20];
}

pub struct ReviewField {
    /// Almost always a static label, so it costs no heap.
    pub name: Cow<'static, str>,
    pub value: String,
    /// Order within its message; see `rank` constants in `schema`.
    rank: u16,
}

/// What the user is shown before approving the signature.
pub struct Review {
    pub fields: Vec<ReviewField>,
    /// True when the payload carries source code that cannot be reviewed on
    /// the device (`m_addpkg`, `m_run`).
    pub blind: bool,
}

#[derive(Clone, Copy)]
enum Frame {
    Object {
        entries: &'static [Entry],
        next: usize,
        /// Set until the `@type` key of a typed object has been read.
        typed: Option<Typed>,
        scope: Scope,
    },
    Array {
        elem: &'static Node,
        count: usize,
        min: usize,
    },
}

/// Which object a frame is, where its end triggers work.
#[derive(Clone, Copy, PartialEq)]
enum Scope {
    Plain,
    Message,
    Package,
    File,
}

#[derive(Default)]
struct MessageState {
    kind: Option<MessageKind>,
    start: usize,
    arg_index: u16,
    seen_spend_limit: bool,
    seen_spend_period: bool,
}

struct PackageState<H: Hashes> {
    fingerprint: H::Sha256,
    body: Option<H::Sha256>,
    body_hash: [u8; 32],
    body_len: u64,
    /// Scans the body being read; its file name only follows the body.
    scanner: Option<Scanner>,
    /// The last body's findings, kept until its name says whether it executes.
    pending: Option<Findings>,
    found: Findings,
    listed: Vec<String>,
    prev_name: [u8; MAX_FILE_NAME_LEN],
    prev_name_len: usize,
    files: u32,
    bytes: u64,
}

pub struct Parser<H: Hashes> {
    lexer: Lexer,
    stack: [Option<Frame>; SCHEMA_DEPTH],
    depth: usize,
    /// The node the next value must match.
    expect: Option<Node>,
    /// The leaf currently being read, if any.
    leaf: Option<Leaf>,
    value: Vec<u8>,
    signer: [u8; ADDRESS_LEN],

    review: Review,
    review_bytes: usize,
    messages: usize,
    message: MessageState,
    chain_id: String,
    fee: String,
    fee_amount: u64,
    gas: String,
    memo: String,
    package: Option<PackageState<H>>,
}

impl<H: Hashes> Parser<H> {
    /// Starts parsing a payload that must be signed by `signer`.
    pub fn new(signer: [u8; ADDRESS_LEN]) -> Self {
        Parser {
            lexer: Lexer::new(),
            stack: [None; SCHEMA_DEPTH],
            depth: 0,
            expect: Some(Node::Obj(schema::SIGN_DOC)),
            leaf: None,
            value: Vec::new(),
            signer,
            review: Review {
                fields: Vec::new(),
                blind: false,
            },
            review_bytes: 0,
            messages: 0,
            message: MessageState::default(),
            chain_id: String::new(),
            fee: String::new(),
            fee_amount: 0,
            gas: String::new(),
            memo: String::new(),
            package: None,
        }
    }

    pub fn feed(&mut self, data: &[u8]) -> Result<(), Error> {
        let mut lexer = core::mem::take(&mut self.lexer);
        let result = lexer.feed(data, self);
        self.lexer = lexer;
        result
    }

    /// Completes parsing and returns what must be shown to the user. Takes
    /// `&mut self` so a boxed parser is never moved onto the stack.
    pub fn finish(&mut self) -> Result<Review, Error> {
        self.lexer.finish()?;
        if self.messages == 0 {
            return Err(Error::MissingKey);
        }
        if self.messages > 1 {
            let mut n = 0;
            for f in self.review.fields.iter_mut() {
                if f.rank == schema::rank::TYPE {
                    n += 1;
                    f.name = Cow::Owned(alloc::format!("Message {}", n));
                }
            }
        }
        if !self.memo.is_empty() {
            let memo = core::mem::take(&mut self.memo);
            self.push("Memo", memo, 0)?;
        }
        let fee = core::mem::take(&mut self.fee);
        let fee = if fee.is_empty() {
            String::from("None")
        } else {
            fee
        };
        self.push("Fee", fee, 0)?;
        let gas = core::mem::take(&mut self.gas);
        self.push("Gas limit", gas, 0)?;
        let chain_id = core::mem::take(&mut self.chain_id);
        self.push("Chain ID", chain_id, 0)?;
        Ok(core::mem::replace(
            &mut self.review,
            Review {
                fields: Vec::new(),
                blind: false,
            },
        ))
    }

    fn push(&mut self, name: &'static str, value: String, rank: u16) -> Result<(), Error> {
        self.push_field(Cow::Borrowed(name), value, rank)
    }

    fn push_owned(&mut self, name: String, value: String, rank: u16) -> Result<(), Error> {
        self.push_field(Cow::Owned(name), value, rank)
    }

    fn push_field(
        &mut self,
        name: Cow<'static, str>,
        mut value: String,
        rank: u16,
    ) -> Result<(), Error> {
        self.review_bytes += name.len() + value.len() + 2;
        if self.review_bytes > MAX_REVIEW_BYTES || self.review.fields.len() == MAX_REVIEW_FIELDS {
            return Err(Error::ReviewTooLarge);
        }
        // Values grow byte by byte; the review is held until approval.
        value.shrink_to_fit();
        self.review.fields.push(ReviewField { name, value, rank });
        Ok(())
    }

    fn top(&mut self) -> Option<&mut Frame> {
        match self.depth {
            0 => None,
            d => self.stack[d - 1].as_mut(),
        }
    }

    fn push_frame(&mut self, frame: Frame) -> Result<(), Error> {
        if self.depth == SCHEMA_DEPTH {
            return Err(Error::TooDeep);
        }
        self.stack[self.depth] = Some(frame);
        self.depth += 1;
        Ok(())
    }

    fn pop_frame(&mut self) -> Result<Frame, Error> {
        if self.depth == 0 {
            return Err(Error::Syntax);
        }
        self.depth -= 1;
        self.stack[self.depth].take().ok_or(Error::Syntax)
    }

    /// Takes the node the current value must match, refusing a second value.
    fn take_expected(&mut self) -> Result<Node, Error> {
        if let Some(Frame::Array { elem, count, .. }) = self.top() {
            *count += 1;
            return Ok(**elem);
        }
        self.expect.take().ok_or(Error::Syntax)
    }

    fn signer_field(&self, value: &[u8]) -> Result<(), Error> {
        if value != self.signer {
            return Err(Error::SignerMismatch);
        }
        Ok(())
    }

    fn end_leaf(&mut self, leaf: Leaf) -> Result<(), Error> {
        use schema::rank;
        let v = core::mem::take(&mut self.value);
        match leaf {
            Leaf::TypeTag => return self.end_type_tag(&v),
            Leaf::ChainId => {
                if v.is_empty() {
                    return Err(Error::InvalidValue);
                }
                encoding::push_display(&mut self.chain_id, &v);
            }
            Leaf::AccountNumber | Leaf::Sequence => {
                encoding::parse_u64(&v)?;
            }
            Leaf::Memo => encoding::push_display(&mut self.memo, &v),
            Leaf::Gas => {
                encoding::parse_i64_nonneg(&v)?;
                encoding::push_display(&mut self.gas, &v);
            }
            Leaf::FeeAmount => {
                self.fee_amount =
                    encoding::parse_i64_nonneg(&v).map_err(|_| Error::InvalidCoins)?;
            }
            Leaf::FeeDenom => {
                if !self.fee.is_empty() {
                    self.fee.push_str(", ");
                }
                encoding::write_amount(&mut self.fee, self.fee_amount, &v)?;
            }
            Leaf::Signer => self.signer_field(&v)?,
            Leaf::Address(label, r) => {
                encoding::validate_address(&v)?;
                let mut s = String::new();
                encoding::push_display(&mut s, &v);
                self.push(label, s, r)?;
            }
            Leaf::Coins { label, empty, rank } => match (encoding::format_coins(&v)?, empty) {
                (Some(s), _) => self.push(label, s, rank)?,
                (None, Some(text)) => self.push(label, String::from(text), rank)?,
                (None, None) => return Err(Error::InvalidCoins),
            },
            Leaf::SpendLimit => {
                self.message.seen_spend_limit = true;
                let s = encoding::format_coins(&v)?.ok_or(Error::InvalidCoins)?;
                self.push("Spend limit", s, rank::SPEND_LIMIT)?;
            }
            Leaf::SpendPeriod => {
                self.message.seen_spend_period = true;
                // amino omits a zero period, so a present one is positive.
                let secs = encoding::parse_i64_nonneg(&v)?;
                if secs == 0 {
                    return Err(Error::InvalidValue);
                }
                self.push(
                    "Spend period",
                    alloc::format!("{} seconds", secs),
                    rank::SPEND_PERIOD,
                )?;
            }
            Leaf::Text(label, r) => {
                let mut s = String::new();
                encoding::push_display(&mut s, &v);
                self.push(label, s, r)?;
            }
            Leaf::Arg => {
                self.message.arg_index += 1;
                let n = self.message.arg_index;
                let mut s = String::new();
                encoding::push_display(&mut s, &v);
                self.push_owned(alloc::format!("Arg {}", n), s, rank::ARGS + n)?;
            }
            Leaf::AllowPath => {
                if v == b"*" {
                    self.push(
                        "Warning",
                        String::from("Session may sign any message type"),
                        rank::WARNING,
                    )?;
                }
                let mut s = String::new();
                encoding::push_display(&mut s, &v);
                self.push("Allowed", s, rank::ALLOW_PATH)?;
            }
            Leaf::ExpiresAt => {
                let ts = encoding::parse_i64_nonneg(&v)?;
                let s = if ts == 0 {
                    self.push(
                        "Warning",
                        String::from("Session never expires"),
                        rank::WARNING,
                    )?;
                    String::from("Never")
                } else {
                    encoding::format_utc(ts)
                };
                self.push("Expires", s, rank::EXPIRES)?;
            }
            Leaf::PubKey => {
                let mut key = [0u8; 33];
                encoding::decode_base64(&v, &mut key)?;
                if key[0] != 0x02 && key[0] != 0x03 {
                    return Err(Error::InvalidEncoding);
                }
                let addr = encoding::encode_address(&H::hash160(&key));
                let mut s = String::new();
                encoding::push_display(&mut s, &addr);
                self.push("Session key", s, rank::SESSION_KEY)?;
            }
            Leaf::PkgHash => {
                if v.len() != 64 || !encoding::is_lower_hex(&v) {
                    return Err(Error::InvalidValue);
                }
                let mut s = String::new();
                encoding::push_display(&mut s, &v);
                self.push("Package hash", s, rank::PKG_HASH)?;
            }
            Leaf::PkgHeight => {
                let h = encoding::parse_i64_nonneg(&v)?;
                if h == 0 {
                    self.push(
                        "Warning",
                        String::from("Approval is not pinned to a submission"),
                        rank::WARNING,
                    )?;
                }
                self.push(
                    "Submitted at",
                    alloc::format!("block {}", h),
                    rank::PKG_HEIGHT,
                )?;
            }
            Leaf::PkgName => {
                if v.is_empty() {
                    return Err(Error::InvalidValue);
                }
                let mut s = String::new();
                encoding::push_display(&mut s, &v);
                self.push("Package name", s, rank::PKG_NAME)?;
            }
            Leaf::PkgPath => {
                let mut s = String::new();
                if v.is_empty() {
                    s.push_str("(assigned by chain)");
                } else {
                    encoding::push_display(&mut s, &v);
                }
                self.push("Package", s, rank::PKG_PATH)?;
            }
            Leaf::PkgType => {
                if v != b"MPUserAll" && v != b"MPUserProd" {
                    return Err(Error::InvalidValue);
                }
            }
            Leaf::FileBody => {
                let pkg = self.package.as_mut().ok_or(Error::Syntax)?;
                let body = pkg.body.take().ok_or(Error::Syntax)?;
                pkg.body_hash = body.finalize();
                pkg.pending = Some(pkg.scanner.take().ok_or(Error::Syntax)?.finish());
            }
            Leaf::FileName => {
                let pkg = self.package.as_mut().ok_or(Error::Syntax)?;
                let prev = &pkg.prev_name[..pkg.prev_name_len];
                if v.is_empty() || (pkg.files > 0 && v.as_slice() <= prev) {
                    return Err(Error::UnsortedFiles);
                }
                // Each file contributes len(name) || name || SHA256(body); see
                // docs/APDU.md for the full fingerprint definition.
                pkg.fingerprint.update(&(v.len() as u32).to_be_bytes());
                pkg.fingerprint.update(&v);
                pkg.fingerprint.update(&pkg.body_hash);
                pkg.prev_name[..v.len()].copy_from_slice(&v);
                pkg.prev_name_len = v.len();
                pkg.files += 1;
                let findings = pkg.pending.take().ok_or(Error::Syntax)?;
                if source::executes(&v) {
                    pkg.found.merge(findings);
                }
                if pkg.listed.len() < MAX_LISTED_FILES {
                    let mut s = String::new();
                    encoding::push_display(&mut s, &v);
                    s.push_str(&alloc::format!(" ({} bytes)", pkg.body_len));
                    pkg.listed.push(s);
                }
            }
        }
        self.value = v;
        self.value.clear();
        Ok(())
    }

    fn end_type_tag(&mut self, tag: &[u8]) -> Result<(), Error> {
        let Some(Frame::Object {
            entries,
            next,
            typed,
            scope,
        }) = self.top()
        else {
            return Err(Error::Syntax);
        };
        let kind = typed.take().ok_or(Error::Syntax)?;
        let (selected, info) = schema::lookup(kind, tag).ok_or(match kind {
            Typed::Message => Error::UnknownMessage,
            _ => Error::InvalidValue,
        })?;
        *entries = selected;
        *next = 0;
        let is_message = *scope == Scope::Message;

        if is_message {
            let info = info.ok_or(Error::Syntax)?;
            self.messages += 1;
            if self.messages > MAX_MESSAGES {
                return Err(Error::TooManyMessages);
            }
            self.message = MessageState {
                kind: Some(info.kind),
                start: self.review.fields.len(),
                ..Default::default()
            };
            self.review.blind |= info.blind;
            self.push("Type", String::from(info.title), schema::rank::TYPE)?;
            if info.kind == MessageKind::Run {
                self.push(
                    "Warning",
                    String::from("Script can do anything your account can"),
                    schema::rank::WARNING,
                )?;
            }
        }
        self.value.clear();
        Ok(())
    }

    fn end_message(&mut self) -> Result<(), Error> {
        use schema::rank;
        // Absent omitempty fields still change what the message means.
        if self.message.kind == Some(MessageKind::CreateSession) {
            if !self.message.seen_spend_limit {
                self.push(
                    "Spend limit",
                    String::from("None (cannot spend)"),
                    rank::SPEND_LIMIT,
                )?;
            } else if !self.message.seen_spend_period {
                self.push(
                    "Spend period",
                    String::from("Lifetime (never resets)"),
                    rank::SPEND_PERIOD,
                )?;
            }
        }
        // Stable, so repeated labels keep their payload order.
        self.review.fields[self.message.start..].sort_by_key(|f| f.rank);
        Ok(())
    }

    /// Shows what the executed source imports and which addresses it spells
    /// out. Lists past their limit are announced, never silently cut.
    fn push_findings(&mut self, found: &Findings) -> Result<(), Error> {
        use schema::rank;
        if found.long_import {
            return Err(Error::ValueTooLong);
        }
        if found.more_imports {
            self.push(
                "Warning",
                alloc::format!("Over {} imports, not all shown", source::MAX_IMPORTS),
                rank::WARNING,
            )?;
        }
        if found.more_addresses {
            self.push(
                "Warning",
                alloc::format!(
                    "Over {} addresses in code, not all shown",
                    source::MAX_ADDRESSES
                ),
                rank::WARNING,
            )?;
        }
        if found.imports.is_empty() {
            self.push("Imports", String::from("None"), rank::PKG_IMPORTS)?;
        }
        for path in &found.imports {
            let mut s = String::new();
            encoding::push_display(&mut s, path);
            self.push("Import", s, rank::PKG_IMPORTS)?;
        }
        if found.addresses.is_empty() {
            self.push(
                "Addresses in code",
                String::from("None found"),
                rank::PKG_ADDRESSES,
            )?;
        }
        for addr in &found.addresses {
            let mut s = String::new();
            encoding::push_display(&mut s, addr);
            if *addr == self.signer {
                s.push_str(" (you)");
            }
            self.push("Address in code", s, rank::PKG_ADDRESSES)?;
        }
        Ok(())
    }

    fn end_package(&mut self) -> Result<(), Error> {
        use schema::rank;
        let pkg = self.package.take().ok_or(Error::Syntax)?;
        self.push_findings(&pkg.found)?;
        let mut fp = String::new();
        encoding::push_hex(&mut fp, &pkg.fingerprint.finalize());
        self.push("Files", alloc::format!("{}", pkg.files), rank::PKG_FILES)?;
        let unlisted = pkg.files as usize - pkg.listed.len();
        for name in pkg.listed {
            self.push("File", name, rank::PKG_FILE_LIST)?;
        }
        if unlisted > 0 {
            self.push(
                "File",
                alloc::format!("and {} more", unlisted),
                rank::PKG_FILE_LIST,
            )?;
        }
        self.push(
            "Source size",
            alloc::format!("{} bytes", pkg.bytes),
            rank::PKG_SIZE,
        )?;
        self.push("Fingerprint", fp, rank::PKG_FINGERPRINT)?;
        Ok(())
    }
}

impl<H: Hashes> Sink for Parser<H> {
    fn begin_object(&mut self) -> Result<(), Error> {
        let (entries, typed) = match self.take_expected()? {
            Node::Obj(entries) => (entries, None),
            Node::Typed(kind) => (schema::TYPE_ONLY, Some(kind)),
            _ => return Err(Error::UnexpectedType),
        };
        let scope = match (entries, typed) {
            (_, Some(Typed::Message)) => Scope::Message,
            (e, _) if core::ptr::eq(e, schema::PACKAGE) => Scope::Package,
            (e, _) if core::ptr::eq(e, schema::FILE) => Scope::File,
            _ => Scope::Plain,
        };
        if scope == Scope::Package {
            if self.package.is_some() {
                return Err(Error::Syntax);
            }
            self.package = Some(PackageState {
                fingerprint: H::Sha256::new(),
                body: None,
                body_hash: [0; 32],
                body_len: 0,
                scanner: None,
                pending: None,
                found: Findings::default(),
                listed: Vec::new(),
                prev_name: [0; MAX_FILE_NAME_LEN],
                prev_name_len: 0,
                files: 0,
                bytes: 0,
            });
        }
        self.push_frame(Frame::Object {
            entries,
            next: 0,
            typed,
            scope,
        })
    }

    fn end_object(&mut self) -> Result<(), Error> {
        let Frame::Object {
            entries,
            next,
            typed,
            scope,
        } = self.pop_frame()?
        else {
            return Err(Error::Syntax);
        };
        if typed.is_some() || entries[next..].iter().any(|e| e.required) {
            return Err(Error::MissingKey);
        }
        match scope {
            Scope::Message => self.end_message(),
            Scope::Package => self.end_package(),
            Scope::Plain | Scope::File => Ok(()),
        }
    }

    fn begin_array(&mut self) -> Result<(), Error> {
        let Node::Arr(elem, min) = self.take_expected()? else {
            return Err(Error::UnexpectedType);
        };
        self.push_frame(Frame::Array {
            elem,
            count: 0,
            min: min as usize,
        })
    }

    fn end_array(&mut self) -> Result<(), Error> {
        let Frame::Array { count, min, .. } = self.pop_frame()? else {
            return Err(Error::Syntax);
        };
        if count < min {
            return Err(Error::MissingKey);
        }
        Ok(())
    }

    fn key(&mut self, key: &[u8]) -> Result<(), Error> {
        let Some(Frame::Object {
            entries,
            next,
            typed,
            ..
        }) = self.top()
        else {
            return Err(Error::Syntax);
        };
        // Keys must come in schema order, which is amino's sorted order; any
        // entry skipped on the way must be optional.
        let found = entries[*next..]
            .iter()
            .position(|e| e.key.as_bytes() == key)
            .ok_or(Error::UnknownKey)?;
        if entries[*next..*next + found].iter().any(|e| e.required) {
            return Err(Error::MissingKey);
        }
        let node = entries[*next + found].node;
        *next += found + 1;
        // A typed object's first key is its type tag, so nothing else may
        // precede the schema it selects.
        if typed.is_some() && key != b"@type" {
            return Err(Error::MissingKey);
        }
        self.expect = Some(node);
        Ok(())
    }

    fn begin_string(&mut self) -> Result<(), Error> {
        let Node::Str(leaf) = self.take_expected()? else {
            return Err(Error::UnexpectedType);
        };
        self.leaf = Some(leaf);
        self.value.clear();
        if leaf == Leaf::FileBody {
            let pkg = self.package.as_mut().ok_or(Error::Syntax)?;
            pkg.body = Some(H::Sha256::new());
            pkg.body_len = 0;
            pkg.scanner = Some(Scanner::new());
        }
        Ok(())
    }

    fn string_bytes(&mut self, bytes: &[u8]) -> Result<(), Error> {
        match self.leaf {
            Some(Leaf::FileBody) => {
                let pkg = self.package.as_mut().ok_or(Error::Syntax)?;
                pkg.bytes += bytes.len() as u64;
                pkg.body_len += bytes.len() as u64;
                pkg.body.as_mut().ok_or(Error::Syntax)?.update(bytes);
                pkg.scanner.as_mut().ok_or(Error::Syntax)?.feed(bytes);
                Ok(())
            }
            Some(leaf) => {
                let limit = match leaf {
                    Leaf::FileName => MAX_FILE_NAME_LEN,
                    _ => MAX_VALUE_LEN,
                };
                if self.value.len() + bytes.len() > limit {
                    return Err(Error::ValueTooLong);
                }
                self.value.extend_from_slice(bytes);
                Ok(())
            }
            None => Err(Error::Syntax),
        }
    }

    fn end_string(&mut self) -> Result<(), Error> {
        let leaf = self.leaf.take().ok_or(Error::Syntax)?;
        self.end_leaf(leaf)
    }
}
