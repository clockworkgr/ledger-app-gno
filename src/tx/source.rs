//! Highlights extracted from package source as it streams: the import paths
//! and the literal `g1` addresses an attacker would have to change to redirect
//! funds or reach other realms.
//!
//! This is a single-pass Go tokenizer, just precise enough to tell code from
//! comments and string literals. It never fails: a file that is not valid Go
//! yields meaningless highlights, and the chain rejects it anyway. Only `.gno`
//! files the chain executes count (see [`executes`]).

use alloc::vec::Vec;

use super::encoding::{self, ADDRESS_LEN};

pub const MAX_IMPORTS: usize = 16;
pub const MAX_IMPORT_LEN: usize = 128;
pub const MAX_ADDRESSES: usize = 8;

/// Distinct highlights, in order of first appearance.
#[derive(Default)]
pub struct Findings {
    /// Import paths as written between the quotes, escapes included.
    pub imports: Vec<Vec<u8>>,
    pub addresses: Vec<[u8; ADDRESS_LEN]>,
    /// Distinct imports beyond `MAX_IMPORTS` were seen and dropped.
    pub more_imports: bool,
    /// Distinct addresses beyond `MAX_ADDRESSES` were seen and dropped.
    pub more_addresses: bool,
    /// An import path exceeded `MAX_IMPORT_LEN`.
    pub long_import: bool,
}

impl Findings {
    /// Records an import path; returns whether it was new and listed.
    pub fn add_import(&mut self, path: &[u8]) -> bool {
        if self.imports.iter().any(|p| p.as_slice() == path) {
            return false;
        }
        if self.imports.len() == MAX_IMPORTS {
            self.more_imports = true;
            return false;
        }
        self.imports.push(path.to_vec());
        true
    }

    /// Records an address; returns whether it was new and listed.
    pub fn add_address(&mut self, addr: &[u8; ADDRESS_LEN]) -> bool {
        if self.addresses.contains(addr) {
            return false;
        }
        if self.addresses.len() == MAX_ADDRESSES {
            self.more_addresses = true;
            return false;
        }
        self.addresses.push(*addr);
        true
    }
}

/// Whether the chain compiles and runs a package file. Test files are stored
/// but never executed, so their contents cannot move funds.
pub fn executes(name: &[u8]) -> bool {
    name.ends_with(b".gno") && !name.ends_with(b"_test.gno") && !name.ends_with(b"_filetest.gno")
}

#[derive(Clone, Copy, PartialEq)]
enum Lex {
    Code,
    /// A `/` in code that may open a comment.
    Slash,
    LineComment,
    BlockComment,
    /// A `*` inside a block comment that may close it.
    BlockStar,
    Str,
    StrEscape,
    RawStr,
    Rune,
    RuneEscape,
}

/// Where the tokenizer stands in an import declaration.
#[derive(Clone, Copy, PartialEq)]
enum Import {
    Outside,
    /// After the `import` keyword: a `(` or a single (optionally named) path.
    Keyword,
    /// Inside `import ( ... )`, where every string literal is a path.
    Group,
}

/// Longest word kept; one more than an address so longer words are told apart.
const WORD_CAP: usize = ADDRESS_LEN + 1;

pub struct Scanner {
    lex: Lex,
    import: Import,
    word: [u8; WORD_CAP],
    word_len: usize,
    /// Whether the open string literal is an import path being captured.
    capture: bool,
    literal: Vec<u8>,
    found: Findings,
}

/// Identifier characters, plus every non-ASCII byte so that a Unicode
/// identifier is never split into an ASCII keyword or address.
fn is_word_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_' || b >= 0x80
}

impl Default for Scanner {
    fn default() -> Self {
        Self::new()
    }
}

impl Scanner {
    pub fn new() -> Self {
        Scanner {
            lex: Lex::Code,
            import: Import::Outside,
            word: [0; WORD_CAP],
            word_len: 0,
            capture: false,
            literal: Vec::new(),
            found: Findings::default(),
        }
    }

    pub fn feed(&mut self, data: &[u8]) {
        for &b in data {
            self.byte(b);
        }
    }

    /// Ends the file and returns what it contained.
    pub fn finish(mut self) -> Findings {
        self.end_word();
        self.found
    }

    fn byte(&mut self, b: u8) {
        match self.lex {
            Lex::Code => self.code(b),
            Lex::Slash => match b {
                b'/' => self.lex = Lex::LineComment,
                b'*' => self.lex = Lex::BlockComment,
                _ => {
                    self.lex = Lex::Code;
                    self.code(b);
                }
            },
            Lex::LineComment => {
                if b == b'\n' {
                    self.lex = Lex::Code;
                }
            }
            Lex::BlockComment => {
                if b == b'*' {
                    self.lex = Lex::BlockStar;
                }
            }
            Lex::BlockStar => match b {
                b'/' => self.lex = Lex::Code,
                b'*' => {}
                _ => self.lex = Lex::BlockComment,
            },
            Lex::Str => match b {
                b'"' => self.end_literal(),
                // An unterminated literal is invalid Go; resynchronize on the next line.
                b'\n' => self.abandon_literal(),
                b'\\' => {
                    self.end_word();
                    self.take_literal_byte(b);
                    self.lex = Lex::StrEscape;
                }
                _ => self.literal_byte(b),
            },
            Lex::StrEscape => {
                self.take_literal_byte(b);
                self.lex = Lex::Str;
            }
            Lex::RawStr => match b {
                b'`' => self.end_literal(),
                _ => self.literal_byte(b),
            },
            Lex::Rune => match b {
                b'\'' | b'\n' => self.lex = Lex::Code,
                b'\\' => self.lex = Lex::RuneEscape,
                _ => {}
            },
            Lex::RuneEscape => self.lex = Lex::Rune,
        }
    }

    fn code(&mut self, b: u8) {
        if is_word_byte(b) {
            self.push_word(b);
            return;
        }
        self.end_word();
        match b {
            b'/' => self.lex = Lex::Slash,
            b'"' => self.begin_literal(Lex::Str),
            b'`' => self.begin_literal(Lex::RawStr),
            b'\'' => self.lex = Lex::Rune,
            b'(' if self.import == Import::Keyword => self.import = Import::Group,
            b')' if self.import == Import::Group => self.import = Import::Outside,
            _ => {}
        }
    }

    fn begin_literal(&mut self, lex: Lex) {
        self.lex = lex;
        self.capture = self.import != Import::Outside;
        self.literal.clear();
    }

    fn end_literal(&mut self) {
        self.end_word();
        self.lex = Lex::Code;
        if !self.capture {
            return;
        }
        self.capture = false;
        if self.literal.len() > MAX_IMPORT_LEN {
            self.found.long_import = true;
        } else {
            self.found.add_import(&self.literal);
        }
        self.literal.clear();
        if self.import == Import::Keyword {
            self.import = Import::Outside;
        }
    }

    fn abandon_literal(&mut self) {
        self.end_word();
        self.lex = Lex::Code;
        self.capture = false;
        self.literal.clear();
        self.import = Import::Outside;
    }

    /// A byte inside a string literal: part of a possible address, and of the
    /// import path when one is being captured.
    fn literal_byte(&mut self, b: u8) {
        if is_word_byte(b) {
            self.push_word(b);
        } else {
            self.end_word();
        }
        self.take_literal_byte(b);
    }

    fn take_literal_byte(&mut self, b: u8) {
        // One byte past the limit is enough to know the path is too long.
        if self.capture && self.literal.len() <= MAX_IMPORT_LEN {
            self.literal.push(b);
        }
    }

    fn push_word(&mut self, b: u8) {
        if self.word_len < WORD_CAP {
            self.word[self.word_len] = b;
            self.word_len += 1;
        }
    }

    fn end_word(&mut self) {
        let len = core::mem::take(&mut self.word_len);
        let word = &self.word[..len];
        if self.lex == Lex::Code && word == b"import" {
            self.import = Import::Keyword;
            return;
        }
        if len != ADDRESS_LEN {
            return;
        }
        let mut addr = [0u8; ADDRESS_LEN];
        addr.copy_from_slice(word);
        // Bech32 also accepts an all-uppercase string, and so does the chain.
        if addr.iter().all(|c| !c.is_ascii_lowercase()) {
            addr.make_ascii_lowercase();
        }
        if encoding::validate_address(&addr).is_ok() {
            self.found.add_address(&addr);
        }
    }
}
