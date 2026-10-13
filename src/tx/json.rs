//! Streaming lexer for amino sign bytes.
//!
//! The input is consumed chunk by chunk and never buffered whole, so the
//! payload size is bounded only by what the host sends, not by RAM. The lexer
//! accepts exactly the JSON subset gno emits for signature payloads: no
//! whitespace, no numbers and no literals, since amino renders every 64-bit
//! integer as a string and sign docs carry no booleans or nulls. Anything else
//! is rejected rather than tolerated.

use super::Error;

const MAX_DEPTH: usize = 8;
const MAX_KEY_LEN: usize = 32;

/// Receives the structure of the document as it is lexed.
///
/// String values arrive decoded, possibly split across several
/// [`Sink::string_bytes`] calls; keys arrive whole.
pub trait Sink {
    fn begin_object(&mut self) -> Result<(), Error>;
    fn end_object(&mut self) -> Result<(), Error>;
    fn begin_array(&mut self) -> Result<(), Error>;
    fn end_array(&mut self) -> Result<(), Error>;
    fn key(&mut self, key: &[u8]) -> Result<(), Error>;
    fn begin_string(&mut self) -> Result<(), Error>;
    fn string_bytes(&mut self, bytes: &[u8]) -> Result<(), Error>;
    fn end_string(&mut self) -> Result<(), Error>;
}

#[derive(Clone, Copy, PartialEq)]
enum Container {
    Object,
    Array,
}

#[derive(Clone, Copy, PartialEq)]
enum State {
    Start,
    Value,
    ValueOrEnd,
    Key,
    KeyOrEnd,
    InKey,
    Colon,
    InString,
    Escape,
    /// Inside `\uXXXX`; `high` is a pending high surrogate, or 0.
    Unicode {
        digits: u8,
        acc: u32,
        high: u32,
    },
    LowSurrogateBackslash {
        high: u32,
    },
    LowSurrogateU {
        high: u32,
    },
    AfterValue,
    Done,
}

pub struct Lexer {
    state: State,
    stack: [Container; MAX_DEPTH],
    depth: usize,
    key: [u8; MAX_KEY_LEN],
    key_len: usize,
}

impl Default for Lexer {
    fn default() -> Self {
        Self::new()
    }
}

impl Lexer {
    pub const fn new() -> Self {
        Lexer {
            state: State::Start,
            stack: [Container::Object; MAX_DEPTH],
            depth: 0,
            key: [0; MAX_KEY_LEN],
            key_len: 0,
        }
    }

    /// Lexes the next chunk of the document.
    pub fn feed<S: Sink>(&mut self, data: &[u8], sink: &mut S) -> Result<(), Error> {
        let mut i = 0;
        while i < data.len() {
            if self.state == State::InString {
                let run = data[i..]
                    .iter()
                    .position(|&b| b == b'"' || b == b'\\' || b < 0x20)
                    .unwrap_or(data.len() - i);
                if run > 0 {
                    sink.string_bytes(&data[i..i + run])?;
                    i += run;
                    continue;
                }
            }
            self.step(data[i], sink)?;
            i += 1;
        }
        Ok(())
    }

    /// Checks that the document ended exactly after its top-level object.
    pub fn finish(&self) -> Result<(), Error> {
        match self.state {
            State::Done => Ok(()),
            _ => Err(Error::Truncated),
        }
    }

    fn step<S: Sink>(&mut self, b: u8, sink: &mut S) -> Result<(), Error> {
        self.state = match self.state {
            State::Start => match b {
                b'{' => self.open(Container::Object, sink)?,
                _ => return Err(Error::Syntax),
            },
            State::Value => self.value(b, sink)?,
            State::ValueOrEnd => match b {
                b']' => self.close(Container::Array, sink)?,
                _ => self.value(b, sink)?,
            },
            State::Key => match b {
                b'"' => self.begin_key(),
                _ => return Err(Error::Syntax),
            },
            State::KeyOrEnd => match b {
                b'"' => self.begin_key(),
                b'}' => self.close(Container::Object, sink)?,
                _ => return Err(Error::Syntax),
            },
            State::InKey => match b {
                b'"' => {
                    sink.key(&self.key[..self.key_len])?;
                    State::Colon
                }
                // Keys are schema names: printable ASCII, never escaped.
                0x20..=0x7e if b != b'\\' => {
                    if self.key_len == MAX_KEY_LEN {
                        return Err(Error::UnknownKey);
                    }
                    self.key[self.key_len] = b;
                    self.key_len += 1;
                    State::InKey
                }
                _ => return Err(Error::Syntax),
            },
            State::Colon => match b {
                b':' => State::Value,
                _ => return Err(Error::Syntax),
            },
            State::InString => match b {
                b'"' => {
                    sink.end_string()?;
                    State::AfterValue
                }
                b'\\' => State::Escape,
                _ => return Err(Error::Syntax),
            },
            State::Escape => {
                let decoded = match b {
                    b'"' => b'"',
                    b'\\' => b'\\',
                    b'/' => b'/',
                    b'b' => 0x08,
                    b'f' => 0x0c,
                    b'n' => b'\n',
                    b'r' => b'\r',
                    b't' => b'\t',
                    b'u' => {
                        self.state = State::Unicode {
                            digits: 0,
                            acc: 0,
                            high: 0,
                        };
                        return Ok(());
                    }
                    _ => return Err(Error::Syntax),
                };
                sink.string_bytes(&[decoded])?;
                State::InString
            }
            State::Unicode { digits, acc, high } => {
                let nibble = match b {
                    b'0'..=b'9' => b - b'0',
                    b'a'..=b'f' => b - b'a' + 10,
                    b'A'..=b'F' => b - b'A' + 10,
                    _ => return Err(Error::Syntax),
                } as u32;
                let acc = (acc << 4) | nibble;
                if digits < 3 {
                    State::Unicode {
                        digits: digits + 1,
                        acc,
                        high,
                    }
                } else {
                    self.code_unit(acc, high, sink)?
                }
            }
            State::LowSurrogateBackslash { high } => match b {
                b'\\' => State::LowSurrogateU { high },
                _ => return Err(Error::Syntax),
            },
            State::LowSurrogateU { high } => match b {
                b'u' => State::Unicode {
                    digits: 0,
                    acc: 0,
                    high,
                },
                _ => return Err(Error::Syntax),
            },
            State::AfterValue => match (b, self.top()) {
                (b',', Some(Container::Object)) => State::Key,
                (b',', Some(Container::Array)) => State::Value,
                (b'}', Some(Container::Object)) => self.close(Container::Object, sink)?,
                (b']', Some(Container::Array)) => self.close(Container::Array, sink)?,
                _ => return Err(Error::Syntax),
            },
            State::Done => return Err(Error::TrailingData),
        };
        Ok(())
    }

    fn value<S: Sink>(&mut self, b: u8, sink: &mut S) -> Result<State, Error> {
        match b {
            b'{' => self.open(Container::Object, sink),
            b'[' => self.open(Container::Array, sink),
            b'"' => {
                sink.begin_string()?;
                Ok(State::InString)
            }
            _ => Err(Error::Syntax),
        }
    }

    fn begin_key(&mut self) -> State {
        self.key_len = 0;
        State::InKey
    }

    fn top(&self) -> Option<Container> {
        self.depth.checked_sub(1).map(|i| self.stack[i])
    }

    fn open<S: Sink>(&mut self, c: Container, sink: &mut S) -> Result<State, Error> {
        if self.depth == MAX_DEPTH {
            return Err(Error::TooDeep);
        }
        self.stack[self.depth] = c;
        self.depth += 1;
        match c {
            Container::Object => {
                sink.begin_object()?;
                Ok(State::KeyOrEnd)
            }
            Container::Array => {
                sink.begin_array()?;
                Ok(State::ValueOrEnd)
            }
        }
    }

    fn close<S: Sink>(&mut self, c: Container, sink: &mut S) -> Result<State, Error> {
        if self.top() != Some(c) {
            return Err(Error::Syntax);
        }
        self.depth -= 1;
        match c {
            Container::Object => sink.end_object()?,
            Container::Array => sink.end_array()?,
        }
        Ok(if self.depth == 0 {
            State::Done
        } else {
            State::AfterValue
        })
    }

    fn code_unit<S: Sink>(&mut self, unit: u32, high: u32, sink: &mut S) -> Result<State, Error> {
        let scalar = match (high, unit) {
            (0, 0xD800..=0xDBFF) => return Ok(State::LowSurrogateBackslash { high: unit }),
            (0, 0xDC00..=0xDFFF) => return Err(Error::Syntax),
            (0, _) => unit,
            (_, 0xDC00..=0xDFFF) => 0x10000 + ((high - 0xD800) << 10) + (unit - 0xDC00),
            (_, _) => return Err(Error::Syntax),
        };
        let mut utf8 = [0u8; 4];
        let c = char::from_u32(scalar).ok_or(Error::Syntax)?;
        sink.string_bytes(c.encode_utf8(&mut utf8).as_bytes())?;
        Ok(State::InString)
    }
}
