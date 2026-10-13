//! The exact shape of every accepted signature payload.
//!
//! Entries are listed in amino's sorted key order, which the parser enforces.
//! A key that is not listed is rejected. Field definitions mirror upstream gno:
//! `tm2/pkg/std/doc.go`, `tm2/pkg/sdk/{bank,auth}/msgs.go` and
//! `gno.land/pkg/sdk/vm/msgs.go`.

#[derive(Clone, Copy)]
pub enum Node {
    Obj(&'static [Entry]),
    /// An object whose leading `@type` selects the rest of its schema.
    Typed(Typed),
    /// An array of the node, with at least this many elements.
    Arr(&'static Node, u8),
    Str(Leaf),
}

#[derive(Clone, Copy, PartialEq)]
pub enum Typed {
    Message,
    PubKey,
    PackageType,
}

pub struct Entry {
    pub key: &'static str,
    pub node: Node,
    /// False for amino `omitempty` fields, which are absent when empty.
    pub required: bool,
}

/// What a string value means, and how it is shown.
#[derive(Clone, Copy, PartialEq)]
pub enum Leaf {
    TypeTag,
    ChainId,
    AccountNumber,
    Sequence,
    Memo,
    Gas,
    FeeAmount,
    FeeDenom,
    /// Must equal the address of the signing key.
    Signer,
    Address(&'static str, u16),
    Coins {
        label: &'static str,
        /// What an empty set means for this field; `None` rejects it.
        empty: Option<&'static str>,
        rank: u16,
    },
    /// A VM message's storage-deposit cap. gno only reads its `ugnot` amount
    /// and falls back to the chain default when that is zero.
    MaxDeposit,
    SpendLimit,
    SpendPeriod,
    Text(&'static str, u16),
    Arg,
    AllowPath,
    ExpiresAt,
    PubKey,
    PkgHash,
    PkgHeight,
    PkgName,
    PkgPath,
    PkgType,
    FileBody,
    FileName,
}

#[derive(Clone, Copy, PartialEq)]
pub enum MessageKind {
    Send,
    Call,
    AddPackage,
    Run,
    EnablePackage,
    RejectPackage,
    CreateSession,
    RevokeSession,
    RevokeAllSessions,
}

pub struct MessageInfo {
    pub kind: MessageKind,
    pub title: &'static str,
    /// Carries source code the device cannot show.
    pub blind: bool,
}

/// Display order of fields within a message.
pub mod rank {
    pub const TYPE: u16 = 0;
    pub const WARNING: u16 = 1;
    pub const PKG_PATH: u16 = 10;
    pub const PKG_NAME: u16 = 11;
    pub const PKG_IMPORTS: u16 = 12;
    pub const PKG_ADDRESSES: u16 = 13;
    pub const PKG_FILES: u16 = 14;
    pub const PKG_FILE_LIST: u16 = 15;
    pub const PKG_SIZE: u16 = 16;
    pub const PKG_FINGERPRINT: u16 = 17;
    pub const PKG_HASH: u16 = 18;
    pub const PKG_HEIGHT: u16 = 19;
    pub const REALM: u16 = 20;
    pub const FUNC: u16 = 21;
    /// Arguments take `ARGS + n` for the n-th argument.
    pub const ARGS: u16 = 100;
    pub const TO: u16 = 1000;
    pub const AMOUNT: u16 = 1001;
    pub const SEND: u16 = 1002;
    pub const MAX_DEPOSIT: u16 = 1003;
    pub const SESSION_KEY: u16 = 1010;
    pub const ALLOW_PATH: u16 = 1011;
    pub const EXPIRES: u16 = 1012;
    pub const SPEND_LIMIT: u16 = 1013;
    pub const SPEND_PERIOD: u16 = 1014;
}

const fn req(key: &'static str, node: Node) -> Entry {
    Entry {
        key,
        node,
        required: true,
    }
}

const fn opt(key: &'static str, node: Node) -> Entry {
    Entry {
        key,
        node,
        required: false,
    }
}

const SEND: Node = Node::Str(Leaf::Coins {
    label: "Send",
    empty: Some("None"),
    rank: rank::SEND,
});
const MAX_DEPOSIT: Node = Node::Str(Leaf::MaxDeposit);
const SIGNER: Node = Node::Str(Leaf::Signer);
const SESSION_KEY: Node = Node::Typed(Typed::PubKey);

pub static TYPE_ONLY: &[Entry] = &[req("@type", Node::Str(Leaf::TypeTag))];

static FEE_COIN: &[Entry] = &[
    req("amount", Node::Str(Leaf::FeeAmount)),
    req("denom", Node::Str(Leaf::FeeDenom)),
];
static FEE_COIN_NODE: Node = Node::Obj(FEE_COIN);
static FEE: &[Entry] = &[
    req("amount", Node::Arr(&FEE_COIN_NODE, 0)),
    req("gas", Node::Str(Leaf::Gas)),
];
static MESSAGE_NODE: Node = Node::Typed(Typed::Message);

pub static SIGN_DOC: &[Entry] = &[
    req("account_number", Node::Str(Leaf::AccountNumber)),
    req("chain_id", Node::Str(Leaf::ChainId)),
    req("fee", Node::Obj(FEE)),
    req("memo", Node::Str(Leaf::Memo)),
    req("msgs", Node::Arr(&MESSAGE_NODE, 1)),
    req("sequence", Node::Str(Leaf::Sequence)),
];

pub static FILE: &[Entry] = &[
    req("body", Node::Str(Leaf::FileBody)),
    req("name", Node::Str(Leaf::FileName)),
];
static FILE_NODE: Node = Node::Obj(FILE);
pub static PACKAGE: &[Entry] = &[
    req("files", Node::Arr(&FILE_NODE, 1)),
    req("name", Node::Str(Leaf::PkgName)),
    req("path", Node::Str(Leaf::PkgPath)),
    opt("type", Node::Typed(Typed::PackageType)),
];

static ARG_NODE: Node = Node::Str(Leaf::Arg);
static ALLOW_PATH_NODE: Node = Node::Str(Leaf::AllowPath);

static MSG_SEND: &[Entry] = &[
    req(
        "amount",
        Node::Str(Leaf::Coins {
            label: "Amount",
            empty: None,
            rank: rank::AMOUNT,
        }),
    ),
    req("from_address", SIGNER),
    req("to_address", Node::Str(Leaf::Address("To", rank::TO))),
];
static MSG_CALL: &[Entry] = &[
    opt("args", Node::Arr(&ARG_NODE, 1)),
    req("caller", SIGNER),
    req("func", Node::Str(Leaf::Text("Function", rank::FUNC))),
    req("max_deposit", MAX_DEPOSIT),
    req("pkg_path", Node::Str(Leaf::Text("Realm", rank::REALM))),
    req("send", SEND),
];
static MSG_ADD_PACKAGE: &[Entry] = &[
    req("creator", SIGNER),
    req("max_deposit", MAX_DEPOSIT),
    req("package", Node::Obj(PACKAGE)),
    req("send", SEND),
];
static MSG_RUN: &[Entry] = &[
    req("caller", SIGNER),
    req("max_deposit", MAX_DEPOSIT),
    req("package", Node::Obj(PACKAGE)),
    req("send", SEND),
];
static MSG_ENABLE_PACKAGE: &[Entry] = &[
    req("approver", SIGNER),
    req("pkg_hash", Node::Str(Leaf::PkgHash)),
    req("pkg_height", Node::Str(Leaf::PkgHeight)),
    req("pkg_path", Node::Str(Leaf::Text("Package", rank::PKG_PATH))),
];
static MSG_REJECT_PACKAGE: &[Entry] = &[
    req("pkg_path", Node::Str(Leaf::Text("Package", rank::PKG_PATH))),
    req("sender", SIGNER),
];
static MSG_CREATE_SESSION: &[Entry] = &[
    opt("allow_paths", Node::Arr(&ALLOW_PATH_NODE, 1)),
    req("creator", SIGNER),
    req("expires_at", Node::Str(Leaf::ExpiresAt)),
    req("session_key", SESSION_KEY),
    opt("spend_limit", Node::Str(Leaf::SpendLimit)),
    opt("spend_period", Node::Str(Leaf::SpendPeriod)),
];
static MSG_REVOKE_SESSION: &[Entry] = &[req("creator", SIGNER), req("session_key", SESSION_KEY)];
static MSG_REVOKE_ALL_SESSIONS: &[Entry] = &[req("creator", SIGNER)];

static PUBKEY_SECP256K1: &[Entry] = &[req("value", Node::Str(Leaf::PubKey))];
static PACKAGE_TYPE: &[Entry] = &[req("value", Node::Str(Leaf::PkgType))];

const fn info(kind: MessageKind, title: &'static str, blind: bool) -> MessageInfo {
    MessageInfo { kind, title, blind }
}

static MESSAGES: &[(&str, &[Entry], MessageInfo)] = &[
    (
        "/bank.MsgSend",
        MSG_SEND,
        info(MessageKind::Send, "Send", false),
    ),
    (
        "/vm.m_call",
        MSG_CALL,
        info(MessageKind::Call, "Call realm", false),
    ),
    (
        "/vm.m_addpkg",
        MSG_ADD_PACKAGE,
        info(MessageKind::AddPackage, "Deploy package", true),
    ),
    (
        "/vm.m_run",
        MSG_RUN,
        info(MessageKind::Run, "Run script", true),
    ),
    (
        "/vm.m_enable_pkg",
        MSG_ENABLE_PACKAGE,
        info(MessageKind::EnablePackage, "Approve package", false),
    ),
    (
        "/vm.m_reject_pkg",
        MSG_REJECT_PACKAGE,
        info(MessageKind::RejectPackage, "Reject package", false),
    ),
    (
        "/auth.m_create_session",
        MSG_CREATE_SESSION,
        info(MessageKind::CreateSession, "Create session", false),
    ),
    (
        "/auth.m_revoke_session",
        MSG_REVOKE_SESSION,
        info(MessageKind::RevokeSession, "Revoke session", false),
    ),
    (
        "/auth.m_revoke_all_sessions",
        MSG_REVOKE_ALL_SESSIONS,
        info(MessageKind::RevokeAllSessions, "Revoke all sessions", false),
    ),
];

/// Resolves a type tag to the schema of the rest of the object.
pub fn lookup(kind: Typed, tag: &[u8]) -> Option<(&'static [Entry], Option<&'static MessageInfo>)> {
    match kind {
        Typed::Message => MESSAGES
            .iter()
            .find(|(t, _, _)| t.as_bytes() == tag)
            .map(|(_, e, i)| (*e, Some(i))),
        Typed::PubKey => (tag == b"/tm.PubKeySecp256k1").then_some((PUBKEY_SECP256K1, None)),
        Typed::PackageType => (tag == b"/gno.MemPackageType").then_some((PACKAGE_TYPE, None)),
    }
}
