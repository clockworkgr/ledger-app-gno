---
description: "Gno (gno.land / Tendermint2) specifics for the Gno Ledger application"
applyTo: "**/*"
---

# Gno Application Rules

This app signs transactions for gno.land chains, which run on Tendermint2 (tm2). The reference
implementation is upstream `github.com/gnolang/gno` (not the `allinbits/gno` fork): `tm2/` for
keys, the sign doc, `auth` and `bank`; `gno.land/pkg/sdk/vm` for the VM messages. Everything below
was checked against upstream `master` at `0260690` (2026-10-10). When a rule here and the Go code
disagree, the Go code on `master` wins. Fix this file in the same change.

## Keys and addresses

- Curve: secp256k1 only.
- Derivation: BIP44 with SLIP-44 coin type `118`. The default path is `m/44'/118'/0'/0/0`
  (`tm2/pkg/crypto/globals.go`). Restrict the app's derivation paths to `44'/118'`.
- Public key: 33-byte compressed SEC1.
- Address: `RIPEMD160(SHA256(compressed_pubkey))`, 20 bytes (`tm2/pkg/crypto/secp256k1`).
- Bech32 HRP: `g` for addresses (`g1...`), `gpub` for public keys.

## Sign bytes

The signed payload is amino JSON with object keys sorted at every level and no insignificant
whitespace (`GetSignaturePayload` in `tm2/pkg/std/doc.go`):

```json
{"account_number":"7","chain_id":"gnoland1","fee":{"amount":[{"amount":"1000000","denom":"ugnot"}],"gas":"2000000"},"memo":"","msgs":[...],"sequence":"3"}
```

- `uint64`/`int64` values are JSON **strings**.
- `fee` uses Cosmos's shape (`amount` + `gas`), not tm2's `std.Fee` (`gas_fee` + `gas_wanted`).
  A zero fee is `"amount":[]`, never `null` and never a zero coin.
- Each message carries its amino type URL in `"@type"`. Coins inside messages are tm2 coin
  strings, e.g. `"1000000ugnot"`, not objects. Public keys are amino `Any` objects,
  e.g. `{"@type":"/tm.PubKeySecp256k1","value":"<base64>"}`.
- Because keys are sorted, `sequence` is the last top-level field and, inside a package message,
  `send` comes after `package`. The device cannot review anything until the whole payload has
  arrived (see "Streaming").
- `GetSignaturePayloadLegacy` (tm2 fee shape) still verifies on chain. Supporting it is a
  separate decision. Do not accept it silently.

## Signature

- ECDSA secp256k1 over `SHA-256(sign_bytes)`, not the Keccak-256 the boilerplate used.
- Return a 64-byte `R || S` signature with low-S. tm2 rejects any other length, and the cgo
  verifier rejects high-S. Do not return DER.

## Messages

Every type that can be decoded from a transaction (amino-registered in a `package.go`):

| `@type` | Source | Fields | Policy |
| --- | --- | --- | --- |
| `/bank.MsgSend` | `tm2/pkg/sdk/bank/msgs.go` | `from_address`, `to_address`, `amount` | Clear sign |
| `/vm.m_call` | `gno.land/pkg/sdk/vm/msgs.go` | `caller`, `send`, `max_deposit`, `pkg_path`, `func`, `args` | Clear sign |
| `/vm.m_enable_pkg` | `gno.land/pkg/sdk/vm/msgs.go` | `approver`, `pkg_path`, `pkg_hash`, `pkg_height` | Clear sign |
| `/vm.m_reject_pkg` | `gno.land/pkg/sdk/vm/msgs.go` | `sender`, `pkg_path` | Clear sign |
| `/auth.m_create_session` | `tm2/pkg/sdk/auth/msgs.go` | `creator`, `session_key`, `expires_at`, `allow_paths`, `spend_limit`, `spend_period` | Clear sign, with warnings |
| `/auth.m_revoke_session` | `tm2/pkg/sdk/auth/msgs.go` | `creator`, `session_key` | Clear sign |
| `/auth.m_revoke_all_sessions` | `tm2/pkg/sdk/auth/msgs.go` | `creator` | Clear sign |
| `/vm.m_addpkg` | `gno.land/pkg/sdk/vm/msgs.go` | `creator`, `package`, `send`, `max_deposit` | Fingerprint and highlights, setting-gated |
| `/vm.m_run` | `gno.land/pkg/sdk/vm/msgs.go` | `caller`, `send`, `max_deposit`, `package` | Fingerprint and highlights, setting-gated |

- `bank.MsgMultiSend` has a handler but is **not** amino-registered, so no transaction can carry
  it. Reject it like any other unknown `@type`.
- Fields tagged `omitempty` (`m_call.args`; `m_create_session.allow_paths`, `spend_limit`,
  `spend_period`) may be absent. Absent and present-but-empty are different signed bytes. Accept
  exactly what amino emits and reject the other form.
- Always display chain ID, fee, gas, memo and every message's amounts and addresses. Each
  message's signer field (`from_address`, `caller`, `creator`, `approver`, `sender`) must equal
  the address derived on the device. If it doesn't, reject, since this app only signs for its own
  account.
- `m_call` args are arbitrary realm-defined strings. Show them verbatim, never interpreted.
- `m_enable_pkg`: show `pkg_hash` in full. It is the `PackageContentHash` the approver is
  vouching for. Reject an empty `pkg_hash`. Show `pkg_height` and warn when it is `0` (unpinned).
- `m_create_session` hands a second key authority over this account. Show the session key as a
  `g1` address, the expiry as a UTC date, every allow-path entry, and the spend limit and period.
  Show a warning screen for `"*"` in `allow_paths`, for `expires_at` = `0` (never expires), and for
  `spend_period` = `0` with a non-empty limit (a lifetime cap, not a per-period one).
- Reject unknown `@type`s, unknown keys, duplicate keys and keys that are out of order. The
  bytes must be exactly what the chain will verify.
- Display `ugnot` amounts as GNOT (1 GNOT = 1,000,000 ugnot) using integer arithmetic only.

## Package-carrying messages (`m_addpkg`, `m_run`)

The `package` field is a whole `std.MemPackage`: `name`, `path` and `files[]` of `{name, body}`,
often tens or hundreds of KiB of Gno source. It cannot fit in RAM or on a screen. Signing it
works like this:

1. **Streaming.** The host streams the sign bytes in chunks. The device runs an incremental,
   strict JSON parser (`src/tx`) and feeds every byte into a running SHA-256, which becomes the
   signing digest. Only the summary fields below are kept in RAM, never the payload.
2. **Package fingerprint.** While streaming, the device computes
   `SHA-256(for each file: u32be(len(name)) | name | SHA-256(body))` over the decoded files.
   Each body is hashed on its own because amino sorts `body` before `name`. The chain rejects
   packages whose files are not sorted by name (`MemPackage.ValidateBasic` in
   `tm2/pkg/std/memfile.go`), so the device requires strictly ascending byte-wise names. This is
   **not** gno's `PackageContentHash`, which rewrites `gnomod.toml` before hashing and needs a
   TOML parser. `docs/APDU.md` is the normative definition.
3. **Review screens.** Show the message type, `package.path`, `package.name`, the highlights
   below, the file count, each file's name and size, the total body bytes, the fingerprint (hex,
   in full), `send`, `max_deposit`, then the usual chain ID, fee, gas and memo. `m_run` also gets
   the warning "Script can do anything your account can".
4. **Highlights** (`src/tx/source.rs`). While hashing each body, a single-pass Go tokenizer
   collects what an attacker would have to change to redirect funds or reach other realms:
   - every import path, as written between the quotes (escapes shown, not decoded; aliases
     dropped);
   - every literal `g1` address with a valid checksum in code or string literals, not in
     comments. All-uppercase bech32 is accepted by the chain, so it is matched too and shown
     lowercase. The signer's own address is marked "(you)".

   Both lists are distinct values in order of first appearance. Only files the chain executes
   count: `.gno` files other than `*_test.gno` and `*_filetest.gno`. A body's findings are held
   until its name arrives, because the name follows the body. "None" / "None found" is shown when
   a list is empty, so the user can tell the scan ran.

   Highlights only catch an unadapted attack. An attacker who knows about them can assemble an
   address at run time (concatenation, byte slices, `\x` escapes) or reach a realm through one
   that is already imported. The fingerprint stays the authoritative check, and the docs and
   the review must never present highlights as a substitute for it.
5. **Gate.** Both messages run arbitrary code with this account's authority. `m_run` executes as
   the caller, and `m_addpkg`'s `init()` executes as the creator. Neither is bounded by `send`.
   They are refused with `PACKAGE_TX_DISABLED` unless the "Packages" setting is on. NVM starts
   zeroed, so it is off until the user enables it. When it is on, the review uses the SDK's
   blind-signing flow (`NbglReview::blind`), which warns first. Settings titles must stay short:
   a title wider than the Nano screen renders an empty page.
6. **Host verification.** A fingerprint is only useful if the user can compare it with one
   computed somewhere the attacker doesn't control. The Go client (gnokey) must print the same
   fingerprint for a local package directory.

## APDU protocol

This app defines its own protocol (CLA `0xE0`), specified in `docs/APDU.md`, and does **not** copy
ledger-cosmos's Zondax protocol (CLA `0x55`). gnokey reaches Ledger through `ledger-cosmos-go`
(`tm2/pkg/crypto/internal/ledger`), so supporting this app needs a new Go client in gno. Keep
`docs/APDU.md`, the `Instruction` enum and `AppSW` in `src/main.rs`, and
`tests/application_client/gno_command_sender.py` in sync.

## Limits

The payload itself is unbounded. What is bounded, in `src/tx/mod.rs`, is what has to be kept for
the review: 512 bytes per displayed value, 3072 bytes of review text, 56 fields, 8 messages, and
128 bytes per import path. Exceeding any of them returns `TX_TOO_LARGE`. Values are never
truncated.

The review limits come from Nano X. NBGL copies the review again (C strings plus per-field
descriptors) while showing it, and Nano X cannot raise its heap above 16 KiB without starving its
stack, so the signing session is also boxed and freed before the review is shown. The other
devices get a 24 KiB heap (`.cargo/config.toml`). `test_sign_review_near_memory_limit` signs a
review at the limits on every device. Ledger's build always takes the latest `ledger_device_sdk`,
so rerun it after an SDK bump: 1.41 needs noticeably more heap per field than 1.37 did.

Package lists are the one place where the review shows fewer items than exist: at most 16
imports, 8 addresses and 16 file names. Refusing larger packages would make them undeployable,
and the lists are a summary next to the fingerprint, not the thing being approved. The overflow
is always announced: a warning for imports and addresses, and an "and N more" entry for files.

Every message's signer field must be the device's own address, so transactions that combine
several signers are refused.

## Test vectors

`tools/vectors` renders one payload per message type with upstream gno, pinned in its `go.mod`,
and signs it with the Speculos seed. The output, `tests/vectors/sign_docs.json`, drives both
`host-tests` (parser, run on the host) and the Ragger tests, which also check that the device's
signature equals gno's byte for byte. When bumping gno, regenerate the file and review the diff:
a changed payload means the schema in `src/tx/schema.rs` may need updating.

## Out of scope

- Swap/Exchange integration: GNOT is not listed in Ledger's Exchange app, and the boilerplate's
  swap support has been removed.
