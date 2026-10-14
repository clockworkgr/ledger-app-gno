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
- "Show address" on the home screen lets the user check an address without a host: they type an
  account, then an index, on two keypads, and the device shows the address and path for
  `m/44'/118'/account'/0/index`. Back on the index keypad returns to the account keypad. Each
  keypad takes at most 7 digits (up to 9,999,999), because Nano's NBGL keypad keeps the entry in
  8 bytes and displays it as a C string. Larger numbers remain reachable over `GET_PUBLIC_KEY`.

## Sign bytes

The signed payload is amino JSON with object keys sorted at every level and no insignificant
whitespace (`GetSignaturePayload` in `tm2/pkg/std/doc.go`):

```json
{"account_number":"7","chain_id":"gnoland1","fee":{"amount":[{"amount":"1000000","denom":"ugnot"}],"gas":"2000000"},"memo":"","msgs":[...],"sequence":"3"}
```

- `uint64`/`int64` values are JSON **strings**.
- `fee` uses Cosmos's shape (`amount` + `gas`), not tm2's `std.Fee` (`gas_fee` + `gas_wanted`).
  The fee is a single coin, so `amount` holds one positive coin or is `[]`. A zero fee is
  always `[]`, never `null` and never a zero coin. Refuse a second coin as soon as it arrives.
- Strings are encoded exactly as Go's `encoding/json` encodes them, because gno re-renders the
  sign doc to verify it. The only escapes are `\" \\ \b \t \n \f \r`, `\u00XX` with lowercase hex
  for the other control characters, `\u0026 \u003c \u003e` for `& < >`, and `\u2028 \u2029`.
  Everything else is raw, valid UTF-8 (Go turns invalid bytes into a raw U+FFFD). Any other
  spelling of the same text can never verify, so the device rejects it.
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
  account. The review starts with the sequence ("Sequence"), which tells transactions apart at a
  glance, then that address ("Signer"): the host picks the derivation path, and the user must see
  which account a transaction spends from.
- Coin strings must be valid tm2 `Coins`: positive amounts, denoms in strictly ascending order
  (so no duplicates), and valid denoms.
- `max_deposit` (`m_call`, `m_addpkg`, `m_run`) is either empty, shown as "Chain default", or a
  single positive `ugnot` coin. gno's `processStorageDeposit` reads only the `ugnot` amount and
  uses the chain's `DefaultDeposit` when that is zero, so any other value would display a cap the
  chain does not enforce. Reject it.
- `m_call` args are arbitrary realm-defined strings. Show them verbatim, never interpreted.
- `m_enable_pkg`: show `pkg_hash` in full. It is the `PackageContentHash` the approver is
  vouching for. Reject an empty `pkg_hash`. Show `pkg_height` and warn when it is `0` (unpinned).
- `m_create_session` hands a second key authority over this account. Show the session key as a
  `g1` address, the expiry as a UTC date, every allow-path entry, and the spend limit and period.
  Show a warning screen for `"*"` in `allow_paths`, for `expires_at` = `0` (never expires), and for
  `spend_period` = `0` with a non-empty limit (a lifetime cap, not a per-period one).
- A session allowed `vm/run`, or `*` (which gno's ante handler only denies for auth messages and
  `m_addpkg`), can run arbitrary scripts as this account. The review warns about it, and signing
  needs the Packages setting, like `m_run` itself.
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
   They are refused with `PACKAGE_TX_DISABLED` unless the "Packages" setting is on, as is a
   session that would be allowed `vm/run` or `*` (`Review::runs_code`). NVM starts
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

A signing session lives only for its own chunks. Any malformed command, wrong CLA included, and
any other instruction closes it, so the app checks the CLA itself rather than through
`Comm::set_expected_cla`, which would answer before the app could react. Transport-level errors
that the SDK answers on its own, and BOLOS commands (CLA `0xB0`), never reach the app.

## Limits

The payload itself is unbounded. What is bounded, in `src/tx/mod.rs`, is what has to be kept for
the review: 512 decoded bytes per value, 3072 bytes of review text, 57 fields, 8 messages, and
128 bytes per import path. Exceeding any of them returns `TX_TOO_LARGE`. Values are never
truncated. Review text is charged as displayed (escapes included) **before** it is rendered or
stored, including what is kept aside until the payload ends: the memo, fee, gas, chain ID and
the package's file names, imports and addresses. A hostile payload therefore hits
`TX_TOO_LARGE` instead of exhausting the heap. Long values stay fully reviewable: Nano devices
page through them, and Stax/Flex/Apex open them in full with "More".

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

## Screens

The Ragger reference snapshots (`tests/standalone/snapshots/`) double as the picture of each flow.
They are regenerated in place with `pytest --golden_run`, so the images below always match
the tests. Stax unless noted; Nano X, Flex and Apex P are under the same test names.

### Home and settings

The home screen with its "Show address" button, app info and the Packages setting (off by
default).

<p><img src="../tests/standalone/snapshots/stax/test_app_mainmenu/00000.png" width="96" alt="test_app_mainmenu 0"> <img src="../tests/standalone/snapshots/stax/test_app_mainmenu/00001.png" width="96" alt="test_app_mainmenu 1"> <img src="../tests/standalone/snapshots/stax/test_app_mainmenu/00002.png" width="96" alt="test_app_mainmenu 2"> <img src="../tests/standalone/snapshots/stax/test_app_mainmenu/00003.png" width="96" alt="test_app_mainmenu 3"></p>

### Verify address

`GET_PUBLIC_KEY` with display: the `g1` address for `m/44'/118'/0'/0/0`.

<p><img src="../tests/standalone/snapshots/stax/test_get_public_key_confirm_accepted/00000.png" width="96" alt="test_get_public_key_confirm_accepted 0"> <img src="../tests/standalone/snapshots/stax/test_get_public_key_confirm_accepted/00001.png" width="96" alt="test_get_public_key_confirm_accepted 1"> <img src="../tests/standalone/snapshots/stax/test_get_public_key_confirm_accepted/00002.png" width="96" alt="test_get_public_key_confirm_accepted 2"> <img src="../tests/standalone/snapshots/stax/test_get_public_key_confirm_accepted/00003.png" width="96" alt="test_get_public_key_confirm_accepted 3"></p>

### Show address

"Show address" on the home screen: the account keypad, the index keypad, then the address and path.

<p><img src="../tests/standalone/snapshots/stax/test_show_address_accepted/keypad/00001.png" width="96" alt="test_show_address_accepted keypad 1"> <img src="../tests/standalone/snapshots/stax/test_show_address_accepted/keypad/00002.png" width="96" alt="test_show_address_accepted keypad 2"> <img src="../tests/standalone/snapshots/stax/test_show_address_accepted/keypad/00004.png" width="96" alt="test_show_address_accepted keypad 4"> <img src="../tests/standalone/snapshots/stax/test_show_address_accepted/00000.png" width="96" alt="test_show_address_accepted 0"> <img src="../tests/standalone/snapshots/stax/test_show_address_accepted/00001.png" width="96" alt="test_show_address_accepted 1"> <img src="../tests/standalone/snapshots/stax/test_show_address_accepted/00002.png" width="96" alt="test_show_address_accepted 2"></p>

### Send

`/bank.MsgSend`: the sequence and the signing account first, then recipient, amount in GNOT, fee, gas and chain ID. Every review starts with the sequence and the signer.

<p><img src="../tests/standalone/snapshots/stax/test_sign_clear_send/00000.png" width="96" alt="test_sign_clear_send 0"> <img src="../tests/standalone/snapshots/stax/test_sign_clear_send/00001.png" width="96" alt="test_sign_clear_send 1"> <img src="../tests/standalone/snapshots/stax/test_sign_clear_send/00002.png" width="96" alt="test_sign_clear_send 2"> <img src="../tests/standalone/snapshots/stax/test_sign_clear_send/00003.png" width="96" alt="test_sign_clear_send 3"> <img src="../tests/standalone/snapshots/stax/test_sign_clear_send/00004.png" width="96" alt="test_sign_clear_send 4"> <img src="../tests/standalone/snapshots/stax/test_sign_clear_send/00005.png" width="96" alt="test_sign_clear_send 5"></p>

### Send with memo and no fee

An empty fee shows as "None"; a memo is shown when present.

<p><img src="../tests/standalone/snapshots/stax/test_sign_clear_send_zero_fee_memo/00000.png" width="96" alt="test_sign_clear_send_zero_fee_memo 0"> <img src="../tests/standalone/snapshots/stax/test_sign_clear_send_zero_fee_memo/00001.png" width="96" alt="test_sign_clear_send_zero_fee_memo 1"> <img src="../tests/standalone/snapshots/stax/test_sign_clear_send_zero_fee_memo/00002.png" width="96" alt="test_sign_clear_send_zero_fee_memo 2"> <img src="../tests/standalone/snapshots/stax/test_sign_clear_send_zero_fee_memo/00003.png" width="96" alt="test_sign_clear_send_zero_fee_memo 3"> <img src="../tests/standalone/snapshots/stax/test_sign_clear_send_zero_fee_memo/00004.png" width="96" alt="test_sign_clear_send_zero_fee_memo 4"> <img src="../tests/standalone/snapshots/stax/test_sign_clear_send_zero_fee_memo/00005.png" width="96" alt="test_sign_clear_send_zero_fee_memo 5"></p>

### Escaped memo

Control characters, non-ASCII text and backslashes are shown as `\xNN` and `\\`, so no two different values look alike.

<p><img src="../tests/standalone/snapshots/stax/test_sign_clear_memo_escapes/00000.png" width="96" alt="test_sign_clear_memo_escapes 0"> <img src="../tests/standalone/snapshots/stax/test_sign_clear_memo_escapes/00001.png" width="96" alt="test_sign_clear_memo_escapes 1"> <img src="../tests/standalone/snapshots/stax/test_sign_clear_memo_escapes/00002.png" width="96" alt="test_sign_clear_memo_escapes 2"> <img src="../tests/standalone/snapshots/stax/test_sign_clear_memo_escapes/00003.png" width="96" alt="test_sign_clear_memo_escapes 3"> <img src="../tests/standalone/snapshots/stax/test_sign_clear_memo_escapes/00004.png" width="96" alt="test_sign_clear_memo_escapes 4"> <img src="../tests/standalone/snapshots/stax/test_sign_clear_memo_escapes/00005.png" width="96" alt="test_sign_clear_memo_escapes 5"> <img src="../tests/standalone/snapshots/stax/test_sign_clear_memo_escapes/00006.png" width="96" alt="test_sign_clear_memo_escapes 6"></p>

### Realm call

`/vm.m_call`: realm, function and every argument verbatim.

<p><img src="../tests/standalone/snapshots/stax/test_sign_clear_call/00000.png" width="96" alt="test_sign_clear_call 0"> <img src="../tests/standalone/snapshots/stax/test_sign_clear_call/00001.png" width="96" alt="test_sign_clear_call 1"> <img src="../tests/standalone/snapshots/stax/test_sign_clear_call/00002.png" width="96" alt="test_sign_clear_call 2"> <img src="../tests/standalone/snapshots/stax/test_sign_clear_call/00003.png" width="96" alt="test_sign_clear_call 3"> <img src="../tests/standalone/snapshots/stax/test_sign_clear_call/00004.png" width="96" alt="test_sign_clear_call 4"> <img src="../tests/standalone/snapshots/stax/test_sign_clear_call/00005.png" width="96" alt="test_sign_clear_call 5"> <img src="../tests/standalone/snapshots/stax/test_sign_clear_call/00006.png" width="96" alt="test_sign_clear_call 6"></p>

### Two messages

Each message is labelled "Message N", followed by the transaction fields.

<p><img src="../tests/standalone/snapshots/stax/test_sign_clear_two_msgs/00000.png" width="96" alt="test_sign_clear_two_msgs 0"> <img src="../tests/standalone/snapshots/stax/test_sign_clear_two_msgs/00001.png" width="96" alt="test_sign_clear_two_msgs 1"> <img src="../tests/standalone/snapshots/stax/test_sign_clear_two_msgs/00002.png" width="96" alt="test_sign_clear_two_msgs 2"> <img src="../tests/standalone/snapshots/stax/test_sign_clear_two_msgs/00003.png" width="96" alt="test_sign_clear_two_msgs 3"> <img src="../tests/standalone/snapshots/stax/test_sign_clear_two_msgs/00004.png" width="96" alt="test_sign_clear_two_msgs 4"> <img src="../tests/standalone/snapshots/stax/test_sign_clear_two_msgs/00005.png" width="96" alt="test_sign_clear_two_msgs 5"> <img src="../tests/standalone/snapshots/stax/test_sign_clear_two_msgs/00006.png" width="96" alt="test_sign_clear_two_msgs 6"></p>

### Approve package

`/vm.m_enable_pkg`: package, full `pkg_hash` and the submission height.

<p><img src="../tests/standalone/snapshots/stax/test_sign_clear_enable_pkg/00000.png" width="96" alt="test_sign_clear_enable_pkg 0"> <img src="../tests/standalone/snapshots/stax/test_sign_clear_enable_pkg/00001.png" width="96" alt="test_sign_clear_enable_pkg 1"> <img src="../tests/standalone/snapshots/stax/test_sign_clear_enable_pkg/00002.png" width="96" alt="test_sign_clear_enable_pkg 2"> <img src="../tests/standalone/snapshots/stax/test_sign_clear_enable_pkg/00003.png" width="96" alt="test_sign_clear_enable_pkg 3"> <img src="../tests/standalone/snapshots/stax/test_sign_clear_enable_pkg/00004.png" width="96" alt="test_sign_clear_enable_pkg 4"> <img src="../tests/standalone/snapshots/stax/test_sign_clear_enable_pkg/00005.png" width="96" alt="test_sign_clear_enable_pkg 5"> <img src="../tests/standalone/snapshots/stax/test_sign_clear_enable_pkg/00006.png" width="96" alt="test_sign_clear_enable_pkg 6"></p>

### Reject package

`/vm.m_reject_pkg`.

<p><img src="../tests/standalone/snapshots/stax/test_sign_clear_reject_pkg/00000.png" width="96" alt="test_sign_clear_reject_pkg 0"> <img src="../tests/standalone/snapshots/stax/test_sign_clear_reject_pkg/00001.png" width="96" alt="test_sign_clear_reject_pkg 1"> <img src="../tests/standalone/snapshots/stax/test_sign_clear_reject_pkg/00002.png" width="96" alt="test_sign_clear_reject_pkg 2"> <img src="../tests/standalone/snapshots/stax/test_sign_clear_reject_pkg/00003.png" width="96" alt="test_sign_clear_reject_pkg 3"> <img src="../tests/standalone/snapshots/stax/test_sign_clear_reject_pkg/00004.png" width="96" alt="test_sign_clear_reject_pkg 4"> <img src="../tests/standalone/snapshots/stax/test_sign_clear_reject_pkg/00005.png" width="96" alt="test_sign_clear_reject_pkg 5"></p>

### Create session

`/auth.m_create_session`: session key as a `g1` address, allowed paths, expiry, spend limit and period.

<p><img src="../tests/standalone/snapshots/stax/test_sign_clear_create_session/00000.png" width="96" alt="test_sign_clear_create_session 0"> <img src="../tests/standalone/snapshots/stax/test_sign_clear_create_session/00001.png" width="96" alt="test_sign_clear_create_session 1"> <img src="../tests/standalone/snapshots/stax/test_sign_clear_create_session/00002.png" width="96" alt="test_sign_clear_create_session 2"> <img src="../tests/standalone/snapshots/stax/test_sign_clear_create_session/00003.png" width="96" alt="test_sign_clear_create_session 3"> <img src="../tests/standalone/snapshots/stax/test_sign_clear_create_session/00004.png" width="96" alt="test_sign_clear_create_session 4"> <img src="../tests/standalone/snapshots/stax/test_sign_clear_create_session/00005.png" width="96" alt="test_sign_clear_create_session 5"> <img src="../tests/standalone/snapshots/stax/test_sign_clear_create_session/00006.png" width="96" alt="test_sign_clear_create_session 6"></p>

### Create session allowed to run scripts

A session allowed `vm/run` gets a warning and needs the Packages setting.

<p><img src="../tests/standalone/snapshots/stax/test_sign_clear_create_session_run/00000.png" width="96" alt="test_sign_clear_create_session_run 0"> <img src="../tests/standalone/snapshots/stax/test_sign_clear_create_session_run/00001.png" width="96" alt="test_sign_clear_create_session_run 1"> <img src="../tests/standalone/snapshots/stax/test_sign_clear_create_session_run/00002.png" width="96" alt="test_sign_clear_create_session_run 2"> <img src="../tests/standalone/snapshots/stax/test_sign_clear_create_session_run/00003.png" width="96" alt="test_sign_clear_create_session_run 3"> <img src="../tests/standalone/snapshots/stax/test_sign_clear_create_session_run/00004.png" width="96" alt="test_sign_clear_create_session_run 4"> <img src="../tests/standalone/snapshots/stax/test_sign_clear_create_session_run/00005.png" width="96" alt="test_sign_clear_create_session_run 5"> <img src="../tests/standalone/snapshots/stax/test_sign_clear_create_session_run/00006.png" width="96" alt="test_sign_clear_create_session_run 6"></p>

### Create session (risky settings)

Warnings for `*` allow-paths (which include scripts, so the Packages setting is needed) and no expiry; an absent spend limit shows as "None (cannot spend)".

<p><img src="../tests/standalone/snapshots/stax/test_sign_clear_create_session_minimal/00000.png" width="96" alt="test_sign_clear_create_session_minimal 0"> <img src="../tests/standalone/snapshots/stax/test_sign_clear_create_session_minimal/00001.png" width="96" alt="test_sign_clear_create_session_minimal 1"> <img src="../tests/standalone/snapshots/stax/test_sign_clear_create_session_minimal/00002.png" width="96" alt="test_sign_clear_create_session_minimal 2"> <img src="../tests/standalone/snapshots/stax/test_sign_clear_create_session_minimal/00003.png" width="96" alt="test_sign_clear_create_session_minimal 3"> <img src="../tests/standalone/snapshots/stax/test_sign_clear_create_session_minimal/00004.png" width="96" alt="test_sign_clear_create_session_minimal 4"> <img src="../tests/standalone/snapshots/stax/test_sign_clear_create_session_minimal/00005.png" width="96" alt="test_sign_clear_create_session_minimal 5"> <img src="../tests/standalone/snapshots/stax/test_sign_clear_create_session_minimal/00006.png" width="96" alt="test_sign_clear_create_session_minimal 6"></p>

### Revoke session

`/auth.m_revoke_session`.

<p><img src="../tests/standalone/snapshots/stax/test_sign_clear_revoke_session/00000.png" width="96" alt="test_sign_clear_revoke_session 0"> <img src="../tests/standalone/snapshots/stax/test_sign_clear_revoke_session/00001.png" width="96" alt="test_sign_clear_revoke_session 1"> <img src="../tests/standalone/snapshots/stax/test_sign_clear_revoke_session/00002.png" width="96" alt="test_sign_clear_revoke_session 2"> <img src="../tests/standalone/snapshots/stax/test_sign_clear_revoke_session/00003.png" width="96" alt="test_sign_clear_revoke_session 3"> <img src="../tests/standalone/snapshots/stax/test_sign_clear_revoke_session/00004.png" width="96" alt="test_sign_clear_revoke_session 4"> <img src="../tests/standalone/snapshots/stax/test_sign_clear_revoke_session/00005.png" width="96" alt="test_sign_clear_revoke_session 5"></p>

### Revoke all sessions

`/auth.m_revoke_all_sessions`.

<p><img src="../tests/standalone/snapshots/stax/test_sign_clear_revoke_all_sessions/00000.png" width="96" alt="test_sign_clear_revoke_all_sessions 0"> <img src="../tests/standalone/snapshots/stax/test_sign_clear_revoke_all_sessions/00001.png" width="96" alt="test_sign_clear_revoke_all_sessions 1"> <img src="../tests/standalone/snapshots/stax/test_sign_clear_revoke_all_sessions/00002.png" width="96" alt="test_sign_clear_revoke_all_sessions 2"> <img src="../tests/standalone/snapshots/stax/test_sign_clear_revoke_all_sessions/00003.png" width="96" alt="test_sign_clear_revoke_all_sessions 3"> <img src="../tests/standalone/snapshots/stax/test_sign_clear_revoke_all_sessions/00004.png" width="96" alt="test_sign_clear_revoke_all_sessions 4"> <img src="../tests/standalone/snapshots/stax/test_sign_clear_revoke_all_sessions/00005.png" width="96" alt="test_sign_clear_revoke_all_sessions 5"></p>

### Deploy package

`/vm.m_addpkg` with Packages enabled: the blind-signing warning, then imports, literal addresses (the signer marked "(you)"), files, size and fingerprint. The README, comment and test-file address in this package are correctly left out.

<p><img src="../tests/standalone/snapshots/stax/test_sign_package_addpkg_highlights/warning/00000.png" width="96" alt="test_sign_package_addpkg_highlights 0"> <img src="../tests/standalone/snapshots/stax/test_sign_package_addpkg_highlights/00000.png" width="96" alt="test_sign_package_addpkg_highlights 1"> <img src="../tests/standalone/snapshots/stax/test_sign_package_addpkg_highlights/00001.png" width="96" alt="test_sign_package_addpkg_highlights 2"> <img src="../tests/standalone/snapshots/stax/test_sign_package_addpkg_highlights/00002.png" width="96" alt="test_sign_package_addpkg_highlights 3"> <img src="../tests/standalone/snapshots/stax/test_sign_package_addpkg_highlights/00003.png" width="96" alt="test_sign_package_addpkg_highlights 4"> <img src="../tests/standalone/snapshots/stax/test_sign_package_addpkg_highlights/00004.png" width="96" alt="test_sign_package_addpkg_highlights 5"> <img src="../tests/standalone/snapshots/stax/test_sign_package_addpkg_highlights/00005.png" width="96" alt="test_sign_package_addpkg_highlights 6"> <img src="../tests/standalone/snapshots/stax/test_sign_package_addpkg_highlights/00006.png" width="96" alt="test_sign_package_addpkg_highlights 7"> <img src="../tests/standalone/snapshots/stax/test_sign_package_addpkg_highlights/00007.png" width="96" alt="test_sign_package_addpkg_highlights 8"> <img src="../tests/standalone/snapshots/stax/test_sign_package_addpkg_highlights/00008.png" width="96" alt="test_sign_package_addpkg_highlights 9"> <img src="../tests/standalone/snapshots/stax/test_sign_package_addpkg_highlights/00009.png" width="96" alt="test_sign_package_addpkg_highlights 10"></p>

### Run script

`/vm.m_run`: the extra warning "Script can do anything your account can".

<p><img src="../tests/standalone/snapshots/stax/test_sign_package_run/warning/00000.png" width="96" alt="test_sign_package_run 0"> <img src="../tests/standalone/snapshots/stax/test_sign_package_run/00000.png" width="96" alt="test_sign_package_run 1"> <img src="../tests/standalone/snapshots/stax/test_sign_package_run/00001.png" width="96" alt="test_sign_package_run 2"> <img src="../tests/standalone/snapshots/stax/test_sign_package_run/00002.png" width="96" alt="test_sign_package_run 3"> <img src="../tests/standalone/snapshots/stax/test_sign_package_run/00003.png" width="96" alt="test_sign_package_run 4"> <img src="../tests/standalone/snapshots/stax/test_sign_package_run/00004.png" width="96" alt="test_sign_package_run 5"> <img src="../tests/standalone/snapshots/stax/test_sign_package_run/00005.png" width="96" alt="test_sign_package_run 6"> <img src="../tests/standalone/snapshots/stax/test_sign_package_run/00006.png" width="96" alt="test_sign_package_run 7"> <img src="../tests/standalone/snapshots/stax/test_sign_package_run/00007.png" width="96" alt="test_sign_package_run 8"></p>

### Send on Nano S+

The same send on a button device, one field per page.

<p><img src="../tests/standalone/snapshots/nanosp/test_sign_clear_send/00000.png" width="160" alt="test_sign_clear_send 0"> <img src="../tests/standalone/snapshots/nanosp/test_sign_clear_send/00001.png" width="160" alt="test_sign_clear_send 1"> <img src="../tests/standalone/snapshots/nanosp/test_sign_clear_send/00002.png" width="160" alt="test_sign_clear_send 2"> <img src="../tests/standalone/snapshots/nanosp/test_sign_clear_send/00003.png" width="160" alt="test_sign_clear_send 3"> <img src="../tests/standalone/snapshots/nanosp/test_sign_clear_send/00004.png" width="160" alt="test_sign_clear_send 4"> <img src="../tests/standalone/snapshots/nanosp/test_sign_clear_send/00005.png" width="160" alt="test_sign_clear_send 5"> <img src="../tests/standalone/snapshots/nanosp/test_sign_clear_send/00006.png" width="160" alt="test_sign_clear_send 6"> <img src="../tests/standalone/snapshots/nanosp/test_sign_clear_send/00007.png" width="160" alt="test_sign_clear_send 7"> <img src="../tests/standalone/snapshots/nanosp/test_sign_clear_send/00008.png" width="160" alt="test_sign_clear_send 8"> <img src="../tests/standalone/snapshots/nanosp/test_sign_clear_send/00009.png" width="160" alt="test_sign_clear_send 9"></p>

## Test vectors

`tools/vectors` renders one payload per message type with upstream gno, pinned in its `go.mod`,
and signs it with the Speculos seed. The output, `tests/vectors/sign_docs.json`, drives both
`host-tests` (parser, run on the host) and the Ragger tests, which also check that the device's
signature equals gno's byte for byte. When bumping gno, regenerate the file and review the diff:
a changed payload means the schema in `src/tx/schema.rs` may need updating.

## Out of scope

- Swap/Exchange integration: GNOT is not listed in Ledger's Exchange app, and the boilerplate's
  swap support has been removed.
