# Gno application APDU protocol

All commands use `CLA = 0xE0`. Responses end with a two-byte status word; data
precedes it where listed. Integers are big-endian.

## Commands

| INS | Command | P1 | P2 | Data |
| --- | --- | --- | --- | --- |
| `0x03` | GET_VERSION | `0x00` | `0x00` | none (any data returns `WRONG_APDU_LENGTH`) |
| `0x04` | GET_APP_NAME | `0x00` | `0x00` | none (any data returns `WRONG_APDU_LENGTH`) |
| `0x05` | GET_PUBLIC_KEY | `0x00` silent, `0x01` confirm on screen | `0x00` | path |
| `0x06` | SIGN_TX | `0x00` first chunk, `0x01` next chunk | `0x80` more, `0x00` last | see below |

### Derivation path

```text
count (1) = 5 | purpose (4) | coin type (4) | account (4) | change (4) | index (4)
```

Only `m/44'/118'/account'/0/index` is accepted: hardened account, change `0`,
unhardened index. Anything else returns `INVALID_PATH`; a different component
count returns `WRONG_APDU_LENGTH`.

### GET_VERSION

Response: `major (1) | minor (1) | patch (1)`.

### GET_APP_NAME

Response: the ASCII string `Gno`.

### GET_PUBLIC_KEY

Response:

```text
pubkey length (1) = 33 | compressed secp256k1 public key (33)
address length (1) = 40 | bech32 address, ASCII, e.g. g1... (40)
```

With `P1 = 0x01` the address is shown first and `DENY` is returned if the user
rejects it.

### SIGN_TX

The host sends the signature payload, the bytes `std.GetSignaturePayload`
returns in gno, after a path chunk:

1. `P1 = 0x00, P2 = 0x80`: the derivation path. Opens a session and discards
   any earlier one. `P2 = 0x00` is refused, since a payload must follow.
2. `P1 = 0x01, P2 = 0x80`: a payload chunk of up to 255 bytes. Repeat as needed.
3. `P1 = 0x01, P2 = 0x00`: the last payload chunk. The device shows the review
   and, if the user approves, returns the signature.

The payload has no length limit: the device hashes and parses it as it streams.
A session survives only its own chunks. It closes on any error, on any command
with a wrong CLA, INS, P1 or P2, and on any other instruction, so a retry starts
again at step 1. The payload must be byte for byte what gno renders: strings use
Go's `encoding/json` escaping and valid UTF-8, coins are valid tm2 coins, and the
fee is at most one positive coin (`docs/GNO.instructions.md`).

The review starts with the signing account's `g1` address, since the host
chooses the derivation path.

Response: `signature (64)`, which is `R (32) | S (32)` with S in the lower half
of the group order, over `SHA-256(payload)`. This is the form tm2 verifies.

## Package fingerprint

`m_addpkg` and `m_run` carry source files that cannot be reviewed on the device.
The review instead shows a fingerprint of the files, which the user compares
with one computed on a machine they trust:

```text
fingerprint = SHA-256( for each file, in payload order:
                         u32be(len(name)) | name | SHA-256(body) )
```

`name` and `body` are the decoded JSON strings as UTF-8 bytes, not the escaped
form in the payload. Files must be sorted by name, strictly ascending bytewise,
which the chain also requires; unsorted payloads are rejected.

Two things to note:

- The body is hashed separately because amino sorts `body` before `name`, so
  the device sees each body before it knows the file's name.
- This is not gno's `PackageContentHash`, which also rewrites `gnomod.toml`
  before hashing. The fingerprint covers the files exactly as sent.

Reference implementations: `reference_fingerprint` in
`host-tests/tests/parser.rs` and the `Leaf::FileName` branch of `src/tx/mod.rs`.

Next to the fingerprint, the review lists each file and the import paths and
literal `g1` addresses found in the executed source. These help spot a crude
substitution without a trusted machine, but they can be evaded and do not
replace comparing the fingerprint. `docs/GNO.instructions.md` defines them.

## Status words

| SW | Name | Meaning |
| --- | --- | --- |
| `0x9000` | OK | Success |
| `0x6985` | DENY | The user rejected the request |
| `0x6A86` | WRONG_P1P2 | Invalid P1/P2 for the instruction |
| `0x6D00` | INS_NOT_SUPPORTED | Unknown instruction |
| `0x6E00` | CLA_NOT_SUPPORTED | Wrong CLA |
| `0x6E03` | WRONG_APDU_LENGTH | Malformed data length |
| `0xB002` | ADDR_DISPLAY_FAIL | The address could not be displayed |
| `0xB005` | TX_PARSING_FAIL | The payload is not an accepted gno sign doc |
| `0xB008` | TX_SIGN_FAIL | Signing failed |
| `0xB009` | KEY_DERIVE_FAIL | Key derivation failed |
| `0xB00A` | VERSION_PARSING_FAIL | The app version could not be encoded |
| `0xB00B` | INVALID_PATH | The path is outside `m/44'/118'/a'/0/i` |
| `0xB00C` | TX_NO_SESSION | A payload chunk arrived without an open session |
| `0xB00D` | TX_WRONG_SIGNER | A message is signed by an address other than the device's |
| `0xB00E` | TX_TOO_LARGE | A displayed value or the review exceeds device limits |
| `0xB00F` | PACKAGE_TX_DISABLED | The Packages setting is off and the payload can run code: `m_addpkg`, `m_run`, or a session allowed `vm/run` or `*` |
