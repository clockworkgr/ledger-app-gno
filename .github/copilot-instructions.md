# Ledger Gno App Development Guide

This is a Rust application for Ledger hardware wallets (Nano X, S+, Stax, Flex, Apex P) using the `ledger_device_sdk`. It signs gno.land (Tendermint2) transactions.

Generic Ledger rules are in `.github/instructions/` (a symlink into the `ledger-app-ai-instructions` submodule). Gno-specific rules for keys, sign bytes, signatures and clear signing are in `docs/GNO.instructions.md`; the wire protocol is in `docs/APDU.md`. Both take precedence over anything below.

## Architecture

- `src/main.rs` — `Instruction` parsing (all APDU parameter validation lives in `Instruction::try_from`) and the `AppSW` status words.
- `src/handlers/` — one handler per instruction, returning `Result<CommandResponse, AppSW>`.
- `src/tx/` — the streaming sign-doc parser. It has **no SDK dependency** (hashing is injected through the `Hashes` trait) so `host-tests/` compiles the same files for the host. Keep it that way.
  - `json.rs` lexes the strict JSON subset amino emits; `schema.rs` lists every accepted key in sorted order; `mod.rs` validates values, builds the review and computes package fingerprints; `source.rs` pulls imports and literal addresses out of package source; `encoding.rs` holds bech32, base64, decimals, amounts and dates.
- `src/crypto.rs` — key derivation, `g1` addresses, DER to 64-byte low-S signatures.
- `src/bip32.rs` — accepts only `m/44'/118'/a'/0/i`.
- `src/app_ui/`, `src/settings.rs` — NBGL screens and the NVM "Packages" switch.

`SIGN_TX` opens a session with a path chunk, then hashes and parses each payload chunk as it arrives; the payload is never buffered. Any error drops the session.

## Build & Test Workflow

```bash
cargo ledger build nanosplus          # nanox | nanosplus | stax | flex | apex_p
cd host-tests && cargo test           # parser, on the host
pytest tests/standalone/ --tb=short -v --device nanosp
```

`tools/vectors/` renders `tests/vectors/sign_docs.json` with upstream gno; both test suites replay it, and the Ragger tests require the device's signature to equal gno's byte for byte. To add a message type, update `src/tx/schema.rs`, `tools/vectors/main.go`, `host-tests/tests/parser.rs` and `tests/standalone/test_sign_cmd.py` together.

## Critical Constraints

- `#![no_std]`: use `alloc::{vec::Vec, string::String, format}`, never `std::`.
- Treat every APDU byte as untrusted. Fail closed: reject, never truncate or default.
- Signing and key export always go through a user-validation screen. The only blind-signing path is package messages behind the "Packages" setting.
- Python tests build payloads from named values or the shared vectors, never raw hex literals.
