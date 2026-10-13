# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Ledger AI instructions submodule

Generic, cross-repo Ledger embedded-app rules live in the `ledger-app-ai-instructions` submodule
(top-level directory), imported via the `@ledger-app-ai-instructions/CLAUDE.md` line above. It carries
`EMBEDDED.instructions.md`, `RUST.instructions.md`, `C.instructions.md`, `TEST.instructions.md`, and
`REVIEW.instructions.md`. `.github/instructions` is a symlink into `ledger-app-ai-instructions/instructions`
so GitHub Copilot picks up the same files. Run `git submodule update --init` after cloning, or both the
import and the symlink will dangle. Keep this `CLAUDE.md` limited to app-specific guidance; contribute
cross-repo rules to the submodule instead.

@ledger-app-ai-instructions/CLAUDE.md

## Gno-specific instructions

Chain facts, sign-doc format, signature encoding and the clear-signing policy for gno.land live in
`docs/GNO.instructions.md`; the wire protocol is in `docs/APDU.md`.

@docs/GNO.instructions.md

## What this repo is

Ledger hardware-wallet application for Gno (gno.land), written in Rust, targeting Nano X, Nano S+, Stax, Flex, and Apex P. It is a `#![no_std]` / `#![no_main]` embedded binary built against `ledger_device_sdk`, forked from [`LedgerHQ/app-boilerplate-rust`](https://github.com/LedgerHQ/app-boilerplate-rust) at `0f857a7`. Nano S is **not** supported.

## Architecture

### Layout

- `src/main.rs` — `Instruction` parsing and `AppSW` status words. **All APDU parameter validation lives in `Instruction::try_from`, not in the handlers.**
- `src/handlers/` — one handler per instruction, returning `Result<CommandResponse, AppSW>`.
- `src/tx/` — the sign-doc parser. **No SDK dependency**: hashing comes in through the `Hashes` trait, so `host-tests` compiles the same files for the host. Keep it that way.
  - `json.rs` — streaming lexer for the strict JSON subset amino emits (no whitespace, numbers or literals).
  - `schema.rs` — every accepted key, in amino's sorted order, with its review label and rank.
  - `mod.rs` — `Parser`: walks the schema, validates values, collects review fields, computes package fingerprints.
  - `encoding.rs` — bech32, base64, canonical decimals, GNOT amounts, UTC dates, escaping for display.
  - `source.rs` — single-pass Go tokenizer that pulls import paths and literal `g1` addresses out of package source for the review.
- `src/crypto.rs` — key derivation, `g1` addresses, and the conversion from SDK DER signatures to tm2's 64-byte low-S form.
- `src/bip32.rs` — accepts only `m/44'/118'/a'/0/i`, in a fixed array; `address_index` builds the first account's path for "Show address".
- `src/app_ui/` — NBGL screens; `src/settings.rs` — the NVM-backed "Packages" switch.

### Signing flow

`SIGN_TX` opens a session with the path chunk. Each following chunk goes to a running SHA-256 and to `Parser::feed`, so the payload is never buffered. The last chunk triggers `Parser::finish`, the package-setting gate, the review and the signature. Any error drops the session (`TxContext.session` is taken, not borrowed), so a half-fed parser can never be resumed.

To support a new message type, add its schema to `src/tx/schema.rs`, a case in `tools/vectors/main.go`, and expectations in `host-tests/tests/parser.rs` and `tests/standalone/test_sign_cmd.py`.

### UI (NBGL)

- Home + settings: `show_home()` in `src/app_ui/menu.rs`, re-shown after each flow. It calls `nbgl_useCaseHomeAndSettings` directly with descriptors in static variables, because the SDK's `NbglHomeAndSettings` passes the action button's descriptor from its stack and Nano NBGL keeps that pointer.
- "Show address" (`src/app_ui/show_address.rs`) starts from the home screen's button, inside `Comm::next_command`, so it chains NBGL's asynchronous use cases (keypad, address review, status) instead of the SDK's blocking screens, which need the `Comm`.
- After each command, `show_status_and_home_if_needed` in `src/main.rs` shows the NBGL success/failure page and returns home.
- Icons are derived from the gnolang GitHub avatar, one per device size, in the same formats as the boilerplate's (1-bit for Nano and Apex P, 16-level grey on white for Stax and Flex).
- `build.rs` pre-processes `icons/gno_14x14.gif` + `icons/mask_14x14.gif` into `glyphs/home_nano_nbgl.png` at compile time.

## App-specific embedded notes (when editing Rust code)

The generic embedded/Rust rules are imported above; the points below are this app's concrete conventions:

- `#![no_std]` — `extern crate alloc` is declared in `main.rs` (and in `host-tests/src/lib.rs`); use `alloc::{vec::Vec, string::String, format}`. Never reference `std::`.
- Treat APDU bytes as untrusted input — validate lengths and structure before parsing.
- Secrets derived from the seed must never be stored, exported, or shown to the user. `ECPrivateKey` zeroes itself on drop; keep keys scoped to the call that needs them.
- Use `ledger_device_sdk::log::debug!` around APDU entry points, crypto calls, and parsing — these are the only way to debug on Speculos.
- The only blind-signing path is package messages behind the "Packages" setting. Do not add others.

## Tests

- `host-tests/` — `cargo +stable test` on the host (it has its own `.cargo/config.toml` that undoes the device target; stable because the pinned nightly would apply the root config's `build-std`). Fast; run it first for any `src/tx` change.
- `tools/vectors/` — Go program rendering `tests/vectors/sign_docs.json` with upstream gno. Regenerate with `go run . > ../../tests/vectors/sign_docs.json`.
- `fuzz/` — cargo-fuzz targets for the parser, DER conversion and source scanner, run by ClusterFuzzLite (`.clusterfuzzlite/`). Run locally with `./fuzz/run.sh <target> <seconds>`, which builds from a copy outside the repo because the root cargo config is for the device.
- `tests/application_client/` — Python `GnoCommandSender`, response unpacker, vector loading, and `navigation.py` for toggling settings.
- `tests/standalone/` — Ragger suite. Signatures are checked against both the public key and gno's own signature for the same payload.
- Tests must construct APDU payloads with named variables — no raw hex literals.
