# Gno Validator (benchmark build)

A second Ledger app built from this repository. It will sign gno.land consensus
messages (prevotes, precommits, proposals) for a validator. This first build
only measures Ed25519 signing speed on the device.

**It signs any message it is sent without confirmation.** It uses a key kept for
benchmarking (`m/44'/118'/9999'/0'/0'`, SLIP-10), never the one a validator will
run with. Do not use it for anything else.

## Build and install

```bash
cd validator
cargo ledger build nanosplus      # or nanox, stax, flex, apex_p
```

The build uses the repository's toolchain and device cargo config. Install it
like the main app, e.g. with `ledgerblue.runScript` on
`target/nanosplus/release/app-gno-validator.apdu`.

## Commands

All commands use `CLA = 0xE0`.

| INS | Command | P1 | P2 | Data | Response |
| --- | --- | --- | --- | --- | --- |
| `0x03` | GET_VERSION | `0x00` | `0x00` | none | major, minor, patch (1 byte each) |
| `0x04` | GET_APP_NAME | `0x00` | `0x00` | none | `Gno Validator` |
| `0x05` | GET_PUBLIC_KEY | `0x00` | `0x00` | none | Ed25519 public key (32) |
| `0x10` | SIGN | `0x00` derive the key, `0x01` keep it in RAM | `0x00` | message (1–255 bytes) | signature (64) |
| `0x7F` | BENCH | iterations (1–255) | `0x00` derive each time, `0x01` derive once | message (1–255 bytes) | last signature (64) |

## Benchmark

```bash
pip install ledgerblue pycryptodome
python bench/bench.py --count 50 --batch 100
```

It signs canonical prevotes and precommits (the Tendermint v0.34 layout tm2
uses), verifies every signature against the device's key, and prints:

- SIGN: time per signature including the USB round trip, as a validator would
  see it;
- BENCH: time per signature on the device alone.

Set `LEDGER_PROXY_ADDRESS=127.0.0.1` and `LEDGER_PROXY_PORT=9999` to run it
against Speculos. Speculos timings do not reflect a real device.
