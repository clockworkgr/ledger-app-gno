# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0]

### Added

- Key derivation on `m/44'/118'/account'/0/index` and `g1` address display.
- Streaming parser for gno.land amino sign docs, signing with SHA-256 / secp256k1 and returning
  64-byte low-S signatures.
- Clear signing for `/bank.MsgSend`, `/vm.m_call`, `/vm.m_enable_pkg`, `/vm.m_reject_pkg`,
  `/auth.m_create_session`, `/auth.m_revoke_session` and `/auth.m_revoke_all_sessions`.
- `/vm.m_addpkg` and `/vm.m_run` behind the "Packages" setting (off by default), signed through
  the blind-signing flow with a package fingerprint, the file list, and the imports and literal
  addresses found in the executed source.
