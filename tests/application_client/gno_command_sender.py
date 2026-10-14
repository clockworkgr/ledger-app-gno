from collections.abc import Generator
from contextlib import contextmanager
from enum import IntEnum

from ragger.backend.interface import RAPDU, BackendInterface
from ragger.bip import pack_derivation_path

MAX_APDU_LEN: int = 255

CLA: int = 0xE0


class InsType(IntEnum):
    GET_VERSION = 0x03
    GET_APP_NAME = 0x04
    GET_PUBLIC_KEY = 0x05
    SIGN_TX = 0x06


class P1(IntEnum):
    PUBKEY_SILENT = 0x00
    PUBKEY_DISPLAY = 0x01
    SIGN_TX_FIRST = 0x00
    SIGN_TX_NEXT = 0x01


class P2(IntEnum):
    SIGN_TX_LAST = 0x00
    SIGN_TX_MORE = 0x80


class Errors(IntEnum):
    SW_COMMAND_NOT_ACCEPTED = 0x6901
    SW_DENY = 0x6985
    SW_WRONG_P1P2 = 0x6A86
    SW_INS_NOT_SUPPORTED = 0x6D00
    SW_CLA_NOT_SUPPORTED = 0x6E00
    SW_WRONG_APDU_LENGTH = 0x6E03
    SW_TX_PARSING_FAIL = 0xB005
    SW_INVALID_PATH = 0xB00B
    SW_TX_NO_SESSION = 0xB00C
    SW_TX_WRONG_SIGNER = 0xB00D
    SW_TX_TOO_LARGE = 0xB00E
    SW_PACKAGE_TX_DISABLED = 0xB00F


def split_message(message: bytes, max_size: int) -> list[bytes]:
    return [message[x : x + max_size] for x in range(0, len(message), max_size)]


class GnoCommandSender:
    def __init__(self, backend: BackendInterface) -> None:
        self.backend = backend

    def get_version(self) -> RAPDU:
        return self.backend.exchange(cla=CLA, ins=InsType.GET_VERSION)

    def get_app_name(self) -> RAPDU:
        return self.backend.exchange(cla=CLA, ins=InsType.GET_APP_NAME)

    def get_public_key(self, path: str) -> RAPDU:
        return self.backend.exchange(
            cla=CLA,
            ins=InsType.GET_PUBLIC_KEY,
            p1=P1.PUBKEY_SILENT,
            data=pack_derivation_path(path),
        )

    @contextmanager
    def get_public_key_with_confirmation(self, path: str) -> Generator[None, None, None]:
        with self.backend.exchange_async(
            cla=CLA,
            ins=InsType.GET_PUBLIC_KEY,
            p1=P1.PUBKEY_DISPLAY,
            data=pack_derivation_path(path),
        ) as response:
            yield response

    def sign_tx_start(self, path: str) -> RAPDU:
        return self.backend.exchange(
            cla=CLA,
            ins=InsType.SIGN_TX,
            p1=P1.SIGN_TX_FIRST,
            p2=P2.SIGN_TX_MORE,
            data=pack_derivation_path(path),
        )

    def sign_tx_chunks(self, sign_bytes: bytes) -> list[bytes]:
        """Sends every chunk but the last, which the caller sends."""
        chunks = split_message(sign_bytes, MAX_APDU_LEN)
        for chunk in chunks[:-1]:
            self.backend.exchange(cla=CLA, ins=InsType.SIGN_TX, p1=P1.SIGN_TX_NEXT, p2=P2.SIGN_TX_MORE, data=chunk)
        return chunks

    @contextmanager
    def sign_tx(self, path: str, sign_bytes: bytes) -> Generator[None, None, None]:
        self.sign_tx_start(path)
        last = self.sign_tx_chunks(sign_bytes)[-1]
        with self.backend.exchange_async(
            cla=CLA, ins=InsType.SIGN_TX, p1=P1.SIGN_TX_NEXT, p2=P2.SIGN_TX_LAST, data=last
        ) as response:
            yield response

    def sign_tx_no_ui(self, path: str, sign_bytes: bytes) -> RAPDU:
        """Signs a payload expected to be rejected before any screen is shown."""
        self.sign_tx_start(path)
        last = self.sign_tx_chunks(sign_bytes)[-1]
        return self.backend.exchange(cla=CLA, ins=InsType.SIGN_TX, p1=P1.SIGN_TX_NEXT, p2=P2.SIGN_TX_LAST, data=last)

    def get_async_response(self) -> RAPDU | None:
        return self.backend.last_async_response
