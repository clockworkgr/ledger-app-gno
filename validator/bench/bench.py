"""Times Ed25519 signing on the Gno Validator benchmark build.

Usage: python bench.py [--count N] [--batch N]

Talks to a real device over USB, or to Speculos when LEDGER_PROXY_ADDRESS and
LEDGER_PROXY_PORT are set (e.g. 127.0.0.1 and 9999). Needs ledgerblue and
pycryptodome.
"""

import argparse
import struct
import time

from Crypto.Signature import eddsa
from ledgerblue.comm import getDongle

CLA = 0xE0
INS_GET_APP_NAME = 0x04
INS_GET_PUBLIC_KEY = 0x05
INS_SIGN = 0x10
INS_BENCH = 0x7F
KEY_DERIVE = 0x00
KEY_CACHED = 0x01

PREVOTE = 0x01
PRECOMMIT = 0x02


def uvarint(n: int) -> bytes:
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def field(number: int, wire_type: int, payload: bytes) -> bytes:
    return uvarint(number << 3 | wire_type) + payload


def varint_field(number: int, value: int) -> bytes:
    return field(number, 0, uvarint(value)) if value else b""


def fixed64_field(number: int, value: int) -> bytes:
    return field(number, 1, struct.pack("<q", value)) if value else b""


def bytes_field(number: int, value: bytes) -> bytes:
    return field(number, 2, uvarint(len(value)) + value) if value else b""


def canonical_vote(
    vote_type: int,
    height: int,
    round_: int,
    block_hash: bytes,
    parts_total: int,
    parts_hash: bytes,
    seconds: int,
    nanos: int,
    chain_id: str,
) -> bytes:
    """tm2's CanonicalVote sign bytes (Tendermint v0.34 layout), length-prefixed."""
    parts = varint_field(1, parts_total) + bytes_field(2, parts_hash)
    block_id = bytes_field(1, block_hash) + bytes_field(2, parts)
    timestamp = varint_field(1, seconds) + varint_field(2, nanos)
    body = (
        varint_field(1, vote_type)
        + fixed64_field(2, height)
        + fixed64_field(3, round_)
        + bytes_field(4, block_id)
        + bytes_field(5, timestamp)
        + bytes_field(6, chain_id.encode())
    )
    return uvarint(len(body)) + body


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--count", type=int, default=50, help="single signs per mode")
    parser.add_argument("--batch", type=int, default=100, help="on-device signs per mode")
    args = parser.parse_args()

    dongle = getDongle(False)

    def exchange(ins: int, p1: int = 0, p2: int = 0, data: bytes = b"") -> bytes:
        return bytes(dongle.exchange(bytes([CLA, ins, p1, p2, len(data)]) + data, timeout=120))

    print("app:", exchange(INS_GET_APP_NAME).decode())
    pubkey = exchange(INS_GET_PUBLIC_KEY)
    print("benchmark pubkey:", pubkey.hex())
    verifier = eddsa.new(eddsa.import_public_key(pubkey), "rfc8032")

    def vote(height: int, vote_type: int = PREVOTE) -> bytes:
        return canonical_vote(
            vote_type, height, 0, bytes(range(32)), 1, bytes(range(32, 64)), 1_760_000_000, 123_456_789, "test-chain"
        )

    print("sign bytes:", len(vote(1)), "bytes")

    for name, mode in (("derive per sign", KEY_DERIVE), ("cached key", KEY_CACHED)):
        start = time.perf_counter()
        for h in range(1, args.count + 1):
            msg = vote(h, PREVOTE if h % 2 else PRECOMMIT)
            verifier.verify(msg, exchange(INS_SIGN, mode, 0, msg))
        per = (time.perf_counter() - start) / args.count
        print(f"SIGN, {name}: {per * 1000:.1f} ms per signature over USB ({args.count} signatures, all verified)")

    msg = vote(1)
    for name, mode in (("derive per sign", KEY_DERIVE), ("cached key", KEY_CACHED)):
        total = 0.0
        done = 0
        while done < args.batch:
            n = min(255, args.batch - done)
            start = time.perf_counter()
            sig = exchange(INS_BENCH, n, mode, msg)
            total += time.perf_counter() - start
            verifier.verify(msg, sig)
            done += n
        print(f"BENCH, {name}: {total / done * 1000:.1f} ms per signature on the device ({done} signatures)")

    dongle.close()


if __name__ == "__main__":
    main()
