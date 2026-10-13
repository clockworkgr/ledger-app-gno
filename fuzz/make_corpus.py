"""Writes seed corpora for the fuzz targets from the gno-rendered test vectors.

Usage: python3 make_corpus.py <repo root> <output dir>
Creates <output dir>/{fuzz_parser,fuzz_der,fuzz_source}/.
"""

import hashlib
import json
import sys
from pathlib import Path

N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141


def der_int(v: int) -> bytes:
    b = v.to_bytes(32, "big").lstrip(b"\0") or b"\0"
    if b[0] >= 0x80:
        b = b"\0" + b
    return bytes([0x02, len(b)]) + b


def der(r: int, s: int) -> bytes:
    body = der_int(r) + der_int(s)
    return bytes([0x30, len(body)]) + body


def write(directory: Path, data: bytes) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    (directory / hashlib.sha1(data).hexdigest()).write_bytes(data)


def main() -> None:
    root, out = Path(sys.argv[1]), Path(sys.argv[2])
    vectors = json.loads((root / "tests/vectors/sign_docs.json").read_text())["vectors"]
    for v in vectors:
        doc = v["sign_bytes"].encode()
        # No chunk sizes, then the same payload in 1- and 7-byte chunks.
        write(out / "fuzz_parser", b"\0" + doc)
        write(out / "fuzz_parser", b"\x02\x01\x07" + doc)

        sig = bytes.fromhex(v["signature"])
        r, s = int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big")
        write(out / "fuzz_der", der(r, s))
        write(out / "fuzz_der", der(r, N - s))

        for msg in json.loads(doc)["msgs"]:
            for f in msg.get("package", {}).get("files", []):
                write(out / "fuzz_source", b"\0" + f["body"].encode())


if __name__ == "__main__":
    main()
