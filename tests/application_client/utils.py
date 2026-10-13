import json
from hashlib import sha256
from pathlib import Path

from ecdsa.curves import SECP256k1
from ecdsa.keys import VerifyingKey
from ecdsa.util import sigdecode_string

VECTORS_FILE = Path(__file__).parent.parent / "vectors" / "sign_docs.json"


def load_vectors() -> dict:
    """Signature payloads rendered by upstream gno; see tools/vectors."""
    with open(VECTORS_FILE, encoding="utf-8") as f:
        return json.load(f)


def sign_bytes(vectors: dict, name: str) -> bytes:
    for v in vectors["vectors"]:
        if v["name"] == name:
            return v["sign_bytes"].encode("utf-8")
    raise KeyError(name)


def reference_signature(vectors: dict, name: str) -> bytes:
    for v in vectors["vectors"]:
        if v["name"] == name:
            return bytes.fromhex(v["signature"])
    raise KeyError(name)


def check_signature_validity(public_key: bytes, signature: bytes, message: bytes) -> bool:
    """Verifies a tm2 signature: ECDSA over SHA-256, 64-byte R || S, low S."""
    s = int.from_bytes(signature[32:], "big")
    if s > SECP256k1.order // 2:
        return False
    pk = VerifyingKey.from_string(public_key, curve=SECP256k1, hashfunc=sha256)
    return pk.verify(signature=signature, data=message, hashfunc=sha256, sigdecode=sigdecode_string)
