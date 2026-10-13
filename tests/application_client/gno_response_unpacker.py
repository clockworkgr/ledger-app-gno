from struct import unpack

PUBKEY_LEN = 33
ADDRESS_LEN = 40
SIGNATURE_LEN = 64


def unpack_get_app_name_response(response: bytes) -> str:
    return response.decode("ascii")


def unpack_get_version_response(response: bytes) -> tuple[int, int, int]:
    assert len(response) == 3
    major, minor, patch = unpack("BBB", response)
    return (major, minor, patch)


def unpack_get_public_key_response(response: bytes) -> tuple[bytes, str]:
    """Returns (compressed public key, g1 address)."""
    pubkey_len = response[0]
    assert pubkey_len == PUBKEY_LEN
    pubkey = response[1 : 1 + pubkey_len]
    rest = response[1 + pubkey_len :]
    address_len = rest[0]
    assert address_len == ADDRESS_LEN
    address = rest[1 : 1 + address_len]
    assert len(rest) == 1 + address_len
    return pubkey, address.decode("ascii")


def unpack_sign_tx_response(response: bytes) -> bytes:
    """Returns the 64-byte R || S signature."""
    assert len(response) == SIGNATURE_LEN
    return response
