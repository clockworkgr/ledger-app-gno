import pytest
from application_client.gno_command_sender import Errors, GnoCommandSender
from application_client.gno_response_unpacker import unpack_get_public_key_response
from application_client.utils import load_vectors
from ragger.error import ExceptionRAPDU

VECTORS = load_vectors()
DEFAULT_PATH = "m/" + VECTORS["path"]


def test_get_public_key_matches_gno(backend):
    """The key and address gnokey derives from the Speculos seed."""
    client = GnoCommandSender(backend)
    pubkey, address = unpack_get_public_key_response(client.get_public_key(DEFAULT_PATH).data)
    assert pubkey.hex() == VECTORS["pubkey"]
    assert address == VECTORS["address"]


def test_get_public_key_other_accounts(backend):
    client = GnoCommandSender(backend)
    seen = set()
    for path in ["m/44'/118'/1'/0/0", "m/44'/118'/0'/0/1", "m/44'/118'/2147483647'/0/2147483647"]:
        pubkey, address = unpack_get_public_key_response(client.get_public_key(path).data)
        assert pubkey[0] in (0x02, 0x03)
        assert address.startswith("g1")
        seen.add(address)
    assert len(seen) == 3


@pytest.mark.parametrize(
    "path",
    [
        "m/44'/1'/0'/0/0",  # another coin type
        "m/44'/118'/0/0/0",  # unhardened account
        "m/44'/118'/0'/1/0",  # change branch
        "m/44'/118'/0'/0/0'",  # hardened index
        "m/45'/118'/0'/0/0",  # another purpose
    ],
)
def test_get_public_key_rejects_foreign_paths(backend, path):
    client = GnoCommandSender(backend)
    with pytest.raises(ExceptionRAPDU) as e:
        client.get_public_key(path)
    assert e.value.status == Errors.SW_INVALID_PATH


@pytest.mark.parametrize("path", ["m/44'/118'/0'/0", "m/44'/118'/0'/0/0/0"])
def test_get_public_key_rejects_wrong_depth(backend, path):
    client = GnoCommandSender(backend)
    with pytest.raises(ExceptionRAPDU) as e:
        client.get_public_key(path)
    assert e.value.status == Errors.SW_WRONG_APDU_LENGTH


def test_get_public_key_confirm_accepted(backend, scenario_navigator):
    client = GnoCommandSender(backend)
    with client.get_public_key_with_confirmation(DEFAULT_PATH):
        scenario_navigator.address_review_approve()
    pubkey, address = unpack_get_public_key_response(client.get_async_response().data)
    assert pubkey.hex() == VECTORS["pubkey"]
    assert address == VECTORS["address"]


def test_get_public_key_confirm_refused(backend, scenario_navigator):
    client = GnoCommandSender(backend)
    with pytest.raises(ExceptionRAPDU) as e:
        with client.get_public_key_with_confirmation(DEFAULT_PATH):
            scenario_navigator.address_review_reject()
    assert e.value.status == Errors.SW_DENY
    assert len(e.value.data) == 0
