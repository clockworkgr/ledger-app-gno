import pytest
from application_client.gno_command_sender import (
    CLA,
    P1,
    P2,
    Errors,
    GnoCommandSender,
    InsType,
)
from application_client.gno_response_unpacker import unpack_sign_tx_response
from application_client.navigation import toggle_package_transactions
from application_client.utils import (
    check_signature_validity,
    load_vectors,
    reference_signature,
    sign_bytes,
)
from ragger.error import ExceptionRAPDU

VECTORS = load_vectors()
PATH = "m/" + VECTORS["path"]
PUBKEY = bytes.fromhex(VECTORS["pubkey"])

CLEAR_SIGNED = [
    "send",
    "send_zero_fee_memo",
    "memo_escapes",
    "call",
    "call_send_no_args",
    "two_msgs",
    "enable_pkg",
    "reject_pkg",
    "create_session",
    "revoke_session",
    "revoke_all_sessions",
]
PACKAGE_TXS = ["addpkg", "run", "addpkg_highlights"]


def assert_signed(name: str, signature: bytes) -> None:
    payload = sign_bytes(VECTORS, name)
    assert check_signature_validity(PUBKEY, signature, payload)
    # RFC 6979 makes the signature deterministic, so it must equal gno's own.
    assert signature == reference_signature(VECTORS, name)


@pytest.mark.parametrize("name", CLEAR_SIGNED)
def test_sign_clear(backend, scenario_navigator, name):
    client = GnoCommandSender(backend)
    with client.sign_tx(PATH, sign_bytes(VECTORS, name)):
        scenario_navigator.review_approve(test_name=f"test_sign_clear_{name}")
    assert_signed(name, unpack_sign_tx_response(client.get_async_response().data))


def test_sign_rejected(backend, scenario_navigator):
    client = GnoCommandSender(backend)
    with pytest.raises(ExceptionRAPDU) as e:
        with client.sign_tx(PATH, sign_bytes(VECTORS, "send")):
            scenario_navigator.review_reject()
    assert e.value.status == Errors.SW_DENY
    assert len(e.value.data) == 0


@pytest.mark.parametrize("name", PACKAGE_TXS)
def test_sign_package_disabled_by_default(backend, name):
    client = GnoCommandSender(backend)
    with pytest.raises(ExceptionRAPDU) as e:
        client.sign_tx_no_ui(PATH, sign_bytes(VECTORS, name))
    assert e.value.status == Errors.SW_PACKAGE_TX_DISABLED


@pytest.mark.parametrize("name", PACKAGE_TXS)
def test_sign_package_with_setting(backend, device, navigator, scenario_navigator, name):
    toggle_package_transactions(device, backend, navigator)
    client = GnoCommandSender(backend)
    with client.sign_tx(PATH, sign_bytes(VECTORS, name)):
        scenario_navigator.review_approve_with_warning(test_name=f"test_sign_package_{name}")
    assert_signed(name, unpack_sign_tx_response(client.get_async_response().data))
    toggle_package_transactions(device, backend, navigator)


def test_sign_package_at_review_limits(backend, device, navigator, scenario_navigator):
    """A package with more imports, addresses and files than the review lists,
    plus a long memo, still fits in device memory and signs."""
    name = "addpkg_limits"
    toggle_package_transactions(device, backend, navigator)
    client = GnoCommandSender(backend)
    with client.sign_tx(PATH, sign_bytes(VECTORS, name)):
        scenario_navigator.review_approve_with_warning(do_comparison=False)
    assert_signed(name, unpack_sign_tx_response(client.get_async_response().data))
    toggle_package_transactions(device, backend, navigator)


def near_limit_payload(import_padding: int) -> bytes:
    """The limits vector with the longest memo and longer import paths."""
    long_dir = b"very/long/import/path/for/limits"
    return (
        sign_bytes(VECTORS, "addpkg_limits")
        .replace(long_dir, long_dir + b"/x" * import_padding)
        .replace(b'"memo":"' + b"m" * 256, b'"memo":"' + b"m" * 512)
    )


def test_sign_review_near_memory_limit(backend, device, navigator, scenario_navigator):
    """Within a few bytes of MAX_REVIEW_BYTES and one field of MAX_REVIEW_FIELDS.
    Nano X has the least heap to show it."""
    payload = near_limit_payload(5)
    toggle_package_transactions(device, backend, navigator)
    client = GnoCommandSender(backend)
    with client.sign_tx(PATH, payload):
        scenario_navigator.review_approve_with_warning(do_comparison=False)
    signature = unpack_sign_tx_response(client.get_async_response().data)
    assert check_signature_validity(PUBKEY, signature, payload)
    toggle_package_transactions(device, backend, navigator)


def test_sign_review_over_limit_is_refused(backend):
    """Past MAX_REVIEW_BYTES the device refuses rather than truncating."""
    client = GnoCommandSender(backend)
    with pytest.raises(ExceptionRAPDU) as e:
        client.sign_tx_no_ui(PATH, near_limit_payload(30))
    assert e.value.status == Errors.SW_TX_TOO_LARGE


def test_sign_package_rejected_at_warning(backend, device, navigator, scenario_navigator):
    toggle_package_transactions(device, backend, navigator)
    client = GnoCommandSender(backend)
    with pytest.raises(ExceptionRAPDU) as e:
        with client.sign_tx(PATH, sign_bytes(VECTORS, "addpkg")):
            scenario_navigator.review_reject_with_warning()
    assert e.value.status == Errors.SW_DENY
    toggle_package_transactions(device, backend, navigator)


def test_sign_wrong_signer(backend):
    """Account 1 must not sign a message whose signer is account 0."""
    client = GnoCommandSender(backend)
    with pytest.raises(ExceptionRAPDU) as e:
        client.sign_tx_no_ui("m/44'/118'/1'/0/0", sign_bytes(VECTORS, "send"))
    assert e.value.status == Errors.SW_TX_WRONG_SIGNER


@pytest.mark.parametrize(
    "mutation",
    [
        (b'"chain_id":', b' "chain_id":'),  # whitespace
        (b"/bank.MsgSend", b"/bank.MsgMultiSend"),  # unregistered message
        (b'"memo":"",', b'"memo":"","extra":"",'),  # unknown key
        (b'"sequence":"3"', b'"sequence":"03"'),  # non-canonical number
    ],
)
def test_sign_malformed(backend, mutation):
    client = GnoCommandSender(backend)
    payload = sign_bytes(VECTORS, "send").replace(*mutation, 1)
    with pytest.raises(ExceptionRAPDU) as e:
        client.sign_tx_no_ui(PATH, payload)
    assert e.value.status == Errors.SW_TX_PARSING_FAIL


def test_sign_truncated(backend):
    client = GnoCommandSender(backend)
    with pytest.raises(ExceptionRAPDU) as e:
        client.sign_tx_no_ui(PATH, sign_bytes(VECTORS, "send")[:-1])
    assert e.value.status == Errors.SW_TX_PARSING_FAIL


def test_sign_value_too_long(backend):
    client = GnoCommandSender(backend)
    payload = sign_bytes(VECTORS, "send_zero_fee_memo").replace(b'"memo":"thanks"', b'"memo":"' + b"m" * 513 + b'"', 1)
    with pytest.raises(ExceptionRAPDU) as e:
        client.sign_tx_no_ui(PATH, payload)
    assert e.value.status == Errors.SW_TX_TOO_LARGE


def test_sign_without_session(backend):
    with pytest.raises(ExceptionRAPDU) as e:
        backend.exchange(cla=CLA, ins=InsType.SIGN_TX, p1=P1.SIGN_TX_NEXT, p2=P2.SIGN_TX_LAST, data=b"{}")
    assert e.value.status == Errors.SW_TX_NO_SESSION


def test_sign_error_closes_session(backend):
    """After a rejected chunk, continuing the same payload must fail."""
    client = GnoCommandSender(backend)
    client.sign_tx_start(PATH)
    with pytest.raises(ExceptionRAPDU):
        backend.exchange(cla=CLA, ins=InsType.SIGN_TX, p1=P1.SIGN_TX_NEXT, p2=P2.SIGN_TX_MORE, data=b"[")
    with pytest.raises(ExceptionRAPDU) as e:
        backend.exchange(cla=CLA, ins=InsType.SIGN_TX, p1=P1.SIGN_TX_NEXT, p2=P2.SIGN_TX_LAST, data=b"{}")
    assert e.value.status == Errors.SW_TX_NO_SESSION


def test_sign_path_chunk_must_announce_more(backend):
    with pytest.raises(ExceptionRAPDU) as e:
        backend.exchange(cla=CLA, ins=InsType.SIGN_TX, p1=P1.SIGN_TX_FIRST, p2=P2.SIGN_TX_LAST)
    assert e.value.status == Errors.SW_WRONG_P1P2


def test_sign_large_package_streams(backend, device, navigator, scenario_navigator):
    """A payload far larger than RAM is hashed and parsed as it streams."""
    name = "run"
    payload = sign_bytes(VECTORS, name).replace(b'"body":"package main', b'"body":"// ' + b"x" * 60_000 + b"\\npackage main", 1)
    toggle_package_transactions(device, backend, navigator)
    client = GnoCommandSender(backend)
    with client.sign_tx(PATH, payload):
        scenario_navigator.review_approve_with_warning(do_comparison=False)
    signature = unpack_sign_tx_response(client.get_async_response().data)
    assert check_signature_validity(PUBKEY, signature, payload)
    toggle_package_transactions(device, backend, navigator)


# Sessions allowed vm/run, or "*" which includes it.
CODE_RUNNING_SESSIONS = ["create_session_run", "create_session_minimal"]


@pytest.mark.parametrize("name", CODE_RUNNING_SESSIONS)
def test_sign_session_running_code_disabled_by_default(backend, name):
    """A session that may run scripts as the account needs the Packages
    setting, like m_run itself."""
    client = GnoCommandSender(backend)
    with pytest.raises(ExceptionRAPDU) as e:
        client.sign_tx_no_ui(PATH, sign_bytes(VECTORS, name))
    assert e.value.status == Errors.SW_PACKAGE_TX_DISABLED


@pytest.mark.parametrize("name", CODE_RUNNING_SESSIONS)
def test_sign_session_running_code_with_setting(backend, device, navigator, scenario_navigator, name):
    toggle_package_transactions(device, backend, navigator)
    client = GnoCommandSender(backend)
    with client.sign_tx(PATH, sign_bytes(VECTORS, name)):
        scenario_navigator.review_approve(test_name=f"test_sign_clear_{name}")
    assert_signed(name, unpack_sign_tx_response(client.get_async_response().data))
    toggle_package_transactions(device, backend, navigator)


@pytest.mark.parametrize("max_deposit", [b"1foo", b"0ugnot", b"1ugnot,1zzz"])
def test_sign_max_deposit_must_be_ugnot(backend, max_deposit):
    """gno only reads ugnot from max_deposit; any other form would show a cap
    that the chain does not enforce."""
    client = GnoCommandSender(backend)
    payload = sign_bytes(VECTORS, "call").replace(b'"max_deposit":""', b'"max_deposit":"' + max_deposit + b'"', 1)
    with pytest.raises(ExceptionRAPDU) as e:
        client.sign_tx_no_ui(PATH, payload)
    assert e.value.status == Errors.SW_TX_PARSING_FAIL


def test_sign_escaped_file_names_are_refused(backend):
    """File names that escape to four times their size hit the review budget
    instead of exhausting the heap."""
    doc = sign_bytes(VECTORS, "addpkg")
    start = doc.index(b'"files":[') + len(b'"files":[')
    end = doc.index(b'],"name":"hello"')
    files = [b'{"body":"package hello\\n","name":"' + b"\\u0000" * 200 + f"f{i:02}.gno".encode() + b'"}' for i in range(16)]
    payload = doc[:start] + b",".join(files) + doc[end:]
    client = GnoCommandSender(backend)
    with pytest.raises(ExceptionRAPDU) as e:
        client.sign_tx_no_ui(PATH, payload)
    assert e.value.status == Errors.SW_TX_TOO_LARGE


def open_session_with_prefix(backend) -> bytes:
    """Opens a session and sends the first chunk of a send; returns the rest."""
    client = GnoCommandSender(backend)
    payload = sign_bytes(VECTORS, "send")
    client.sign_tx_start(PATH)
    backend.exchange(cla=CLA, ins=InsType.SIGN_TX, p1=P1.SIGN_TX_NEXT, p2=P2.SIGN_TX_MORE, data=payload[:100])
    return payload[100:]


def assert_session_closed(backend, rest: bytes) -> None:
    with pytest.raises(ExceptionRAPDU) as e:
        backend.exchange(cla=CLA, ins=InsType.SIGN_TX, p1=P1.SIGN_TX_NEXT, p2=P2.SIGN_TX_LAST, data=rest)
    assert e.value.status == Errors.SW_TX_NO_SESSION


def test_sign_malformed_header_closes_session(backend):
    rest = open_session_with_prefix(backend)
    with pytest.raises(ExceptionRAPDU) as e:
        backend.exchange(cla=CLA, ins=InsType.SIGN_TX, p1=0x02, p2=P2.SIGN_TX_MORE, data=rest[:10])
    assert e.value.status == Errors.SW_WRONG_P1P2
    assert_session_closed(backend, rest)


def test_sign_wrong_cla_closes_session(backend):
    rest = open_session_with_prefix(backend)
    with pytest.raises(ExceptionRAPDU) as e:
        backend.exchange(cla=CLA + 1, ins=InsType.SIGN_TX, p1=P1.SIGN_TX_NEXT, p2=P2.SIGN_TX_MORE, data=rest[:10])
    assert e.value.status == Errors.SW_CLA_NOT_SUPPORTED
    assert_session_closed(backend, rest)


def test_sign_other_command_closes_session(backend):
    rest = open_session_with_prefix(backend)
    GnoCommandSender(backend).get_version()
    assert_session_closed(backend, rest)
