"""The home screen's "Show address": the user types an account and an address
index, and the device shows the address at m/44'/118'/<account>'/0/<index>,
with no host involved."""

import pytest
from application_client.gno_command_sender import GnoCommandSender
from application_client.gno_response_unpacker import unpack_get_public_key_response
from application_client.navigation import leave_keypad, open_show_address, type_digits
from ragger.navigator import NavInsID

MAX_DIGITS = 7


def address_at(backend, account: int, index: int) -> str:
    """The address GET_PUBLIC_KEY returns for the same path."""
    client = GnoCommandSender(backend)
    _, address = unpack_get_public_key_response(client.get_public_key(f"m/44'/118'/{account}'/0/{index}").data)
    return address


def enter(device, backend, navigator, account: str, index: str, path=None, test_name=None) -> None:
    """Types the account, then the index, from the home screen. Returns as the
    index keypad validates, leaving the next screen for the caller to wait for."""
    backend.wait_for_home_screen()
    instructions = open_show_address(device) + type_digits(device, account) + type_digits(device, index)
    if test_name is None:
        navigator.navigate(
            instructions,
            screen_change_before_first_instruction=False,
            screen_change_after_last_instruction=False,
        )
    else:
        navigator.navigate_and_compare(
            path,
            test_name,
            instructions,
            screen_change_before_first_instruction=False,
            screen_change_after_last_instruction=False,
        )


def review_text(device, backend, navigator) -> str:
    """Pages through the address review up to its confirmation, returning
    everything shown on the way as one string."""
    backend.wait_for_text_on_screen("Verify Gno address")
    seen = []
    for _ in range(10):
        texts = [e["text"] for e in backend.get_current_screen_content()["events"]]
        seen += texts
        if "Confirm" in texts:
            return "".join(seen)
        navigator.navigate(
            [NavInsID.RIGHT_CLICK if device.is_nano else NavInsID.SWIPE_CENTER_TO_LEFT],
            screen_change_before_first_instruction=False,
        )
    raise AssertionError(f"no confirmation page, saw {seen}")


def test_show_address_accepted(device, backend, navigator, scenario_navigator, default_screenshot_path, test_name):
    enter(device, backend, navigator, "3", "7", default_screenshot_path, f"{test_name}/keypad")
    scenario_navigator.address_review_approve()
    backend.wait_for_home_screen()


def test_show_address_rejected(device, backend, navigator, scenario_navigator):
    enter(device, backend, navigator, "3", "7")
    scenario_navigator.address_review_reject()
    backend.wait_for_home_screen()


@pytest.mark.parametrize(
    "account_digits, index_digits, account, index",
    [
        ("0", "0", 0, 0),
        ("0", "1", 0, 1),
        ("1", "0", 1, 0),
        ("003", "007", 3, 7),
        ("9" * MAX_DIGITS, "9" * MAX_DIGITS, int("9" * MAX_DIGITS), int("9" * MAX_DIGITS)),
    ],
)
def test_show_address_matches_get_public_key(device, backend, navigator, account_digits, index_digits, account, index):
    expected = address_at(backend, account, index)
    enter(device, backend, navigator, account_digits, index_digits)
    shown = review_text(device, backend, navigator)
    assert expected in shown
    assert f"m/44'/118'/{account}'/0/{index}" in shown


def type_full_keypad(device, navigator, digits: str) -> None:
    """Fills a keypad with `digits`, tries an extra digit, then validates."""
    navigator.navigate(
        type_digits(device, digits, validate=False),
        screen_change_before_first_instruction=False,
    )
    # The keypad is full. Nano redraws its cursor; touch screens don't change.
    navigator.navigate(
        type_digits(device, "8", typed=MAX_DIGITS, validate=False),
        screen_change_before_first_instruction=False,
        screen_change_after_last_instruction=device.is_nano,
    )
    navigator.navigate(
        type_digits(device, "", typed=MAX_DIGITS + 1),
        screen_change_before_first_instruction=False,
        screen_change_after_last_instruction=False,
    )


def test_show_address_ignores_extra_digits(device, backend, navigator):
    expected = address_at(backend, 1234567, 7654321)
    backend.wait_for_home_screen()
    navigator.navigate(open_show_address(device), screen_change_before_first_instruction=False)
    type_full_keypad(device, navigator, "1234567")
    type_full_keypad(device, navigator, "7654321")
    shown = review_text(device, backend, navigator)
    assert expected in shown
    assert "m/44'/118'/1234567'/0/7654321" in shown


def test_show_address_back_to_home(device, backend, navigator):
    backend.wait_for_home_screen()
    navigator.navigate(
        open_show_address(device) + leave_keypad(device),
        screen_change_before_first_instruction=False,
    )
    backend.wait_for_home_screen()
    # The app still answers commands afterwards.
    assert address_at(backend, 0, 0).startswith("g1")


def test_show_address_back_to_account(device, backend, navigator):
    """Leaving the index keypad returns to the account keypad, where a new
    account can be typed."""
    expected = address_at(backend, 2, 4)
    backend.wait_for_home_screen()
    navigator.navigate(
        open_show_address(device) + type_digits(device, "5") + leave_keypad(device),
        screen_change_before_first_instruction=False,
    )
    navigator.navigate(
        type_digits(device, "2") + type_digits(device, "4"),
        screen_change_before_first_instruction=False,
        screen_change_after_last_instruction=False,
    )
    shown = review_text(device, backend, navigator)
    assert expected in shown
    assert "m/44'/118'/2'/0/4" in shown
