from ragger.navigator import NavIns, NavInsID

# Position of the first settings switch on touch devices.
FIRST_SWITCH = (200, 113)


def toggle_package_transactions(device, backend, navigator) -> None:
    """Flips the "Packages" switch and returns to the home screen.

    Waits for the home screen first, since a preceding flow may still be
    showing its status page.
    """
    backend.wait_for_home_screen()
    instructions: list[NavIns | NavInsID]
    if device.is_nano:
        instructions = [
            NavInsID.RIGHT_CLICK,  # Show address
            NavInsID.RIGHT_CLICK,  # App settings
            NavInsID.BOTH_CLICK,
            NavInsID.BOTH_CLICK,
            NavInsID.RIGHT_CLICK,
            NavInsID.BOTH_CLICK,
            NavInsID.LEFT_CLICK,
            NavInsID.LEFT_CLICK,
        ]
    else:
        instructions = [
            NavInsID.USE_CASE_HOME_SETTINGS,
            NavIns(NavInsID.TOUCH, FIRST_SWITCH),
            NavInsID.USE_CASE_SUB_SETTINGS_EXIT,
        ]
    navigator.navigate(
        instructions,
        screen_change_before_first_instruction=False,
        screen_change_after_last_instruction=False,
    )


# Touch positions of the home screen's "Show address" button.
SHOW_ADDRESS_BUTTON = {"stax": (200, 520), "flex": (240, 430), "apex_p": (150, 295)}
# Touch positions of the keypad's back arrow, and of its cell centres: three
# columns, four rows (1-3, 4-6, 7-9, then backspace, 0, validate).
KEYPAD_BACK = {"stax": (44, 44), "flex": (48, 48), "apex_p": (25, 30)}
KEYPAD_COLUMNS = {"stax": (66, 200, 333), "flex": (78, 238, 398), "apex_p": (50, 150, 250)}
KEYPAD_ROWS = {
    "stax": (308, 412, 516, 620),
    "flex": (290, 378, 465, 553),
    "apex_p": (191, 250, 310, 370),
}

# Nano keypad: a row of ⌫ 0-9 (and ✓ once a digit is entered), walked with
# the buttons. The cursor starts on 5, jumps to ✓ when it first appears, and
# goes back to 5 after every later digit.
NANO_KEYPAD_START = 6
NANO_VALIDATE = 11


def _nano_moves(start: int, target: int) -> list[NavIns | NavInsID]:
    step = NavInsID.RIGHT_CLICK if target > start else NavInsID.LEFT_CLICK
    return [step] * abs(target - start)


def _keypad_cell(device: str, column: int, row: int) -> NavIns:
    return NavIns(NavInsID.TOUCH, (KEYPAD_COLUMNS[device][column], KEYPAD_ROWS[device][row]))


def open_show_address(device) -> list[NavIns | NavInsID]:
    """From the home screen to the address index keypad."""
    if device.is_nano:
        return [NavInsID.RIGHT_CLICK, NavInsID.BOTH_CLICK]
    return [NavIns(NavInsID.TOUCH, SHOW_ADDRESS_BUTTON[device.name])]


def type_index(device, digits: str, typed: int = 0, validate: bool = True) -> list[NavIns | NavInsID]:
    """Types `digits` on the keypad, after `typed` digits already entered,
    then validates unless told not to."""
    instructions: list[NavIns | NavInsID] = []
    if device.is_nano:
        cursor = NANO_VALIDATE if typed == 1 else NANO_KEYPAD_START
        for d in digits:
            instructions += _nano_moves(cursor, int(d) + 1)
            instructions.append(NavInsID.BOTH_CLICK)
            typed += 1
            cursor = NANO_VALIDATE if typed == 1 else NANO_KEYPAD_START
        if validate:
            instructions += _nano_moves(cursor, NANO_VALIDATE)
            instructions.append(NavInsID.BOTH_CLICK)
        return instructions
    for d in digits:
        n = int(d)
        cell = (1, 3) if n == 0 else ((n - 1) % 3, (n - 1) // 3)
        instructions.append(_keypad_cell(device.name, *cell))
    if validate:
        instructions.append(_keypad_cell(device.name, 2, 3))
    return instructions


def leave_keypad(device) -> list[NavIns | NavInsID]:
    """Leaves the empty keypad, back to the home screen."""
    if device.is_nano:
        return [*_nano_moves(NANO_KEYPAD_START, 0), NavInsID.BOTH_CLICK]
    return [NavIns(NavInsID.TOUCH, KEYPAD_BACK[device.name])]
