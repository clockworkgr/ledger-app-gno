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
            NavInsID.RIGHT_CLICK,
            NavInsID.BOTH_CLICK,
            NavInsID.BOTH_CLICK,
            NavInsID.RIGHT_CLICK,
            NavInsID.BOTH_CLICK,
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
