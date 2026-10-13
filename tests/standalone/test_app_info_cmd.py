from pathlib import Path

import tomli
from application_client.gno_command_sender import GnoCommandSender
from application_client.gno_response_unpacker import (
    unpack_get_app_name_response,
    unpack_get_version_response,
)


def test_app_name(backend):
    client = GnoCommandSender(backend)
    assert unpack_get_app_name_response(client.get_app_name().data) == "Gno"


def test_version(backend):
    with open(Path(__file__).parent.parent.parent / "Cargo.toml", "rb") as f:
        data = tomli.load(f)
    version = tuple(map(int, data["package"]["version"].split(".")))
    client = GnoCommandSender(backend)
    assert unpack_get_version_response(client.get_version().data) == version
