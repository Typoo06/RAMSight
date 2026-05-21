# Volatility command builder tests.

from pathlib import Path

from app.volatility.commands import build_volatility_command
from app.volatility.registry import get_plugin_definition


class DummySettings:
    volatility_path = "vol"
    volatility_symbol_path = "/opt/volatility/symbols"
    volatility_yara_rules_path = None


def test_build_command_uses_json_renderer_and_symbol_dirs() -> None:
    command = build_volatility_command(
        DummySettings(),
        get_plugin_definition("windows.pslist"),
        Path("/workspace/evidence.raw"),
        Path("/workspace/raw"),
    )

    assert command == [
        "vol",
        "-f",
        "/workspace/evidence.raw",
        "-r",
        "json",
        "-o",
        "/workspace/raw",
        "-s",
        "/opt/volatility/symbols",
        "windows.pslist.PsList",
    ]


def test_build_yarascan_command_adds_yara_file_when_configured() -> None:
    class YaraSettings(DummySettings):
        volatility_yara_rules_path = "/rules/memory.yar"

    command = build_volatility_command(
        YaraSettings(),
        get_plugin_definition("yarascan"),
        Path("/workspace/evidence.raw"),
        Path("/workspace/raw"),
    )

    assert command[-3:] == ["yarascan.YaraScan", "--yara-file", "/rules/memory.yar"]

