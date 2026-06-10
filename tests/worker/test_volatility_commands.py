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
        "-q",
        "-r",
        "json",
        "-s",
        "/opt/volatility/symbols",
        "windows.pslist.PsList",
    ]
    assert command[-1] == "windows.pslist.PsList"


def test_build_command_omits_symbol_dirs_when_not_configured() -> None:
    class NoSymbolSettings(DummySettings):
        volatility_symbol_path = ""

    command = build_volatility_command(
        NoSymbolSettings(),
        get_plugin_definition("windows.malfind"),
        Path("/workspace/evidence.raw"),
        Path("/workspace/raw"),
    )

    assert "-s" not in command
    assert command[-1] == "windows.malware.malfind.Malfind"


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


def test_build_yara_command_omits_yara_file_when_not_configured() -> None:
    command = build_volatility_command(
        DummySettings(),
        get_plugin_definition("windows.vadyarascan"),
        Path("/workspace/evidence.raw"),
        Path("/workspace/raw"),
    )

    assert "--yara-file" not in command
    assert command[-1] == "windows.vadyarascan.VadYaraScan"


def test_build_vadyarascan_command_places_plugin_args_after_plugin_name() -> None:
    class YaraSettings(DummySettings):
        volatility_yara_rules_path = None

    command = build_volatility_command(
        YaraSettings(),
        get_plugin_definition("windows.vadyarascan"),
        Path("/workspace/evidence.raw"),
        Path("/workspace/raw"),
        yara_rules_path="/rules/yara/compiled/elastic_yara.yar",
    )

    assert command[-3:] == [
        "windows.vadyarascan.VadYaraScan",
        "--yara-file",
        "/rules/yara/compiled/elastic_yara.yar",
    ]
