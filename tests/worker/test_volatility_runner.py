# Volatility runner tests.

import json
import subprocess
from types import SimpleNamespace

from app.tasks.status import STATUS_COMPLETED, STATUS_FAILED, STATUS_SKIPPED
from app.volatility.registry import get_plugin_definition
from app.volatility.runner import run_volatility_plugin


class DummySettings:
    volatility_path = "vol"
    volatility_symbol_path = "/symbols"
    volatility_plugin_timeout_seconds = 5
    volatility_yara_rules_path = None


def test_runner_writes_raw_wrapper_for_success(tmp_path) -> None:
    def fake_run(command, capture_output, text, timeout, check):
        return SimpleNamespace(returncode=0, stdout='{"rows": []}', stderr="")

    result = run_volatility_plugin(
        get_plugin_definition("windows.pslist"),
        tmp_path / "evidence.raw",
        tmp_path / "raw",
        settings=DummySettings(),
        process_runner=fake_run,
    )

    payload = json.loads(result.raw_output_path.read_text(encoding="utf-8"))
    assert result.status == STATUS_COMPLETED
    assert result.plugin_name == "windows.pslist"
    assert result.source_plugin == "windows.pslist"
    assert result.raw_output_path.name == "windows_pslist.json"
    assert payload["plugin_name"] == "windows.pslist"
    assert payload["source_plugin"] == "windows.pslist"
    assert payload["stdout"] == '{"rows": []}'
    assert payload["command"][-1] == "windows.pslist.PsList"


def test_runner_marks_nonzero_plugin_failed(tmp_path) -> None:
    def fake_run(command, capture_output, text, timeout, check):
        return SimpleNamespace(returncode=1, stdout="", stderr="plugin failed")

    result = run_volatility_plugin(
        get_plugin_definition("windows.netscan"),
        tmp_path / "evidence.raw",
        tmp_path / "raw",
        settings=DummySettings(),
        process_runner=fake_run,
    )

    assert result.status == STATUS_FAILED
    assert result.error_message == "plugin failed"


def test_runner_skips_yarascan_without_rule_configuration(tmp_path) -> None:
    result = run_volatility_plugin(
        get_plugin_definition("yarascan"),
        tmp_path / "evidence.raw",
        tmp_path / "raw",
        settings=DummySettings(),
    )

    payload = json.loads(result.raw_output_path.read_text(encoding="utf-8"))
    assert result.status == STATUS_SKIPPED
    assert "YARA rule configuration" in result.error_message
    assert payload["command"] == []
    assert result.extra_data["requires_yara_rules"] is True
    assert result.extra_data["yara_rules_configured"] is False
    assert payload["extra_data"]["skip_reason"] == "YARA rule configuration is required for this plugin"


def test_runner_uses_discovered_yara_rules_for_vadyarascan(tmp_path) -> None:
    yara_dir = tmp_path / "rules" / "yara"
    yara_dir.mkdir(parents=True)
    rule_path = yara_dir / "demo.yar"
    rule_path.write_text("rule Demo { condition: false }", encoding="utf-8")

    class YaraSettings(DummySettings):
        rules_dir = str(tmp_path / "rules")

    def fake_run(command, capture_output, text, timeout, check):
        assert command[-3:] == ["windows.vadyarascan.VadYaraScan", "--yara-file", str(rule_path)]
        return SimpleNamespace(returncode=0, stdout="[]", stderr="")

    result = run_volatility_plugin(
        get_plugin_definition("windows.vadyarascan"),
        tmp_path / "evidence.raw",
        tmp_path / "raw",
        settings=YaraSettings(),
        process_runner=fake_run,
    )

    assert result.status == STATUS_COMPLETED
    assert result.extra_data["yara_rules_configured"] is True
    assert result.extra_data["yara_rules_source"] == "demo.yar"


def test_runner_marks_timeout_failed(tmp_path) -> None:
    def fake_run(command, capture_output, text, timeout, check):
        raise subprocess.TimeoutExpired(command, timeout, output="partial", stderr="slow")

    result = run_volatility_plugin(
        get_plugin_definition("windows.psscan"),
        tmp_path / "evidence.raw",
        tmp_path / "raw",
        settings=DummySettings(),
        process_runner=fake_run,
    )

    assert result.status == STATUS_FAILED
    assert result.timed_out is True
    assert "timed out" in result.error_message
