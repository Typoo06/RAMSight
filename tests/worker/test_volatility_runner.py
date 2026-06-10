# Volatility runner tests.

import json
import subprocess

from app.tasks.status import STATUS_COMPLETED, STATUS_FAILED, STATUS_SKIPPED
from app.volatility.registry import get_plugin_definition
from app.volatility.runner import MAX_STDERR_CAPTURE_BYTES, plugin_timeout_seconds, run_volatility_plugin


class DummySettings:
    volatility_path = "vol"
    volatility_symbol_path = "/symbols"
    volatility_plugin_timeout_seconds = 5
    volatility_yara_timeout_seconds = 15
    volatility_yara_rules_path = None


class FakeProcess:

    def __init__(self, return_code: int = 0, timeout: bool = False) -> None:
        self.pid = 12345
        self.return_code = return_code
        self.timeout = timeout
        self.killed = False

    def wait(self, timeout=None):
        if self.timeout:
            raise subprocess.TimeoutExpired("vol", timeout)
        return self.return_code

    def kill(self) -> None:
        self.killed = True


def test_timeout_selection_uses_default_for_normal_plugins() -> None:
    assert plugin_timeout_seconds(get_plugin_definition("windows.pslist"), DummySettings()) == 5


def test_timeout_selection_uses_yara_timeout_for_vadyarascan() -> None:
    assert plugin_timeout_seconds(get_plugin_definition("windows.vadyarascan"), DummySettings()) == 15


def test_runner_streams_stdout_to_raw_output_file_for_success(tmp_path) -> None:
    captured = {}

    def fake_popen(command, stdout, stderr, text, start_new_session):
        captured["command"] = command
        captured["text"] = text
        captured["start_new_session"] = start_new_session
        stdout.write(b'{"rows": []}')
        return FakeProcess(return_code=0)

    result = run_volatility_plugin(
        get_plugin_definition("windows.pslist"),
        tmp_path / "evidence.raw",
        tmp_path / "raw",
        settings=DummySettings(),
        process_runner=fake_popen,
    )

    payload = json.loads(result.raw_output_path.read_text(encoding="utf-8"))
    assert result.status == STATUS_COMPLETED
    assert result.plugin_name == "windows.pslist"
    assert result.source_plugin == "windows.pslist"
    assert result.raw_output_path.name == "windows_pslist.json"
    assert result.stdout == ""
    assert payload == {"rows": []}
    assert captured["command"][-1] == "windows.pslist.PsList"
    assert captured["text"] is False
    assert captured["start_new_session"] is True


def test_runner_marks_nonzero_plugin_failed_with_bounded_stderr(tmp_path) -> None:
    long_stderr = b"x" * (MAX_STDERR_CAPTURE_BYTES + 1024)

    def fake_popen(command, stdout, stderr, text, start_new_session):
        stdout.write(b"")
        stderr.write(long_stderr)
        return FakeProcess(return_code=1)

    result = run_volatility_plugin(
        get_plugin_definition("windows.netscan"),
        tmp_path / "evidence.raw",
        tmp_path / "raw",
        settings=DummySettings(),
        process_runner=fake_popen,
    )

    assert result.status == STATUS_FAILED
    assert "stderr truncated" in result.stderr
    assert len(result.stderr.encode("utf-8")) < MAX_STDERR_CAPTURE_BYTES + 2048
    assert result.error_message.startswith("x")
    assert len(result.error_message) <= 500


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
    yara_dir = tmp_path / "rules" / "yara" / "compiled"
    yara_dir.mkdir(parents=True)
    rule_path = yara_dir / "elastic_yara.yar"
    rule_path.write_text("rule ElasticTest { condition: false }", encoding="utf-8")

    class YaraSettings(DummySettings):
        rules_dir = str(tmp_path / "rules")

    def fake_popen(command, stdout, stderr, text, start_new_session):
        assert command[-3:] == ["windows.vadyarascan.VadYaraScan", "--yara-file", str(rule_path)]
        stdout.write(b"[]")
        return FakeProcess(return_code=0)

    result = run_volatility_plugin(
        get_plugin_definition("windows.vadyarascan"),
        tmp_path / "evidence.raw",
        tmp_path / "raw",
        settings=YaraSettings(),
        plugin_profile="windows_memory_yara_elastic",
        process_runner=fake_popen,
    )

    assert result.status == STATUS_COMPLETED
    assert result.extra_data["timeout_seconds"] == 15
    assert result.extra_data["yara_rules_configured"] is True
    assert result.extra_data["yara_rule_pack"] == "elastic_yara"
    assert result.extra_data["yara_rules_source"] == "elastic_yara.yar"


def test_runner_marks_timeout_failed(tmp_path) -> None:
    def fake_popen(command, stdout, stderr, text, start_new_session):
        stdout.write(b"partial")
        stderr.write(b"slow")
        return FakeProcess(timeout=True)

    result = run_volatility_plugin(
        get_plugin_definition("windows.psscan"),
        tmp_path / "evidence.raw",
        tmp_path / "raw",
        settings=DummySettings(),
        process_runner=fake_popen,
    )

    assert result.raw_output_path.read_text(encoding="utf-8") == "partial"
    assert result.status == STATUS_FAILED
    assert result.timed_out is True
    assert result.stderr == "slow"
    assert result.error_message == "Volatility plugin timed out after 5s"
    assert result.extra_data["timeout_seconds"] == 5
    assert result.extra_data["timeout_reason"] == "plugin_timeout"
    assert result.extra_data["plugin_name"] == "windows.psscan"
    assert result.extra_data["is_yara_plugin"] is False


def test_runner_marks_vadyarascan_timeout_with_yara_timeout_metadata(tmp_path) -> None:
    yara_dir = tmp_path / "rules" / "yara" / "compiled"
    yara_dir.mkdir(parents=True)
    (yara_dir / "elastic_yara.yar").write_text("rule ElasticTest { condition: false }", encoding="utf-8")

    class YaraSettings(DummySettings):
        rules_dir = str(tmp_path / "rules")

    def fake_popen(command, stdout, stderr, text, start_new_session):
        stderr.write(b"slow")
        return FakeProcess(timeout=True)

    result = run_volatility_plugin(
        get_plugin_definition("windows.vadyarascan"),
        tmp_path / "evidence.raw",
        tmp_path / "raw",
        settings=YaraSettings(),
        plugin_profile="windows_memory_yara",
        process_runner=fake_popen,
    )

    assert result.status == STATUS_FAILED
    assert result.timed_out is True
    assert result.error_message == "Volatility plugin timed out after 15s"
    assert result.extra_data["timeout_seconds"] == 15
    assert result.extra_data["timeout_reason"] == "plugin_timeout"
    assert result.extra_data["plugin_name"] == "windows.vadyarascan"
    assert result.extra_data["is_yara_plugin"] is True
