# Volatility execution runner.

from dataclasses import dataclass
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
from time import perf_counter

from app.core.config import Settings, get_settings
from app.storage.keys import normalize_plugin_name_part
from app.tasks import status as task_status
from app.volatility.commands import build_volatility_command
from app.volatility.registry import PluginDefinition
from app.yara.rules import profile_is_heavy_yara, resolve_yara_rules_path, yara_pack_for_profile


YARA_PLUGIN_NAMES = {"windows.vadyarascan", "yarascan", "linux.vmayarascan"}
MAX_STDERR_CAPTURE_BYTES = 64 * 1024


@dataclass(frozen=True)
class VolatilityRunResult:
    plugin_name: str
    source_plugin: str
    status: str
    raw_output_path: Path
    command: list[str]
    return_code: int | None
    stdout: str
    stderr: str
    error_message: str | None
    duration_ms: int
    extra_data: dict | None = None
    timed_out: bool = False


class VolatilityUnavailableError(RuntimeError):
    pass


def ensure_volatility_available(volatility_path: str) -> None:
    if Path(volatility_path).is_absolute() or "/" in volatility_path:
        executable = Path(volatility_path)
        if not executable.is_file() or not os.access(executable, os.X_OK):
            raise VolatilityUnavailableError(f"Volatility executable not found: {volatility_path}")
        return
    if shutil.which(volatility_path) is None:
        raise VolatilityUnavailableError(f"Volatility executable not found: {volatility_path}")


def duration_ms_since(started_at: float) -> int:
    return int((perf_counter() - started_at) * 1000)


def short_error_message(message: str, max_length: int = 500) -> str:
    return " ".join(message.split())[:max_length]


def raw_output_path_for_plugin(raw_dir: Path, plugin_name: str) -> Path:
    return raw_dir / f"{normalize_plugin_name_part(plugin_name)}.json"


def stderr_path_for_plugin(raw_dir: Path, plugin_name: str) -> Path:
    return raw_dir / f"{normalize_plugin_name_part(plugin_name)}.stderr.txt"


def read_text_excerpt(path: Path, max_bytes: int = MAX_STDERR_CAPTURE_BYTES) -> str:
    if not path.exists():
        return ""
    with path.open("rb") as handle:
        data = handle.read(max_bytes)
        truncated = handle.read(1) != b""
    text = data.decode("utf-8", errors="replace")
    if truncated:
        text = f"{text}\n[stderr truncated to {max_bytes} bytes]"
    return text


def terminate_process(process: subprocess.Popen) -> None:
    try:
        os.killpg(process.pid, signal.SIGKILL)
        return
    except Exception:
        pass
    try:
        process.kill()
    except Exception:
        pass


def is_yara_plugin(plugin_name: str) -> bool:
    return plugin_name in YARA_PLUGIN_NAMES


def plugin_timeout_seconds(plugin: PluginDefinition, settings: Settings) -> int:
    if is_yara_plugin(plugin.name):
        return settings.volatility_yara_timeout_seconds
    return settings.volatility_plugin_timeout_seconds


def write_raw_wrapper(
    output_path: Path,
    plugin: PluginDefinition,
    command: list[str],
    status: str,
    return_code: int | None,
    stdout: str,
    stderr: str,
    error_message: str | None,
    duration_ms: int,
    timed_out: bool,
    extra_data: dict | None = None,
) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "plugin_name": plugin.name,
        "source_plugin": plugin.name,
        "command": command,
        "status": status,
        "return_code": return_code,
        "timed_out": timed_out,
        "duration_ms": duration_ms,
        "stdout": stdout,
        "stderr": stderr,
        "error_message": error_message,
        "renderer": "json",
        "extra_data": extra_data or {},
    }
    output_path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")


def skipped_plugin_result(raw_dir: Path, plugin: PluginDefinition, reason: str, extra_data: dict | None = None) -> VolatilityRunResult:
    output_path = raw_output_path_for_plugin(raw_dir, plugin.name)
    write_raw_wrapper(
        output_path=output_path,
        plugin=plugin,
        command=[],
        status=task_status.STATUS_SKIPPED,
        return_code=None,
        stdout="",
        stderr="",
        error_message=reason,
        duration_ms=0,
        timed_out=False,
        extra_data=extra_data,
    )
    return VolatilityRunResult(
        plugin_name=plugin.name,
        source_plugin=plugin.name,
        status=task_status.STATUS_SKIPPED,
        raw_output_path=output_path,
        command=[],
        return_code=None,
        stdout="",
        stderr="",
        error_message=reason,
        duration_ms=0,
        extra_data=extra_data or {},
    )


def run_volatility_plugin(
    plugin: PluginDefinition,
    evidence_path: Path,
    raw_dir: Path,
    settings: Settings | None = None,
    plugin_profile: str | None = None,
    process_runner=subprocess.Popen,
) -> VolatilityRunResult:
    runtime_settings = settings or get_settings()
    output_path = raw_output_path_for_plugin(raw_dir, plugin.name)
    stderr_path = stderr_path_for_plugin(raw_dir, plugin.name)
    timeout_seconds = plugin_timeout_seconds(plugin, runtime_settings)
    plugin_extra_data = {
        "requires_yara_rules": plugin.requires_yara_rules,
        "plugin_name": plugin.name,
        "logical_plugin_name": plugin.name,
        "cli_plugin_name": plugin.command_name,
        "plugin_category": plugin.category,
        "timeout_policy": plugin.timeout_policy,
        "parser_strategy": plugin.parser_strategy,
        "available": plugin.available,
        "product_purpose": plugin.product_purpose,
        "is_yara_plugin": is_yara_plugin(plugin.name),
        "plugin_profile": plugin_profile,
        "timeout_seconds": timeout_seconds,
        "stderr_capture_limit_bytes": MAX_STDERR_CAPTURE_BYTES,
    }

    if not plugin.available:
        plugin_extra_data["skip_reason"] = "plugin is not available in the installed Volatility build"
        return skipped_plugin_result(raw_dir, plugin, plugin_extra_data["skip_reason"], plugin_extra_data)
    if not plugin.implemented:
        return skipped_plugin_result(raw_dir, plugin, "plugin is registered but not implemented for execution yet", plugin_extra_data)
    yara_rules_path = None
    if plugin.requires_yara_rules:
        selected_pack = yara_pack_for_profile(plugin_profile)
        yara_rules_path = resolve_yara_rules_path(runtime_settings, plugin_profile=plugin_profile)
        plugin_extra_data.update(
            {
                "yara_rule_pack": selected_pack,
                "heavy_yara_profile": profile_is_heavy_yara(plugin_profile),
            }
        )
        if not yara_rules_path:
            skip_reason = (
                f"YARA rule pack {selected_pack} is required for this profile; run scripts/rules/import_third_party_rules.py, "
                "validate_yara_rules.py, and build_yara_pack.py before starting this profile"
                if selected_pack
                else "YARA rule configuration is required for this plugin"
            )
            plugin_extra_data.update(
                {
                    "yara_rules_configured": False,
                    "skip_reason": skip_reason,
                }
            )
            return skipped_plugin_result(raw_dir, plugin, skip_reason, plugin_extra_data)
        plugin_extra_data.update(
            {
                "yara_rules_configured": True,
                "yara_rules_source": Path(yara_rules_path).name,
                "yara_rules_path": str(yara_rules_path),
            }
        )

    command = build_volatility_command(runtime_settings, plugin, evidence_path, raw_dir, yara_rules_path=yara_rules_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    started_at = perf_counter()
    process: subprocess.Popen | None = None
    try:
        with output_path.open("wb") as stdout_file, stderr_path.open("wb") as stderr_file:
            process = process_runner(
                command,
                stdout=stdout_file,
                stderr=stderr_file,
                text=False,
                start_new_session=True,
            )
            return_code = process.wait(timeout=timeout_seconds)
        duration_ms = duration_ms_since(started_at)
        stderr = read_text_excerpt(stderr_path)
        status = task_status.STATUS_COMPLETED if return_code == 0 else task_status.STATUS_FAILED
        error_message = None if return_code == 0 else short_error_message(stderr or "Volatility plugin failed")
        return VolatilityRunResult(
            plugin_name=plugin.name,
            source_plugin=plugin.name,
            status=status,
            raw_output_path=output_path,
            command=command,
            return_code=return_code,
            stdout="",
            stderr=stderr,
            error_message=error_message,
            duration_ms=duration_ms,
            extra_data=plugin_extra_data,
        )
    except subprocess.TimeoutExpired:
        if process is not None:
            terminate_process(process)
            try:
                process.wait(timeout=5)
            except Exception:
                pass
        duration_ms = duration_ms_since(started_at)
        stderr = read_text_excerpt(stderr_path)
        error_message = short_error_message(f"Volatility plugin timed out after {timeout_seconds}s")
        timeout_extra_data = {**plugin_extra_data, "timeout_reason": "plugin_timeout"}
        output_path.touch(exist_ok=True)
        return VolatilityRunResult(
            plugin_name=plugin.name,
            source_plugin=plugin.name,
            status=task_status.STATUS_FAILED,
            raw_output_path=output_path,
            command=command,
            return_code=None,
            stdout="",
            stderr=stderr,
            error_message=error_message,
            duration_ms=duration_ms,
            extra_data=timeout_extra_data,
            timed_out=True,
        )
