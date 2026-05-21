# Volatility execution runner.

from dataclasses import dataclass
import json
import os
from pathlib import Path
import shutil
import subprocess
from time import perf_counter

from app.core.config import Settings, get_settings
from app.storage.keys import normalize_plugin_name_part
from app.tasks import status as task_status
from app.volatility.commands import build_volatility_command
from app.volatility.registry import PluginDefinition


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
    }
    output_path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")


def skipped_plugin_result(raw_dir: Path, plugin: PluginDefinition, reason: str) -> VolatilityRunResult:
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
    )


def run_volatility_plugin(
    plugin: PluginDefinition,
    evidence_path: Path,
    raw_dir: Path,
    settings: Settings | None = None,
    process_runner=subprocess.run,
) -> VolatilityRunResult:
    runtime_settings = settings or get_settings()
    output_path = raw_output_path_for_plugin(raw_dir, plugin.name)

    if not plugin.implemented:
        return skipped_plugin_result(raw_dir, plugin, "plugin is registered but not implemented for execution yet")
    if plugin.requires_yara_rules and not runtime_settings.volatility_yara_rules_path:
        return skipped_plugin_result(raw_dir, plugin, "YARA rule configuration is required for this plugin")

    command = build_volatility_command(runtime_settings, plugin, evidence_path, raw_dir)
    started_at = perf_counter()
    try:
        completed = process_runner(
            command,
            capture_output=True,
            text=True,
            timeout=runtime_settings.volatility_plugin_timeout_seconds,
            check=False,
        )
        duration_ms = duration_ms_since(started_at)
        stdout = completed.stdout or ""
        stderr = completed.stderr or ""
        status = task_status.STATUS_COMPLETED if completed.returncode == 0 else task_status.STATUS_FAILED
        error_message = None if completed.returncode == 0 else short_error_message(stderr or "Volatility plugin failed")
        write_raw_wrapper(
            output_path,
            plugin,
            command,
            status,
            completed.returncode,
            stdout,
            stderr,
            error_message,
            duration_ms,
            timed_out=False,
        )
        return VolatilityRunResult(
            plugin.name,
            plugin.name,
            status,
            output_path,
            command,
            completed.returncode,
            stdout,
            stderr,
            error_message,
            duration_ms,
        )
    except subprocess.TimeoutExpired as exc:
        duration_ms = duration_ms_since(started_at)
        stdout = exc.stdout if isinstance(exc.stdout, str) else (exc.stdout or b"").decode(errors="replace")
        stderr = exc.stderr if isinstance(exc.stderr, str) else (exc.stderr or b"").decode(errors="replace")
        error_message = short_error_message(f"Volatility plugin timed out after {runtime_settings.volatility_plugin_timeout_seconds}s")
        write_raw_wrapper(
            output_path,
            plugin,
            command,
            task_status.STATUS_FAILED,
            None,
            stdout,
            stderr,
            error_message,
            duration_ms,
            timed_out=True,
        )
        return VolatilityRunResult(
            plugin.name,
            plugin.name,
            task_status.STATUS_FAILED,
            output_path,
            command,
            None,
            stdout,
            stderr,
            error_message,
            duration_ms,
            timed_out=True,
        )
