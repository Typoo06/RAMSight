# Local demo preflight script tests.

from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys
from urllib.error import URLError

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT_ROOT = REPO_ROOT / "scripts" / "demo"
if str(SCRIPT_ROOT) not in sys.path:
    sys.path.insert(0, str(SCRIPT_ROOT))

import preflight_check


class FakeResponse:

    def __init__(self, status: int, payload=None, raw: bytes | None = None) -> None:
        self.status = status
        self.payload = payload
        self.raw = raw

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        return None

    def getcode(self) -> int:
        return self.status

    def read(self) -> bytes:
        if self.raw is not None:
            return self.raw
        if self.payload is None:
            return b""
        return json.dumps(self.payload).encode("utf-8")


class FakeOpener:

    def __init__(self, responses: dict[str, FakeResponse | Exception]) -> None:
        self.responses = responses
        self.urls: list[str] = []

    def __call__(self, request, timeout=0):
        url = getattr(request, "full_url", request)
        self.urls.append(url)
        response = self.responses.get(url)
        if isinstance(response, Exception):
            raise response
        if response is None:
            raise URLError("missing fake response")
        return response


def git_runner_with_files(files: list[str]):
    def run(args, cwd=None, capture_output=False, text=False, check=False):
        if args[:3] == ["git", "rev-parse", "--is-inside-work-tree"]:
            return subprocess.CompletedProcess(args, 0, stdout="true\n", stderr="")
        if args[:2] == ["git", "ls-files"]:
            return subprocess.CompletedProcess(args, 0, stdout="\n".join(files), stderr="")
        return subprocess.CompletedProcess(args, 1, stdout="", stderr="")

    return run


def ok_responses() -> dict[str, FakeResponse]:
    return {
        "http://localhost:8000/health": FakeResponse(200, {"status": "ok", "environment": "development"}),
        "http://localhost:8000/ready": FakeResponse(200, {"status": "ready", "checks": {"database": "ok", "redis": "ok", "object_storage": "ok"}}),
        "http://localhost:5173": FakeResponse(200, raw=b"<html></html>"),
    }


def test_preflight_success_with_health_ready_and_frontend() -> None:
    opener = FakeOpener(ok_responses())

    result = preflight_check.run_preflight(
        "http://localhost:8000/api/v1",
        "http://localhost:5173",
        opener=opener,
        command_runner=git_runner_with_files(["README.md"]),
    )

    assert result.status == "pass"
    assert [check.status for check in result.checks] == ["ok", "ok", "ok", "ok"]
    assert "http://localhost:8000/health" in opener.urls
    assert "http://localhost:8000/ready" in opener.urls


def test_readiness_not_ready_fails_without_leaking_urls() -> None:
    responses = ok_responses()
    responses["http://localhost:8000/ready"] = FakeResponse(503, {"status": "not_ready", "checks": {"database": "ok", "redis": "error", "object_storage": "ok"}})
    opener = FakeOpener(responses)

    result = preflight_check.run_preflight(
        "http://localhost:8000/api/v1",
        "http://localhost:5173",
        opener=opener,
        command_runner=git_runner_with_files([]),
    )

    assert result.status == "fail"
    ready_check = next(check for check in result.checks if check.name == "backend_readiness")
    assert ready_check.status == "fail"
    assert ready_check.details["checks"] == {"database": "ok", "redis": "error", "object_storage": "ok"}
    serialized = json.dumps(result.to_jsonable()).lower()
    assert "redis://" not in serialized
    assert "postgresql" not in serialized
    assert "secret" not in serialized


def test_frontend_unreachable_fails() -> None:
    responses = ok_responses()
    responses["http://localhost:5173"] = URLError("connection refused")
    opener = FakeOpener(responses)

    result = preflight_check.run_preflight(
        "http://localhost:8000/api/v1",
        "http://localhost:5173",
        opener=opener,
        command_runner=git_runner_with_files([]),
    )

    assert result.status == "fail"
    frontend = next(check for check in result.checks if check.name == "frontend")
    assert frontend.status == "fail"


def test_job_id_optional_checks_summarize_job_data() -> None:
    job_id = "600f1bb4-0eb1-4468-a7a8-8539283d41e7"
    responses = ok_responses()
    responses.update(
        {
            f"http://localhost:8000/api/v1/analysis-jobs/{job_id}": FakeResponse(200, {"id": job_id, "status": "completed"}),
            f"http://localhost:8000/api/v1/analysis-jobs/{job_id}/plugin-results?limit=500": FakeResponse(200, {"items": [{"plugin_name": "windows.pslist"}]}),
            f"http://localhost:8000/api/v1/risk-findings?job_id={job_id}&limit=500": FakeResponse(200, {"items": [{"rule_id": "R1"}, {"rule_id": "R2"}]}),
            f"http://localhost:8000/api/v1/iocs?job_id={job_id}&limit=500": FakeResponse(200, {"items": [{"ioc_type": "ip_address"}]}),
            f"http://localhost:8000/api/v1/reports?job_id={job_id}&limit=500": FakeResponse(200, {"items": [{"report_type": "technical"}]}),
        }
    )
    opener = FakeOpener(responses)

    result = preflight_check.run_preflight(
        "http://localhost:8000/api/v1",
        "http://localhost:5173",
        job_id=job_id,
        opener=opener,
        command_runner=git_runner_with_files([]),
    )

    assert result.status == "pass"
    counts = {check.name: check.details.get("visible_items") for check in result.checks}
    assert counts["plugin_results"] == 1
    assert counts["risk_findings"] == 2
    assert counts["iocs"] == 1
    assert counts["reports"] == 1


def test_json_output_is_valid_json(capsys) -> None:
    result = preflight_check.PreflightResult(
        status="pass",
        checks=[preflight_check.CheckResult(name="backend_health", status="ok", summary="ok")],
    )

    print(json.dumps(result.to_jsonable(), indent=2, sort_keys=True))
    payload = json.loads(capsys.readouterr().out)

    assert payload["status"] == "pass"
    assert payload["checks"][0]["name"] == "backend_health"


def test_git_dump_check_detects_tracked_dump_like_filename() -> None:
    result = preflight_check.tracked_dump_files(command_runner=git_runner_with_files(["docs/readme.md", "sample.mem"]))

    assert result.status == "fail"
    assert result.details["count"] == 1
    assert result.details["files"] == ["sample.mem"]


def test_non_strict_job_optional_endpoint_warns_but_strict_fails() -> None:
    job_id = "600f1bb4-0eb1-4468-a7a8-8539283d41e7"
    responses = ok_responses()
    responses.update(
        {
            f"http://localhost:8000/api/v1/analysis-jobs/{job_id}": FakeResponse(200, {"id": job_id, "status": "completed"}),
            f"http://localhost:8000/api/v1/analysis-jobs/{job_id}/plugin-results?limit=500": FakeResponse(404, {"detail": "missing"}),
            f"http://localhost:8000/api/v1/risk-findings?job_id={job_id}&limit=500": FakeResponse(200, {"items": []}),
            f"http://localhost:8000/api/v1/iocs?job_id={job_id}&limit=500": FakeResponse(200, {"items": []}),
            f"http://localhost:8000/api/v1/reports?job_id={job_id}&limit=500": FakeResponse(200, {"items": []}),
        }
    )

    non_strict = preflight_check.run_preflight(
        "http://localhost:8000/api/v1",
        "http://localhost:5173",
        job_id=job_id,
        strict=False,
        opener=FakeOpener(responses),
        command_runner=git_runner_with_files([]),
    )
    strict = preflight_check.run_preflight(
        "http://localhost:8000/api/v1",
        "http://localhost:5173",
        job_id=job_id,
        strict=True,
        opener=FakeOpener(responses),
        command_runner=git_runner_with_files([]),
    )

    assert non_strict.status == "pass"
    assert next(check for check in non_strict.checks if check.name == "plugin_results").status == "warn"
    assert strict.status == "fail"
    assert next(check for check in strict.checks if check.name == "plugin_results").status == "fail"

def test_backend_health_unreachable_fails_cleanly() -> None:
    responses = ok_responses()
    responses["http://localhost:8000/health"] = URLError("connection refused")
    opener = FakeOpener(responses)

    result = preflight_check.run_preflight(
        "http://localhost:8000/api/v1",
        "http://localhost:5173",
        opener=opener,
        command_runner=git_runner_with_files([]),
    )

    assert result.status == "fail"
    health_check = next(check for check in result.checks if check.name == "backend_health")
    assert health_check.status == "fail"
    assert health_check.details["http_status"] == 0

