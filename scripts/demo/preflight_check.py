#!/usr/bin/env python3
# Local RAMSight demo preflight checks without running memory analysis.

from __future__ import annotations

import argparse
from dataclasses import asdict, dataclass, field
import json
from pathlib import Path
import subprocess
import sys
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urljoin, urlparse, urlunparse
from urllib.request import Request, urlopen

DUMP_EXTENSIONS = (".raw", ".mem", ".dmp", ".vmem", ".lime", ".aff4")
DEFAULT_API_BASE = "http://localhost:8000/api/v1"
DEFAULT_FRONTEND_URL = "http://localhost:5173"
REQUEST_TIMEOUT_SECONDS = 5


@dataclass
class CheckResult:
    name: str
    status: str
    summary: str
    details: dict[str, Any] = field(default_factory=dict)


@dataclass
class PreflightResult:
    status: str
    checks: list[CheckResult]

    def to_jsonable(self) -> dict[str, Any]:
        return {"status": self.status, "checks": [asdict(check) for check in self.checks]}


def root_base_from_api_base(api_base: str) -> str:
    parsed = urlparse(api_base)
    if not parsed.scheme or not parsed.netloc:
        raise ValueError("api-base must be an absolute URL")
    return urlunparse((parsed.scheme, parsed.netloc, "", "", "", ""))


def join_url(base: str, path: str) -> str:
    return urljoin(base.rstrip("/") + "/", path.lstrip("/"))


def safe_count_items(payload: Any) -> int | None:
    if isinstance(payload, dict) and isinstance(payload.get("items"), list):
        return len(payload["items"])
    return None


def read_http_json(url: str, opener=urlopen, timeout: int = REQUEST_TIMEOUT_SECONDS) -> tuple[int, Any]:
    request = Request(url, headers={"Accept": "application/json"})
    try:
        with opener(request, timeout=timeout) as response:
            status = getattr(response, "status", None) or response.getcode()
            data = response.read()
    except HTTPError as exc:
        status = exc.code
        data = exc.read()
    except (URLError, OSError):
        return 0, None
    if not data:
        return int(status), None
    try:
        return int(status), json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return int(status), None


def check_http_success(name: str, url: str, opener=urlopen) -> CheckResult:
    request = Request(url)
    try:
        with opener(request, timeout=REQUEST_TIMEOUT_SECONDS) as response:
            status = int(getattr(response, "status", None) or response.getcode())
    except (HTTPError, URLError, OSError):
        return CheckResult(name=name, status="fail", summary="unreachable")
    if 200 <= status < 400:
        return CheckResult(name=name, status="ok", summary="reachable", details={"http_status": status})
    return CheckResult(name=name, status="fail", summary="unexpected HTTP status", details={"http_status": status})


def check_health(api_base: str, opener=urlopen) -> CheckResult:
    url = join_url(root_base_from_api_base(api_base), "/health")
    status, payload = read_http_json(url, opener=opener)
    if status == 200 and isinstance(payload, dict) and payload.get("status") == "ok":
        return CheckResult(name="backend_health", status="ok", summary="backend health endpoint is ok")
    return CheckResult(name="backend_health", status="fail", summary="backend health endpoint is not ok", details={"http_status": status})


def check_ready(api_base: str, opener=urlopen) -> CheckResult:
    url = join_url(root_base_from_api_base(api_base), "/ready")
    status, payload = read_http_json(url, opener=opener)
    checks = payload.get("checks") if isinstance(payload, dict) else None
    safe_checks = checks if isinstance(checks, dict) else {}
    if status == 200 and isinstance(payload, dict) and payload.get("status") == "ready":
        return CheckResult(name="backend_readiness", status="ok", summary="backend dependencies are ready", details={"checks": safe_checks})
    return CheckResult(name="backend_readiness", status="fail", summary="backend dependencies are not ready", details={"http_status": status, "checks": safe_checks})


def check_frontend(frontend_url: str, opener=urlopen) -> CheckResult:
    return check_http_success("frontend", frontend_url, opener=opener)


def query_string(params: dict[str, Any]) -> str:
    return urlencode({key: value for key, value in params.items() if value is not None})


def check_optional_json_endpoint(name: str, url: str, strict: bool, opener=urlopen) -> CheckResult:
    status, payload = read_http_json(url, opener=opener)
    if 200 <= status < 300:
        details: dict[str, Any] = {"http_status": status}
        item_count = safe_count_items(payload)
        if item_count is not None:
            details["visible_items"] = item_count
        elif isinstance(payload, dict):
            details["fields"] = sorted(str(key) for key in payload.keys())[:10]
        return CheckResult(name=name, status="ok", summary="available", details=details)
    result_status = "fail" if strict else "warn"
    return CheckResult(name=name, status=result_status, summary="unavailable", details={"http_status": status})


def check_job(api_base: str, job_id: str, strict: bool, opener=urlopen) -> list[CheckResult]:
    base = api_base.rstrip("/")
    checks = [check_optional_json_endpoint("analysis_job", f"{base}/analysis-jobs/{job_id}", strict=True, opener=opener)]
    optional_endpoints = [
        ("plugin_results", f"{base}/analysis-jobs/{job_id}/plugin-results?{query_string({'limit': 500})}"),
        ("risk_findings", f"{base}/risk-findings?{query_string({'job_id': job_id, 'limit': 500})}"),
        ("iocs", f"{base}/iocs?{query_string({'job_id': job_id, 'limit': 500})}"),
        ("reports", f"{base}/reports?{query_string({'job_id': job_id, 'limit': 500})}"),
    ]
    for name, url in optional_endpoints:
        checks.append(check_optional_json_endpoint(name, url, strict=strict, opener=opener))
    return checks


def tracked_dump_files(command_runner=subprocess.run, cwd: Path | None = None) -> CheckResult:
    cwd = cwd or Path.cwd()
    try:
        inside = command_runner(["git", "rev-parse", "--is-inside-work-tree"], cwd=cwd, capture_output=True, text=True, check=False)
    except (OSError, FileNotFoundError):
        return CheckResult(name="git_dump_check", status="warn", summary="git is unavailable")
    if inside.returncode != 0 or inside.stdout.strip().lower() != "true":
        return CheckResult(name="git_dump_check", status="warn", summary="not running inside a Git worktree")

    listed = command_runner(["git", "ls-files"], cwd=cwd, capture_output=True, text=True, check=False)
    if listed.returncode != 0:
        return CheckResult(name="git_dump_check", status="warn", summary="could not inspect tracked files")
    matches = [line for line in listed.stdout.splitlines() if line.lower().endswith(DUMP_EXTENSIONS)]
    if matches:
        return CheckResult(name="git_dump_check", status="fail", summary="tracked dump-like files found", details={"count": len(matches), "files": matches[:10]})
    return CheckResult(name="git_dump_check", status="ok", summary="no tracked dump-like files found")


def run_preflight(api_base: str, frontend_url: str, job_id: str | None = None, strict: bool = False, opener=urlopen, command_runner=subprocess.run) -> PreflightResult:
    checks = [
        check_health(api_base, opener=opener),
        check_ready(api_base, opener=opener),
        check_frontend(frontend_url, opener=opener),
        tracked_dump_files(command_runner=command_runner),
    ]
    if job_id:
        checks.extend(check_job(api_base, job_id, strict=strict, opener=opener))

    failed = any(check.status == "fail" for check in checks)
    return PreflightResult(status="fail" if failed else "pass", checks=checks)


def print_human(result: PreflightResult) -> None:
    print(f"RAMSight local demo preflight: {result.status.upper()}")
    for check in result.checks:
        line = f"- {check.name}: {check.status} - {check.summary}"
        if "visible_items" in check.details:
            line += f" ({check.details['visible_items']} visible items)"
        if check.name == "backend_readiness" and check.details.get("checks"):
            dependency_summary = ", ".join(f"{name}={status}" for name, status in sorted(check.details["checks"].items()))
            line += f" [{dependency_summary}]"
        if check.name == "git_dump_check" and check.details.get("count"):
            line += f" ({check.details['count']} tracked dump-like files)"
        print(line)


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run lightweight RAMSight local demo preflight checks.")
    parser.add_argument("--api-base", default=DEFAULT_API_BASE, help=f"Backend API base URL. Default: {DEFAULT_API_BASE}")
    parser.add_argument("--frontend-url", default=DEFAULT_FRONTEND_URL, help=f"Frontend URL. Default: {DEFAULT_FRONTEND_URL}")
    parser.add_argument("--job-id", default=None, help="Optional analysis job ID to summarize through existing result APIs.")
    parser.add_argument("--json", action="store_true", help="Print JSON output instead of a human-readable summary.")
    parser.add_argument("--strict", action="store_true", help="Treat optional job result endpoint failures as preflight failures.")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    try:
        result = run_preflight(args.api_base, args.frontend_url, job_id=args.job_id, strict=args.strict)
    except ValueError as exc:
        result = PreflightResult(status="fail", checks=[CheckResult(name="configuration", status="fail", summary=str(exc))])

    if args.json:
        print(json.dumps(result.to_jsonable(), indent=2, sort_keys=True))
    else:
        print_human(result)
    return 0 if result.status == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
