# Path reputation helpers for cautious Windows AppData module triage.

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from app.parsers.common import is_path_like


@dataclass(frozen=True)
class KnownMicrosoftAppDataPath:
    app_name: str
    root_fragment: str
    normalized_root: str


@dataclass(frozen=True)
class BenignProcessContext:
    name: str
    reason: str
    category: str = "benign_context"


KNOWN_MICROSOFT_APPDATA_ROOTS = {
    "onedrive": "/appdata/local/microsoft/onedrive/",
    "edge": "/appdata/local/microsoft/edge/",
    "edgewebview": "/appdata/local/microsoft/edgewebview/",
}

BENIGN_PROCESS_CONTEXTS = {
    "elastic_endpoint": {
        "name_fragments": ("elastic-endpoi", "elastic-endpoint", "elasticendpoint", "elastic endpoint"),
        "path_fragments": ("elastic\\endpoint", "elastic/endpoint", "elastic-agent", "elastic agent"),
        "reason": "Elastic Endpoint / Elastic Agent security sensor context",
    },
    "elastic_agent": {
        "name_fragments": ("elastic-agent", "elasticagent", "agentbeat", "winlogbeat"),
        "path_fragments": ("elastic\\agent", "elastic/agent", "beats\\winlogbeat", "beats/winlogbeat"),
        "reason": "Elastic Agent / Beats telemetry context",
    },
    "phone_experience": {
        "name_fragments": ("phoneexperienc", "phoneexperiencehost", "yourphone", "phonelink"),
        "path_fragments": ("phoneexperience", "yourphone", "phone link"),
        "reason": "Microsoft Phone Link / PhoneExperience context",
    },
    "onedrive": {
        "name_fragments": ("onedrive",),
        "path_fragments": ("microsoft\\onedrive", "microsoft/onedrive"),
        "reason": "Microsoft OneDrive sync client context",
    },
    "edge_webview": {
        "name_fragments": ("msedge", "msedgewebview", "webview2", "microsoftedge"),
        "path_fragments": ("microsoft\\edge", "microsoft/edge", "edgewebview", "webview2"),
        "reason": "Microsoft Edge / WebView runtime context",
    },
    "defender": {
        "name_fragments": ("msmpeng", "nissrv", "securityhealth", "windefend", "defender"),
        "path_fragments": ("windows defender", "microsoft\\defender", "microsoft/defender", "windows\\system32\\securityhealth"),
        "reason": "Microsoft Defender / Windows Security context",
    },
    "browser_runtime": {
        "name_fragments": ("chrome", "firefox", "browser", "iexplore"),
        "path_fragments": ("google\\chrome", "google/chrome", "mozilla firefox", "firefox"),
        "reason": "Browser runtime or JIT memory context",
    },
}


def normalize_windows_path(value: Any) -> str:
    return str(value or "").strip().replace("\\", "/").lower()


def _normalized_any(value: Any) -> str:
    return str(value or "").strip().replace("\\", "/").lower()


def known_microsoft_appdata_path(value: Any, os_family: str | None = None) -> KnownMicrosoftAppDataPath | None:
    if (os_family or "unknown").lower() != "windows":
        return None
    if not is_path_like(value, os_family):
        return None
    normalized = normalize_windows_path(value)
    normalized_with_slash = normalized if normalized.endswith("/") else f"{normalized}/"
    for app_name, root_fragment in KNOWN_MICROSOFT_APPDATA_ROOTS.items():
        if root_fragment in normalized_with_slash:
            root_end = normalized_with_slash.find(root_fragment) + len(root_fragment)
            return KnownMicrosoftAppDataPath(
                app_name=app_name,
                root_fragment=root_fragment.strip("/"),
                normalized_root=normalized_with_slash[:root_end].rstrip("/"),
            )
    return None


def is_known_microsoft_appdata_path(value: Any, os_family: str | None = None) -> bool:
    return known_microsoft_appdata_path(value, os_family) is not None


def known_benign_process_context(
    process_name: Any = None,
    image_path: Any = None,
    command_line: Any = None,
    os_family: str | None = None,
) -> BenignProcessContext | None:
    if (os_family or "unknown").lower() not in {"windows", "unknown"}:
        return None
    name = _normalized_any(process_name)
    path = _normalized_any(image_path)
    command = _normalized_any(command_line)
    combined_path = f"{path} {command}"
    for key, config in BENIGN_PROCESS_CONTEXTS.items():
        if any(fragment in name for fragment in config["name_fragments"]):
            return BenignProcessContext(name=key, reason=config["reason"])
        if any(fragment.replace("\\", "/") in combined_path for fragment in config["path_fragments"]):
            return BenignProcessContext(name=key, reason=config["reason"])
    return None
