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


KNOWN_MICROSOFT_APPDATA_ROOTS = {
    "onedrive": "/appdata/local/microsoft/onedrive/",
    "edge": "/appdata/local/microsoft/edge/",
    "edgewebview": "/appdata/local/microsoft/edgewebview/",
}


def normalize_windows_path(value: Any) -> str:
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
