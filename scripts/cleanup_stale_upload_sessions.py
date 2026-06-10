#!/usr/bin/env python3
# Remove expired browser upload temp sessions for local RAMSight demos.

from __future__ import annotations

from pathlib import Path
import sys

REPO_ROOT = Path(__file__).resolve().parents[1]
BACKEND_ROOT = REPO_ROOT / "backend"
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from app.services.evidence_upload_session_service import cleanup_expired_upload_sessions


def main() -> int:
    counts = cleanup_expired_upload_sessions()
    print(
        "Upload session cleanup: "
        f"scanned={counts['scanned']} "
        f"removed={counts['removed']} "
        f"expired={counts['expired']} "
        f"corrupt_stale={counts['corrupt_stale']} "
        f"active={counts['active']} "
        f"ignored={counts['ignored']} "
        f"errors={counts['errors']}"
    )
    return 0 if counts["errors"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
