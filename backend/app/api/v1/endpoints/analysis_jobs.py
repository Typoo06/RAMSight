"""Analysis job endpoint placeholders."""

from fastapi import APIRouter

router = APIRouter()


@router.get("")
def list_analysis_jobs() -> dict[str, list[object]]:
    """Return analysis job placeholders until worker orchestration is implemented."""
    return {"items": []}
