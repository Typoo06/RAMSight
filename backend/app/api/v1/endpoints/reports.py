"""Report endpoint placeholders."""

from fastapi import APIRouter

router = APIRouter()


@router.get("")
def list_reports() -> dict[str, list[object]]:
    """Return report placeholders until report generation is implemented."""
    return {"items": []}
