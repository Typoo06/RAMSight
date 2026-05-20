"""Evidence endpoint placeholders."""

from fastapi import APIRouter

router = APIRouter()


@router.get("")
def list_evidences() -> dict[str, list[object]]:
    """Return evidence placeholders until upload metadata is implemented."""
    return {"items": []}
