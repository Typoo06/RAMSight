"""Case endpoint placeholders."""

from fastapi import APIRouter

router = APIRouter()


@router.get("")
def list_cases() -> dict[str, list[object]]:
    """Return case placeholders until persistence is implemented."""
    return {"items": []}
