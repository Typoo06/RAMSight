"""IOC endpoint placeholders."""

from fastapi import APIRouter

router = APIRouter()


@router.get("")
def list_iocs() -> dict[str, list[object]]:
    """Return IOC placeholders until extraction is implemented."""
    return {"items": []}
