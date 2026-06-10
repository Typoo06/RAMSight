# Plugin result metadata endpoints.

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.api.deps import get_db
from app.schemas.plugin_result import PluginResultListResponse, PluginResultRead
from app.services import plugin_result_service
from app.services.errors import NotFoundError

router = APIRouter()


@router.get("/analysis-jobs/{job_id}/plugin-results", response_model=PluginResultListResponse)
def list_plugin_results(
    job_id: UUID,
    status_filter: str | None = Query(default=None, alias="status"),
    plugin_name: str | None = None,
    source_plugin: str | None = None,
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
):
    try:
        items = plugin_result_service.list_plugin_results(
            db,
            job_id,
            status=status_filter,
            plugin_name=plugin_name,
            source_plugin=source_plugin,
            limit=limit,
            offset=offset,
        )
    except NotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    return {"items": items}


@router.get("/plugin-results/{plugin_result_id}", response_model=PluginResultRead)
def get_plugin_result(plugin_result_id: UUID, db: Session = Depends(get_db)):
    try:
        return plugin_result_service.get_plugin_result(db, plugin_result_id)
    except NotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
