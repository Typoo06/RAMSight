# Plugin result metadata endpoints.

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import Response, StreamingResponse
from sqlalchemy.orm import Session

from app.api.deps import get_db
from app.api.v1.endpoints.download_utils import generated_export_response, storage_download_response
from app.core.config import get_settings
from app.schemas.plugin_result import PluginResultListResponse, PluginResultRead
from app.services import download_service, plugin_result_service
from app.services.result_export_service import build_export_file, export_rows
from app.services.errors import NotFoundError, ValidationError
from app.storage.client import ObjectStorageClient, get_storage_client

router = APIRouter()

PLUGIN_RESULT_EXPORT_FIELDS = [
    "id",
    "analysis_job_id",
    "evidence_id",
    "os_family",
    "plugin_profile",
    "plugin_name",
    "source_plugin",
    "status",
    "raw_output_bucket",
    "raw_output_key",
    "parsed_output_bucket",
    "parsed_output_key",
    "parsed_record_count",
    "error_message",
    "duration_ms",
    "extra_data",
    "started_at",
    "completed_at",
    "created_at",
    "updated_at",
]


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
        total = plugin_result_service.count_plugin_results(
            db,
            job_id,
            status=status_filter,
            plugin_name=plugin_name,
            source_plugin=source_plugin,
        )
    except NotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    return {"items": items, "total": total, "limit": limit, "offset": offset}


@router.get("/analysis-jobs/{job_id}/plugin-results/export.json", response_class=Response)
def export_plugin_results_json(
    job_id: UUID,
    status_filter: str | None = Query(default=None, alias="status"),
    plugin_name: str | None = None,
    source_plugin: str | None = None,
    db: Session = Depends(get_db),
):
    try:
        items = plugin_result_service.export_plugin_results(
            db, job_id, status=status_filter, plugin_name=plugin_name, source_plugin=source_plugin
        )
    except NotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    rows = export_rows(items, PLUGIN_RESULT_EXPORT_FIELDS)
    return generated_export_response(build_export_file("plugin_results", "plugin_results", rows, "json"))


@router.get("/plugin-results/{plugin_result_id}/raw-output/download", response_class=StreamingResponse)
def download_plugin_result_raw_output(
    plugin_result_id: UUID,
    db: Session = Depends(get_db),
    storage_client: ObjectStorageClient = Depends(get_storage_client),
):
    try:
        plugin_result = plugin_result_service.get_plugin_result(db, plugin_result_id)
        spec = download_service.plugin_raw_output_download_spec(plugin_result, get_settings())
    except NotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except ValidationError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    return storage_download_response(spec, storage_client)


@router.get("/plugin-results/{plugin_result_id}", response_model=PluginResultRead)
def get_plugin_result(plugin_result_id: UUID, db: Session = Depends(get_db)):
    try:
        return plugin_result_service.get_plugin_result(db, plugin_result_id)
    except NotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
