# Shared response helpers for DB-backed object downloads.

from fastapi import HTTPException, status
from fastapi.responses import Response, StreamingResponse

from app.services.download_service import DownloadSpec
from app.services.result_export_service import ExportFile
from app.storage.client import ObjectStorageClient, StorageDownloadError, StorageObjectNotFoundError


def storage_download_response(spec: DownloadSpec, storage_client: ObjectStorageClient) -> StreamingResponse:
    try:
        storage_object = storage_client.open_object_stream(spec.bucket, spec.key)
    except StorageObjectNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=spec.missing_message) from exc
    except StorageDownloadError as exc:
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail="RAMSight could not download the generated file.") from exc

    headers = {"Content-Disposition": f'attachment; filename="{spec.filename}"'}
    if storage_object.size_bytes is not None:
        headers["Content-Length"] = str(storage_object.size_bytes)

    return StreamingResponse(storage_object.iter_chunks(), media_type=spec.media_type, headers=headers)


def generated_export_response(export_file: ExportFile) -> Response:
    headers = {"Content-Disposition": f'attachment; filename="{export_file.filename}"'}
    return Response(content=export_file.content, media_type=export_file.media_type, headers=headers)
