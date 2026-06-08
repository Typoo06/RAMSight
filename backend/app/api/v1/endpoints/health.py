# Health and readiness endpoints.

from fastapi import APIRouter, Depends, Response, status
from redis import Redis
from sqlalchemy import text

from app.core.config import Settings, get_settings
from app.db.session import engine
from app.storage.client import ObjectStorageClient

router = APIRouter()


@router.get("/health")
def health_check(settings: Settings = Depends(get_settings)) -> dict[str, str]:
    return {"status": "ok", "environment": settings.app_env}


def _check_database() -> str:
    with engine.connect() as connection:
        connection.execute(text("SELECT 1"))
    return "ok"


def _check_redis(settings: Settings) -> str:
    client = Redis.from_url(settings.redis_url, socket_connect_timeout=2, socket_timeout=2)
    try:
        client.ping()
    finally:
        client.close()
    return "ok"


def _check_object_storage(settings: Settings) -> str:
    storage_client = ObjectStorageClient(settings=settings)
    required_buckets = (
        settings.minio_bucket_evidence,
        settings.minio_bucket_raw_outputs,
        settings.minio_bucket_reports,
    )
    for bucket_name in required_buckets:
        if not storage_client.client.bucket_exists(bucket_name):
            return "error"
    return "ok"


def _safe_check(check) -> str:
    try:
        return check()
    except Exception:
        return "error"


@router.get("/ready")
def readiness_check(response: Response, settings: Settings = Depends(get_settings)) -> dict[str, object]:
    checks = {
        "database": _safe_check(_check_database),
        "redis": _safe_check(lambda: _check_redis(settings)),
        "object_storage": _safe_check(lambda: _check_object_storage(settings)),
    }
    ready = all(result == "ok" for result in checks.values())
    if not ready:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    return {"status": "ready" if ready else "not_ready", "checks": checks}
