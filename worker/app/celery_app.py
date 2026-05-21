# Celery application entry point.

from celery import Celery

from app.core.config import get_settings

settings = get_settings()

celery_app = Celery(
    "memory_malware_triage_worker",
    broker=settings.celery_broker_url,
    backend=settings.celery_result_backend,
)

celery_app.conf.update(
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    imports=("app.tasks.analysis",),
    task_track_started=True,
    worker_prefetch_multiplier=1,
)
