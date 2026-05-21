# Celery sender configuration for backend dispatching.

from celery import Celery

from app.core.config import get_settings

settings = get_settings()

celery_sender = Celery(
    "memory_malware_triage_backend",
    broker=settings.celery_broker_url,
    backend=settings.celery_result_backend,
)
celery_sender.conf.update(task_serializer="json", result_serializer="json", accept_content=["json"])

