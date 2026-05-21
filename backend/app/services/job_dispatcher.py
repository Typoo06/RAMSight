# Analysis job dispatch abstraction for Celery integration.

from uuid import UUID

from celery import Celery

from app.core.celery import celery_sender

ANALYSIS_TASK_NAME = "app.tasks.analysis.run_analysis_job"


class AnalysisJobDispatcher:

    def __init__(self, celery_app: Celery | None = None) -> None:
        self.celery_app = celery_app or celery_sender

    def dispatch(self, job_id: UUID) -> None:
        self.celery_app.send_task(ANALYSIS_TASK_NAME, args=[str(job_id)])


def get_analysis_job_dispatcher() -> AnalysisJobDispatcher:
    return AnalysisJobDispatcher()
