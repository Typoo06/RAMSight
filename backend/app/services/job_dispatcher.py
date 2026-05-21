"""Analysis job dispatch abstraction for future Celery integration."""

from uuid import UUID


class AnalysisJobDispatcher:
    """No-op dispatcher stub for Task 6A."""

    def dispatch(self, job_id: UUID) -> None:
        """Dispatch an analysis job later when Task 6B wires Celery."""
        return None


def get_analysis_job_dispatcher() -> AnalysisJobDispatcher:
    """Return the current analysis job dispatcher."""
    return AnalysisJobDispatcher()
