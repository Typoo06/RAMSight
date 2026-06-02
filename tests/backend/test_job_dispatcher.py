# Analysis job dispatcher tests.

from uuid import uuid4

import pytest

from app.services.job_dispatcher import ANALYSIS_TASK_NAME, AnalysisJobDispatchError, AnalysisJobDispatcher


class FakeCelery:
    def __init__(self) -> None:
        self.calls = []

    def send_task(self, name: str, args: list[str]) -> None:
        self.calls.append({"name": name, "args": args})


class FailingCelery:

    def send_task(self, name: str, args: list[str]) -> None:
        raise RuntimeError("broker unavailable")


def test_dispatcher_enqueues_analysis_task_without_live_redis() -> None:
    fake_celery = FakeCelery()
    dispatcher = AnalysisJobDispatcher(celery_app=fake_celery)
    job_id = uuid4()

    dispatcher.dispatch(job_id)

    assert fake_celery.calls == [{"name": ANALYSIS_TASK_NAME, "args": [str(job_id)]}]


def test_dispatcher_wraps_celery_failures() -> None:
    dispatcher = AnalysisJobDispatcher(celery_app=FailingCelery())

    with pytest.raises(AnalysisJobDispatchError) as exc_info:
        dispatcher.dispatch(uuid4())

    assert "RAMSight could not queue" in str(exc_info.value)
