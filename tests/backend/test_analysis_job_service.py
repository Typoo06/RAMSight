# Analysis job service tests.

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.models import Base, Case, Evidence
from app.models.enums import EvidenceSourceType, OSFamily
from app.schemas.analysis_job import AnalysisJobCreate
from app.services.analysis_job_service import create_analysis_job
from app.services.errors import ValidationError


class RecordingDispatcher:
    def __init__(self) -> None:
        self.dispatched = []

    def dispatch(self, job_id) -> None:
        self.dispatched.append(job_id)


@pytest.fixture()
def db_session():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    Base.metadata.create_all(bind=engine)
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()
        Base.metadata.drop_all(bind=engine)


def _create_case_and_evidence(db):
    case = Case(case_code="CASE-001", name="Demo case")
    db.add(case)
    db.flush()
    evidence = Evidence(
        case_id=case.id,
        source_type=EvidenceSourceType.MINIO_OBJECT.value,
        original_filename="sample.raw",
        storage_bucket="evidence",
        storage_key="case-1/evidence-1/sample.raw",
        os_family=OSFamily.WINDOWS.value,
        architecture="x64",
    )
    db.add(evidence)
    db.commit()
    db.refresh(case)
    db.refresh(evidence)
    return case, evidence


def test_create_analysis_job_with_valid_case_and_evidence(db_session) -> None:
    case, evidence = _create_case_and_evidence(db_session)
    dispatcher = RecordingDispatcher()

    job = create_analysis_job(
        db_session,
        AnalysisJobCreate(
            case_id=case.id,
            evidence_id=evidence.id,
            os_family=OSFamily.WINDOWS.value,
            plugin_profile="windows_default",
        ),
        dispatcher,
    )

    assert job.status == "queued"
    assert job.case_id == case.id
    assert job.evidence_id == evidence.id
    assert dispatcher.dispatched == [job.id]


def test_reject_analysis_job_when_evidence_does_not_belong_to_case(db_session) -> None:
    case, evidence = _create_case_and_evidence(db_session)
    other_case = Case(case_code="CASE-002", name="Other case")
    db_session.add(other_case)
    db_session.commit()
    db_session.refresh(other_case)

    with pytest.raises(ValidationError):
        create_analysis_job(
            db_session,
            AnalysisJobCreate(case_id=other_case.id, evidence_id=evidence.id, os_family=OSFamily.WINDOWS.value),
            RecordingDispatcher(),
        )
