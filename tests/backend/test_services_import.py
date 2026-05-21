# Service import smoke tests.

from app.services import analysis_job_service, case_service, evidence_service, ioc_service, report_service, risk_finding_service
from app.services.job_dispatcher import AnalysisJobDispatcher


def test_services_import() -> None:
    assert case_service.create_case is not None
    assert evidence_service.register_evidence is not None
    assert analysis_job_service.create_analysis_job is not None
    assert ioc_service.list_iocs is not None
    assert risk_finding_service.list_risk_findings is not None
    assert report_service.list_reports is not None
    assert AnalysisJobDispatcher().dispatch is not None
