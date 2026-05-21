# Route registration tests for the backend API scaffold.

from app.main import app


def test_expected_routes_are_registered() -> None:
    routes = {route.path for route in app.routes}

    assert "/health" in routes
    assert "/api/v1/cases" in routes
    assert "/api/v1/cases/{case_id}" in routes
    assert "/api/v1/evidences" in routes
    assert "/api/v1/evidences/upload" in routes
    assert "/api/v1/evidences/register" in routes
    assert "/api/v1/evidences/{evidence_id}" in routes
    assert "/api/v1/analysis-jobs" in routes
    assert "/api/v1/analysis-jobs/{job_id}" in routes
    assert "/api/v1/analysis-jobs/{job_id}/status" in routes
    assert "/api/v1/iocs" in routes
    assert "/api/v1/risk-findings" in routes
    assert "/api/v1/reports" in routes
    assert "/api/v1/reports/{report_id}" in routes
