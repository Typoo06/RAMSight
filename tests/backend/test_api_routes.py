# Route registration tests for the backend API scaffold.

from app.main import app


def test_expected_routes_are_registered() -> None:
    routes = {route.path for route in app.routes}

    assert "/health" in routes
    assert "/ready" in routes
    assert "/api/v1/cases" in routes
    assert "/api/v1/cases/{case_id}" in routes
    assert "/api/v1/evidences" in routes
    assert "/api/v1/evidences/multipart/initiate" in routes
    assert "/api/v1/evidences/multipart/{session_id}/presign-part" in routes
    assert "/api/v1/evidences/multipart/{session_id}/parts" in routes
    assert "/api/v1/evidences/multipart/{session_id}/complete" in routes
    assert "/api/v1/evidences/multipart/{session_id}" in routes
    assert "/api/v1/evidences/uploads/initiate" in routes
    assert "/api/v1/evidences/uploads/{upload_id}/chunks/{chunk_index}" in routes
    assert "/api/v1/evidences/uploads/{upload_id}/complete" in routes
    assert "/api/v1/evidences/uploads/{upload_id}" in routes
    assert "/api/v1/evidences/upload" in routes
    assert "/api/v1/evidences/register" in routes
    assert "/api/v1/evidences/{evidence_id}" in routes
    assert "/api/v1/analysis-jobs" in routes
    assert "/api/v1/analysis-jobs/{job_id}" in routes
    assert "/api/v1/analysis-jobs/{job_id}/status" in routes
    assert "/api/v1/analysis-jobs/{job_id}/plugin-results" in routes
    assert "/api/v1/plugin-results/{plugin_result_id}" in routes
    assert "/api/v1/analysis-jobs/{job_id}/artifacts/processes" in routes
    assert "/api/v1/analysis-jobs/{job_id}/artifacts/commands" in routes
    assert "/api/v1/analysis-jobs/{job_id}/artifacts/network" in routes
    assert "/api/v1/analysis-jobs/{job_id}/artifacts/modules" in routes
    assert "/api/v1/analysis-jobs/{job_id}/artifacts/memory-regions" in routes
    assert "/api/v1/analysis-jobs/{job_id}/artifacts/yara-matches" in routes
    assert "/api/v1/analysis-jobs/{job_id}/iocs/export.json" in routes
    assert "/api/v1/analysis-jobs/{job_id}/iocs/export.csv" in routes
    assert "/api/v1/analysis-jobs/{job_id}/iocs/export.{export_format}" in routes
    assert "/api/v1/iocs" in routes
    assert "/api/v1/risk-findings" in routes
    assert "/api/v1/reports" in routes
    assert "/api/v1/reports/{report_id}" in routes
    assert "/api/v1/reports/{report_id}/download" in routes
