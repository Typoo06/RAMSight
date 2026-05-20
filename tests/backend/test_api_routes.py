"""Route registration tests for the backend API scaffold."""

from app.main import app


def test_expected_routes_are_registered() -> None:
    routes = {route.path for route in app.routes}

    assert "/health" in routes
    assert "/api/v1/cases" in routes
    assert "/api/v1/evidences" in routes
    assert "/api/v1/analysis-jobs" in routes
    assert "/api/v1/iocs" in routes
    assert "/api/v1/reports" in routes


def test_placeholder_endpoints_return_empty_items() -> None:
    endpoint_by_path = {route.path: route.endpoint for route in app.routes}

    assert endpoint_by_path["/api/v1/cases"]() == {"items": []}
    assert endpoint_by_path["/api/v1/evidences"]() == {"items": []}
    assert endpoint_by_path["/api/v1/analysis-jobs"]() == {"items": []}
    assert endpoint_by_path["/api/v1/iocs"]() == {"items": []}
    assert endpoint_by_path["/api/v1/reports"]() == {"items": []}
