# Readiness endpoint tests.

from fastapi.testclient import TestClient

from app.api.v1.endpoints import health
from app.main import app


def test_ready_returns_safe_ok_payload(monkeypatch) -> None:
    monkeypatch.setattr(health, "_check_database", lambda: "ok")
    monkeypatch.setattr(health, "_check_redis", lambda settings: "ok")
    monkeypatch.setattr(health, "_check_object_storage", lambda settings: "ok")

    response = TestClient(app).get("/ready")

    assert response.status_code == 200
    payload = response.json()
    assert payload == {
        "status": "ready",
        "checks": {"database": "ok", "redis": "ok", "object_storage": "ok"},
    }
    response_text = response.text.lower()
    assert "redis://" not in response_text
    assert "postgresql" not in response_text
    assert "minio" not in response_text
    assert "change-me" not in response_text
    assert "secret" not in response_text
    assert "/tmp" not in response_text


def test_ready_reports_not_ready_without_leaking_dependency_details(monkeypatch) -> None:
    monkeypatch.setattr(health, "_check_database", lambda: "ok")

    def fail_redis(settings):
        raise RuntimeError("redis://:very-secret@example.internal/0")

    monkeypatch.setattr(health, "_check_redis", fail_redis)
    monkeypatch.setattr(health, "_check_object_storage", lambda settings: "ok")

    response = TestClient(app).get("/ready")

    assert response.status_code == 503
    payload = response.json()
    assert payload == {
        "status": "not_ready",
        "checks": {"database": "ok", "redis": "error", "object_storage": "ok"},
    }
    response_text = response.text.lower()
    assert "very-secret" not in response_text
    assert "redis://" not in response_text
    assert "example.internal" not in response_text
