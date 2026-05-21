"""MVP case API tests."""

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.api.deps import get_db
from app.main import app
from app.models import Base


@pytest.fixture()
def client():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    Base.metadata.create_all(bind=engine)

    def override_get_db():
        db = TestingSessionLocal()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db
    try:
        yield TestClient(app)
    finally:
        app.dependency_overrides.clear()
        Base.metadata.drop_all(bind=engine)


def test_create_list_get_case(client: TestClient) -> None:
    create_response = client.post(
        "/api/v1/cases",
        json={"case_code": "CASE-001", "name": "Demo case", "description": "MVP smoke"},
    )
    assert create_response.status_code == 201
    created = create_response.json()
    assert created["case_code"] == "CASE-001"
    assert created["created_by_id"] is None

    list_response = client.get("/api/v1/cases", params={"limit": 10, "offset": 0})
    assert list_response.status_code == 200
    assert list_response.json()["items"][0]["case_code"] == "CASE-001"

    get_response = client.get(f"/api/v1/cases/{created['id']}")
    assert get_response.status_code == 200
    assert get_response.json()["id"] == created["id"]


def test_duplicate_case_code_returns_409(client: TestClient) -> None:
    payload = {"case_code": "CASE-001", "name": "Demo case"}
    assert client.post("/api/v1/cases", json=payload).status_code == 201

    duplicate_response = client.post("/api/v1/cases", json=payload)

    assert duplicate_response.status_code == 409
