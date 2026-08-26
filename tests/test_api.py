from fastapi.testclient import TestClient
from backend.app import app

client = TestClient(app)


def test_root_endpoint():
    response = client.get("/")
    assert response.status_code == 200
    assert response.json() == {"message": "Compliance engine is alive"}


def test_login_fails_with_bad_credentials():
    response = client.post("/auth/login", data={"username": "nope", "password": "wrong"})
    assert response.status_code == 401  # failed login must be 401, not a 200 with an error field
    assert "access_token" not in response.json()

def test_upload_logs_requires_auth():
    response = client.post("/upload-logs")
    assert response.status_code in (401, 422)  # 422 if no file attached, 401 if auth checked first


def test_rules_creation_requires_auth():
    response = client.post("/rules", json={
        "name": "test_rule",
        "description": "test",
        "framework": "TEST",
        "severity": "LOW",
        "remediation": "test",
        "condition": []
    })
    assert response.status_code == 401