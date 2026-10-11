import uuid

from fastapi.testclient import TestClient

from backend.config import settings
from backend.database import execute
from backend.main import app
from backend.services.auth_service import auth_service


def test_authenticated_api_access(monkeypatch):
    username = f"auth_test_{uuid.uuid4().hex[:12]}"
    email = f"{username}@example.test"
    password = "a-long-test-password"
    monkeypatch.setattr(settings, "AUTH_ENABLED", True)
    monkeypatch.setattr(settings, "JWT_SECRET", "test-jwt-secret-that-is-long-enough-for-validation")

    execute(
        "INSERT INTO users (username, email, password_hash, role, is_active) VALUES (%s, %s, %s, %s, %s)",
        (username, email, auth_service.hash_password(password), "ANALYST", True),
    )
    try:
        with TestClient(app) as client:
            assert client.get("/api/auth/me").status_code == 401

            login = client.post("/api/auth/login", json={"username": username, "password": password})
            assert login.status_code == 200
            token = login.json()["access_token"]

            current_user = client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"})
            assert current_user.status_code == 200
            assert current_user.json()["username"] == username
    finally:
        execute("DELETE FROM users WHERE username = %s", (username,))
