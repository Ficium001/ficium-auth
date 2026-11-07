"""The real app adds the transport/security defaults to every response."""
from fastapi.testclient import TestClient

from src.main import app


def test_security_defaults_on_every_response() -> None:
    r = TestClient(app).get("/health/live")
    assert r.headers["strict-transport-security"] == "max-age=63072000; includeSubDomains"
    assert r.headers["x-content-type-options"] == "nosniff"
