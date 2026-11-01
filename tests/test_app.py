"""HTTP-level tests for the keyforge portal."""
import pytest
from fastapi.testclient import TestClient

from keyforge import app as appmod


@pytest.fixture
def client():
    appmod.store = appmod.KeyStore()
    appmod.limiter = appmod.RateLimiter()
    return TestClient(appmod.app)


class TestCreate:
    def test_creates_and_returns_raw_key(self, client):
        r = client.post("/api/keys", json={"name": "ci"})
        assert r.status_code == 200
        assert r.json()["key"].startswith("kf_live_")

    def test_rejects_blank_name(self, client):
        assert client.post("/api/keys", json={"name": "  "}).status_code == 400

    def test_rejects_zero_rate_limit(self, client):
        assert client.post("/api/keys",
                           json={"name": "x", "rate_limit_per_min": 0}).status_code == 400

    def test_list_never_returns_raw_key(self, client):
        raw = client.post("/api/keys", json={"name": "ci"}).json()["key"]
        body = client.get("/api/keys").text
        assert raw not in body, "raw key leaked through the list endpoint"


class TestProtected:
    def test_valid_key_allowed(self, client):
        raw = client.post("/api/keys", json={"name": "ci"}).json()["key"]
        r = client.get("/api/protected", headers={"Authorization": f"Bearer {raw}"})
        assert r.status_code == 200
        assert r.json()["ok"] is True

    def test_missing_key_is_401(self, client):
        assert client.get("/api/protected").status_code == 401

    def test_bad_key_is_401(self, client):
        r = client.get("/api/protected", headers={"Authorization": "Bearer nope"})
        assert r.status_code == 401

    def test_revoked_key_is_401(self, client):
        created = client.post("/api/keys", json={"name": "ci"}).json()
        client.delete(f"/api/keys/{created['id']}")
        r = client.get("/api/protected",
                       headers={"Authorization": f"Bearer {created['key']}"})
        assert r.status_code == 401

    def test_rate_limit_returns_429(self, client):
        raw = client.post("/api/keys",
                          json={"name": "ci", "rate_limit_per_min": 2}).json()["key"]
        h = {"Authorization": f"Bearer {raw}"}
        assert client.get("/api/protected", headers=h).status_code == 200
        assert client.get("/api/protected", headers=h).status_code == 200
        r = client.get("/api/protected", headers=h)
        assert r.status_code == 429
        assert r.headers.get("retry-after") == "60"

    def test_remaining_decrements(self, client):
        raw = client.post("/api/keys",
                          json={"name": "ci", "rate_limit_per_min": 5}).json()["key"]
        h = {"Authorization": f"Bearer {raw}"}
        assert client.get("/api/protected", headers=h).json()["remaining"] == 4


class TestRevoke:
    def test_revoke_unknown_is_404(self, client):
        assert client.delete("/api/keys/deadbeef").status_code == 404

    def test_revoke_marks_revoked(self, client):
        kid = client.post("/api/keys", json={"name": "ci"}).json()["id"]
        client.delete(f"/api/keys/{kid}")
        keys = client.get("/api/keys").json()["keys"]
        assert [k for k in keys if k["id"] == kid][0]["revoked"] is True


class TestIndex:
    def test_renders(self, client):
        assert client.get("/").status_code == 200
