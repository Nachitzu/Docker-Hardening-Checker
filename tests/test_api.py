"""Tests for the Flask web API."""
from __future__ import annotations

import json

import pytest

from app import app


@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as c:
        yield c


class TestHealth:
    def test_health(self, client):
        r = client.get("/api/health")
        assert r.status_code == 200
        assert r.get_json() == {"status": "ok"}


class TestAnalyze:
    def test_index_page(self, client):
        r = client.get("/")
        assert r.status_code == 200
        assert b"<h1>" in r.data

    def test_sample_endpoint(self, client):
        r = client.get("/api/sample?which=Dockerfile.bad")
        assert r.status_code == 200
        data = r.get_json()
        assert "FROM ubuntu" in data["content"]

    def test_sample_path_traversal_blocked(self, client):
        r = client.get("/api/sample?which=../requirements.txt")
        assert r.status_code == 404

    def test_analyze_json_dockerfile(self, client, bad_dockerfile):
        r = client.post(
            "/api/analyze",
            data=json.dumps({"kind": "dockerfile", "content": bad_dockerfile,
                             "filename": "Dockerfile.bad"}),
            content_type="application/json",
        )
        assert r.status_code == 200
        data = r.get_json()
        assert data["summary"]["total"] == 14

    def test_analyze_json_compose(self, client, bad_compose):
        r = client.post(
            "/api/analyze",
            data=json.dumps({"kind": "compose", "content": bad_compose,
                             "filename": "compose-bad.yml"}),
            content_type="application/json",
        )
        assert r.status_code == 200
        data = r.get_json()
        assert data["summary"]["total"] == 21

    def test_analyze_autodetect_kind(self, client, bad_dockerfile):
        r = client.post(
            "/api/analyze",
            data=json.dumps({"content": bad_dockerfile, "filename": "Dockerfile.bad"}),
            content_type="application/json",
        )
        assert r.status_code == 200
        data = r.get_json()
        assert data["target"] == "Dockerfile"

    def test_analyze_empty_payload_400(self, client):
        r = client.post(
            "/api/analyze",
            data=json.dumps({"content": ""}),
            content_type="application/json",
        )
        assert r.status_code == 400

    def test_analyze_unknown_kind_400(self, client, bad_dockerfile):
        r = client.post(
            "/api/analyze",
            data=json.dumps({"kind": "k8s-manifest", "content": bad_dockerfile}),
            content_type="application/json",
        )
        assert r.status_code == 400

    def test_analyze_form_upload(self, client, bad_dockerfile):
        r = client.post(
            "/api/analyze",
            data={"content": bad_dockerfile, "filename": "Dockerfile.bad",
                  "kind": "dockerfile"},
            content_type="multipart/form-data",
        )
        assert r.status_code == 200
        assert r.get_json()["summary"]["total"] == 14

    def test_analyze_returns_finding_shape(self, client, bad_dockerfile):
        r = client.post(
            "/api/analyze",
            data=json.dumps({"kind": "dockerfile", "content": bad_dockerfile}),
            content_type="application/json",
        )
        f = r.get_json()["findings"][0]
        for key in ("rule_id", "title", "severity", "description", "remediation",
                    "line", "snippet"):
            assert key in f
