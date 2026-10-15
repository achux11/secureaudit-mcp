"""Smoke tests for the FastAPI dashboard endpoints."""

from fastapi.testclient import TestClient

from secureaudit.webapp import app

client = TestClient(app)
FILES = ["erp_q3_export.csv", "legacy_billing_q3.csv", "rbac_audit_log.json"]


def test_health():
    assert client.get("/api/health").json()["status"] == "ok"


def test_full_scan_endpoint():
    body = client.post("/api/scan/full", json={"selected_files": FILES}).json()
    assert body["duplicate_group_count"] == 2
    assert body["rbac_finding_count"] == 3


def test_alert_dry_run_sends_metadata_only():
    body = client.post(
        "/api/alert",
        json={"webhook_url": "https://example.com/hook", "dry_run": True, "selected_files": FILES},
    ).json()
    assert body["ok"] and body["dry_run"] and not body["sent"]
    assert body["payload"]["finding_count"] == 5
