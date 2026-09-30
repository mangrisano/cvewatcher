"""Tests for the periodic monitoring cycle and alert extraction."""

import asyncio

from app.services import scheduler
from app.services.alerts import extract_alerts
from app.services.scheduler import run_monitoring_cycle


MONITORING_RESULTS = {
    "asset_results": [
        {
            "asset_name": "nginx",
            "asset_version": "1.20.0",
            "user_email": "u@example.com",
            "new_vulnerabilities": [
                {
                    "cve_id": "CVE-2024-1",
                    "severity": "HIGH",
                    "score": 7.5,
                    "cve_url": "https://example.com/CVE-2024-1",
                    "publish_date": None,
                }
            ],
        },
        {
            "asset_name": "openssl",
            "asset_version": "3.0",
            "user_email": "u@example.com",
            "new_vulnerabilities": [],
            "escalations": [
                {
                    "cve_id": "CVE-2023-9",
                    "severity": "CRITICAL",
                    "alert": "severity_raised",
                    "previous_severity": "UNKNOWN",
                    "status": "acknowledged",
                }
            ],
        },
    ]
}


def test_extract_alerts_flattens_new_findings_and_escalations():
    alerts = extract_alerts(MONITORING_RESULTS)
    assert [a["cve_id"] for a in alerts] == ["CVE-2024-1", "CVE-2023-9"]
    new, raised = alerts
    assert new["alert"] == "new"
    assert new["asset_name"] == "nginx"
    assert new["user_email"] == "u@example.com"
    assert new["status"] == "open"
    assert raised["alert"] == "severity_raised"
    assert raised["previous_severity"] == "UNKNOWN"
    assert raised["status"] == "acknowledged"
    assert raised["asset_name"] == "openssl"


def test_run_monitoring_cycle_delivers_alerts(monkeypatch):
    class FakeService:
        def __init__(self, db):
            pass

        async def monitor_all_assets(self):
            return MONITORING_RESULTS

    class FakeSession:
        def close(self):
            pass

    delivered = {}

    async def fake_deliver(db, alerts, notifiers):
        delivered["alerts"] = alerts
        delivered["notifiers"] = notifiers

    monkeypatch.setattr(scheduler, "CVEMonitoringService", FakeService)
    monkeypatch.setattr(scheduler, "SessionLocal", lambda: FakeSession())
    monkeypatch.setattr(scheduler, "deliver_alerts", fake_deliver)

    admin = object()
    alerts = asyncio.run(run_monitoring_cycle(notifiers=[admin]))

    assert len(alerts) == 2
    assert delivered == {"alerts": alerts, "notifiers": [admin]}


def test_run_monitoring_cycle_handles_service_error(monkeypatch):
    class FakeService:
        def __init__(self, db):
            pass

        async def monitor_all_assets(self):
            raise RuntimeError("nvd down")

    closed = {"value": False}

    class FakeSession:
        def close(self):
            closed["value"] = True

    monkeypatch.setattr(scheduler, "CVEMonitoringService", FakeService)
    monkeypatch.setattr(scheduler, "SessionLocal", lambda: FakeSession())

    findings = asyncio.run(run_monitoring_cycle(notifiers=[]))

    assert findings == []
    assert closed["value"] is True
