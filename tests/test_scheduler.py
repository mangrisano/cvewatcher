"""Tests for the periodic monitoring cycle and finding extraction."""

import asyncio

from app.services import scheduler
from app.services.scheduler import _extract_new_findings, run_monitoring_cycle


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
        },
    ]
}


class RecordingNotifier:
    def __init__(self):
        self.received = None

    def notify(self, findings):
        self.received = findings


def test_extract_new_findings_flattens_results():
    findings = _extract_new_findings(MONITORING_RESULTS)
    assert len(findings) == 1
    assert findings[0]["cve_id"] == "CVE-2024-1"
    assert findings[0]["asset_name"] == "nginx"
    assert findings[0]["user_email"] == "u@example.com"


def test_run_monitoring_cycle_dispatches_findings(monkeypatch):
    class FakeService:
        def __init__(self, db):
            pass

        async def monitor_all_assets(self):
            return MONITORING_RESULTS

    class FakeSession:
        def close(self):
            pass

    monkeypatch.setattr(scheduler, "CVEMonitoringService", FakeService)
    monkeypatch.setattr(scheduler, "SessionLocal", lambda: FakeSession())

    recorder = RecordingNotifier()
    findings = asyncio.run(run_monitoring_cycle(notifiers=[recorder]))

    assert len(findings) == 1
    assert recorder.received == findings


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
