"""Tests for per-user alert routing, escalation detection and alert settings."""

import asyncio
from types import SimpleNamespace

import pytest

from app.database.connection import SessionLocal
from app.database.models import Asset, AssetCVE, CVE, NotificationPreference, User
from app.services import alerts, notifications
from app.services.alerts import AlertPreferences, deliver_alerts, observe, wants
from app.services.cve_monitoring import CVEMonitoringService
from app.services.notifications import EmailNotifier
from app.services.sources import SourceResult


def _alert(**overrides):
    return {
        "alert": "new",
        "cve_id": "CVE-2024-1",
        "severity": "MEDIUM",
        "kev": False,
        "status": "open",
        **overrides,
    }


DEFAULTS = AlertPreferences()


@pytest.mark.parametrize(
    "alert, prefs, expected",
    [
        (_alert(severity="HIGH"), DEFAULTS, True),
        (_alert(severity="MEDIUM"), DEFAULTS, False),
        (_alert(severity="LOW", kev=True), DEFAULTS, True),
        (
            _alert(severity="LOW", kev=True),
            AlertPreferences(always_kev=False),
            False,
        ),
        (_alert(severity=None), AlertPreferences(min_severity="LOW"), True),
        (_alert(severity="CRITICAL", status="fixed"), DEFAULTS, False),
        (_alert(severity="CRITICAL", status="false_positive"), DEFAULTS, False),
        (_alert(severity="CRITICAL", status="accepted_risk"), DEFAULTS, False),
        (_alert(alert="kev_added", kev=True, status="accepted_risk"), DEFAULTS, True),
        (
            _alert(alert="kev_added", kev=True),
            AlertPreferences(escalations=False),
            False,
        ),
        (
            _alert(alert="severity_raised", severity="CRITICAL"),
            DEFAULTS,
            True,
        ),
    ],
)
def test_wants_applies_threshold_kev_status_and_escalation_preferences(
    alert, prefs, expected
):
    assert wants(alert, prefs) is expected


def _link(status="open", kev=None, severity=None):
    return SimpleNamespace(status=status, kev=kev, severity=severity)


def test_observe_records_a_silent_baseline():
    link = _link()
    assert observe(link, {"kev": True, "severity": "HIGH"}, kev_known=True) == []
    assert (link.kev, link.severity) == (True, "HIGH")


def test_observe_alerts_once_when_a_finding_enters_kev():
    link = _link(kev=False, severity="HIGH")
    finding = {"cve_id": "CVE-1", "kev": True, "severity": "HIGH"}
    [alert] = observe(link, finding, kev_known=True)
    assert alert["alert"] == "kev_added"
    assert link.kev is True
    assert observe(link, finding, kev_known=True) == []


def test_observe_ignores_kev_when_the_catalog_is_unavailable():
    link = _link(kev=None, severity="HIGH")
    observe(link, {"kev": False, "severity": "HIGH"}, kev_known=False)
    assert link.kev is None  # still a baseline once the catalog is back
    assert observe(link, {"kev": True, "severity": "HIGH"}, kev_known=True) == []


def test_observe_alerts_once_when_severity_rises():
    link = _link(kev=False, severity="UNKNOWN")
    finding = {"cve_id": "CVE-1", "kev": False, "severity": "CRITICAL"}
    [alert] = observe(link, finding, kev_known=True)
    assert alert["alert"] == "severity_raised"
    assert alert["previous_severity"] == "UNKNOWN"
    assert observe(link, finding, kev_known=True) == []
    # A drop is recorded without an alert.
    assert observe(link, {**finding, "severity": "LOW"}, kev_known=True) == []
    assert link.severity == "LOW"


@pytest.mark.parametrize("status", ["fixed", "false_positive", "accepted_risk"])
def test_observe_does_not_escalate_suppressed_findings_on_severity(status):
    link = _link(status=status, kev=False, severity="LOW")
    assert observe(link, {"kev": False, "severity": "CRITICAL"}, True) == []


def test_observe_reports_kev_for_accepted_risk_but_not_fixed():
    finding = {"kev": True, "severity": "HIGH"}
    assert observe(_link("accepted_risk", False, "HIGH"), finding, True)
    assert observe(_link("fixed", False, "HIGH"), finding, True) == []


class _Source:
    def __init__(self, findings):
        self.findings = findings

    async def search(self, asset, start, end, use_cache):
        return SourceResult(findings=[dict(f) for f in self.findings])


class _Enricher:
    kev_catalog_loaded = True

    def __init__(self):
        self.kev = set()

    async def enrich(self, findings):
        for finding in findings:
            finding["kev"] = finding["cve_id"] in self.kev
            finding["epss"] = None
        return findings


_OWNER = "escalation-owner@example.com"
_CVE = "CVE-2099-7777"


def test_monitor_asset_reports_new_findings_then_escalations():
    db = SessionLocal()
    try:
        asset = Asset(name="escalation-app", version="1.0", user_email=_OWNER)
        db.add(asset)
        db.commit()
        db.refresh(asset)
        source = _Source([{"cve_id": _CVE, "severity": None, "summary": "x"}])
        enricher = _Enricher()
        service = CVEMonitoringService(db, sources=[source], enricher=enricher)

        first = asyncio.run(service.monitor_asset(asset))
        assert [v["cve_id"] for v in first["new_vulnerabilities"]] == [_CVE]
        assert first["escalations"] == []

        # Nothing changed: no alerts at all.
        second = asyncio.run(service.monitor_asset(asset))
        assert second["new_vulnerabilities"] == second["escalations"] == []

        source.findings = [{"cve_id": _CVE, "severity": "CRITICAL", "summary": "x"}]
        enricher.kev.add(_CVE)
        third = asyncio.run(service.monitor_asset(asset))
        assert [e["alert"] for e in third["escalations"]] == ["kev_added"]

        source.findings = [{"cve_id": _CVE, "severity": "CRITICAL", "summary": "x"}]
        assert asyncio.run(service.monitor_asset(asset))["escalations"] == []
    finally:
        db.query(AssetCVE).filter(AssetCVE.cve_id == _CVE).delete()
        db.query(CVE).filter(CVE.id == _CVE).delete()
        db.query(Asset).filter(Asset.user_email == _OWNER).delete()
        db.commit()
        db.close()


class _Recorder:
    def __init__(self):
        self.received = []

    async def notify(self, findings):
        self.received.extend(findings)
        return True


def test_deliver_alerts_sends_each_owner_only_their_filtered_alerts(monkeypatch):
    db = SessionLocal()
    anna = User(
        username="deliver-anna", email="deliver-anna@example.com", password_hash="x"
    )
    bob = User(
        username="deliver-bob", email="deliver-bob@example.com", password_hash="x"
    )
    try:
        db.add_all([anna, bob])
        db.commit()
        db.add(NotificationPreference(user_id=bob.id, min_severity="LOW"))
        db.commit()

        personal = {}

        def fake_personal(email, prefs, smtp):
            personal[email] = {"email": _Recorder(), "slack": _Recorder()}
            return personal[email]

        monkeypatch.setattr(alerts, "personal_notifiers", fake_personal)
        admin = _Recorder()
        admin_email = EmailNotifier(
            host="smtp", port=25, sender="s@x", recipients=["Deliver-Bob@example.com"]
        )
        monkeypatch.setattr(admin_email, "notify", _Recorder().notify)

        found = [
            _alert(cve_id="CVE-A1", severity="LOW", user_email=anna.email),
            _alert(cve_id="CVE-A2", severity="CRITICAL", user_email=anna.email),
            _alert(cve_id="CVE-B1", severity="LOW", user_email=bob.email),
        ]
        asyncio.run(deliver_alerts(db, found, [admin, admin_email]))

        assert [a["cve_id"] for a in admin.received] == ["CVE-A1", "CVE-A2", "CVE-B1"]
        anna_channels = personal[anna.email]
        assert [a["cve_id"] for a in anna_channels["email"].received] == ["CVE-A2"]
        assert [a["cve_id"] for a in anna_channels["slack"].received] == ["CVE-A2"]
        # Bob already gets the admin email feed, so no personal email copy.
        bob_channels = personal[bob.email]
        assert "email" not in bob_channels
        assert [a["cve_id"] for a in bob_channels["slack"].received] == ["CVE-B1"]
    finally:
        db.query(NotificationPreference).filter(
            NotificationPreference.user_id.in_([anna.id, bob.id])
        ).delete()
        db.query(User).filter(User.id.in_([anna.id, bob.id])).delete()
        db.commit()
        db.close()


def _login(client, username):
    email = f"{username}@example.com"
    client.post(
        "/auth/register",
        json={"username": username, "email": email, "password": "Password123"},
    )
    token = client.post(
        "/auth/login", json={"email": email, "password": "Password123"}
    ).json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


def test_notification_settings_defaults_and_update(client):
    headers = _login(client, "notif-carla")
    settings = client.get("/user/notifications", headers=headers).json()
    assert settings == {
        "email": "notif-carla@example.com",
        "email_available": False,
        "min_severity": "HIGH",
        "always_kev": True,
        "escalations": True,
        "slack_configured": False,
        "teams_configured": False,
        "discord_configured": False,
        "telegram_configured": False,
    }

    slack = "https://hooks.slack.com/services/T0/B0/secret"
    response = client.put(
        "/user/notifications",
        headers=headers,
        json={"min_severity": "CRITICAL", "slack_webhook_url": slack},
    )
    assert response.status_code == 200
    assert response.json()["min_severity"] == "CRITICAL"
    assert response.json()["slack_configured"] is True
    assert "secret" not in response.text

    # Fields not sent are kept; an empty URL removes the webhook.
    response = client.put(
        "/user/notifications", headers=headers, json={"slack_webhook_url": ""}
    )
    assert response.json()["slack_configured"] is False
    assert response.json()["min_severity"] == "CRITICAL"


def test_telegram_settings_need_token_and_chat_and_can_be_removed(client):
    headers = _login(client, "notif-fabio")
    token = "123456789:" + "A" * 35
    response = client.put(
        "/user/notifications",
        headers=headers,
        json={"telegram_bot_token": token, "telegram_chat_id": "-100123"},
    )
    assert response.json()["telegram_configured"] is True
    assert token not in response.text

    response = client.put(
        "/user/notifications",
        headers=headers,
        json={"telegram_bot_token": "", "telegram_chat_id": ""},
    )
    assert response.json()["telegram_configured"] is False


@pytest.mark.parametrize(
    "payload",
    [
        {"slack_webhook_url": "http://hooks.slack.com/services/x"},
        {"teams_webhook_url": "https://169.254.169.254/latest/meta-data"},
        {"discord_webhook_url": "https://discord.com.evil.com/api/webhooks/1/a"},
        {"min_severity": "EVERYTHING"},
        {"telegram_bot_token": "123456789:" + "A" * 35},
        {"telegram_bot_token": "123456789:" + "A" * 35, "telegram_chat_id": ""},
        {"telegram_bot_token": "not-a-token", "telegram_chat_id": "42"},
    ],
)
def test_notification_settings_reject_invalid_values(client, payload):
    headers = _login(client, "notif-dario")
    response = client.put("/user/notifications", headers=headers, json=payload)
    assert response.status_code == 422


def test_test_notification_needs_a_channel_and_reports_results(client, monkeypatch):
    headers = _login(client, "notif-elena")
    response = client.post("/user/notifications/test", headers=headers)
    assert response.status_code == 400

    client.put(
        "/user/notifications",
        headers=headers,
        json={"discord_webhook_url": "https://discord.com/api/webhooks/1/abc"},
    )

    async def fake_post(url, **kwargs):
        return SimpleNamespace(is_success=True, status_code=204)

    monkeypatch.setattr(notifications, "_http_post", fake_post)
    response = client.post("/user/notifications/test", headers=headers)
    assert response.status_code == 200
    assert response.json() == {"results": {"discord": True}}

    for _ in range(4):
        client.post("/user/notifications/test", headers=headers)
    assert client.post("/user/notifications/test", headers=headers).status_code == 429
