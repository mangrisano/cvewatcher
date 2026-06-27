"""Tests for notification backends."""

from app.services import notifications
from app.services.notifications import (
    ConsoleNotifier,
    WebhookNotifier,
    build_notifiers_from_env,
    dispatch,
)


FINDINGS = [
    {
        "asset_name": "nginx",
        "asset_version": "1.20.0",
        "user_email": "u@example.com",
        "cve_id": "CVE-2024-1",
        "severity": "HIGH",
        "score": 7.5,
        "cve_url": "https://example.com/CVE-2024-1",
        "publish_date": None,
    }
]


class RecordingNotifier:
    def __init__(self):
        self.received = None

    def notify(self, findings):
        self.received = findings


def test_console_notifier_does_not_raise():
    ConsoleNotifier().notify(FINDINGS)


def test_webhook_notifier_posts_findings(monkeypatch):
    captured = {}

    def fake_post(url, json, timeout):
        captured["url"] = url
        captured["json"] = json
        captured["timeout"] = timeout

    monkeypatch.setattr(notifications.httpx, "post", fake_post)
    WebhookNotifier("https://hook.example.com", timeout=7).notify(FINDINGS)

    assert captured["url"] == "https://hook.example.com"
    assert captured["json"] == {"findings": FINDINGS}
    assert captured["timeout"] == 7


def test_webhook_notifier_swallows_http_errors(monkeypatch):
    import httpx

    def boom(*args, **kwargs):
        raise httpx.ConnectError("down")

    monkeypatch.setattr(notifications.httpx, "post", boom)
    # Should not raise.
    WebhookNotifier("https://hook.example.com").notify(FINDINGS)


def test_dispatch_skips_when_no_findings():
    recorder = RecordingNotifier()
    dispatch([], [recorder])
    assert recorder.received is None


def test_dispatch_sends_to_all_notifiers():
    recorder = RecordingNotifier()
    dispatch(FINDINGS, [recorder])
    assert recorder.received == FINDINGS


def test_dispatch_isolates_failing_notifier():
    class FailingNotifier:
        def notify(self, findings):
            raise RuntimeError("boom")

    recorder = RecordingNotifier()
    # The failing notifier must not prevent the recorder from being called.
    dispatch(FINDINGS, [FailingNotifier(), recorder])
    assert recorder.received == FINDINGS


def test_build_notifiers_from_env(monkeypatch):
    monkeypatch.setenv("NOTIFY_CONSOLE", "true")
    monkeypatch.delenv("NOTIFY_WEBHOOK_URL", raising=False)
    notifiers = build_notifiers_from_env()
    assert any(isinstance(n, ConsoleNotifier) for n in notifiers)
    assert not any(isinstance(n, WebhookNotifier) for n in notifiers)

    monkeypatch.setenv("NOTIFY_CONSOLE", "false")
    monkeypatch.setenv("NOTIFY_WEBHOOK_URL", "https://hook.example.com")
    notifiers = build_notifiers_from_env()
    assert not any(isinstance(n, ConsoleNotifier) for n in notifiers)
    assert any(isinstance(n, WebhookNotifier) for n in notifiers)
