"""Tests for notification backends."""

from app.services import notifications
from app.services.notifications import (
    ConsoleNotifier,
    EmailNotifier,
    SlackNotifier,
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
        "kev": True,
        "epss": 0.97,
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


def test_slack_notifier_posts_text(monkeypatch):
    captured = {}

    def fake_post(url, json, timeout):
        captured["url"] = url
        captured["json"] = json

    monkeypatch.setattr(notifications.httpx, "post", fake_post)
    SlackNotifier("https://slack.example.com/hook").notify(FINDINGS)

    assert captured["url"] == "https://slack.example.com/hook"
    text = captured["json"]["text"]
    assert "CVE-2024-1" in text
    assert "KEV" in text
    assert "EPSS 0.97" in text


def test_slack_notifier_swallows_http_errors(monkeypatch):
    import httpx

    def boom(*args, **kwargs):
        raise httpx.ConnectError("down")

    monkeypatch.setattr(notifications.httpx, "post", boom)
    SlackNotifier("https://slack.example.com/hook").notify(FINDINGS)


def test_email_notifier_sends_message(monkeypatch):
    sent = {}

    class FakeSMTP:
        def __init__(self, host, port, timeout):
            sent["host"] = host
            sent["port"] = port

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def starttls(self):
            sent["tls"] = True

        def login(self, username, password):
            sent["login"] = (username, password)

        def send_message(self, message):
            sent["subject"] = message["Subject"]
            sent["to"] = message["To"]
            sent["body"] = message.get_content()

    monkeypatch.setattr(notifications.smtplib, "SMTP", FakeSMTP)

    EmailNotifier(
        host="smtp.example.com",
        port=587,
        sender="cve@example.com",
        recipients=["ops@example.com"],
        username="user",
        password="pass",
        use_tls=True,
    ).notify(FINDINGS)

    assert sent["host"] == "smtp.example.com"
    assert sent["tls"] is True
    assert sent["login"] == ("user", "pass")
    assert sent["to"] == "ops@example.com"
    assert "CVE-2024-1" in sent["body"]


def test_email_notifier_swallows_smtp_errors(monkeypatch):
    def boom(*args, **kwargs):
        raise OSError("connection refused")

    monkeypatch.setattr(notifications.smtplib, "SMTP", boom)
    EmailNotifier(
        host="smtp.example.com",
        port=587,
        sender="cve@example.com",
        recipients=["ops@example.com"],
    ).notify(FINDINGS)


def test_build_notifiers_includes_slack_and_email(monkeypatch):
    monkeypatch.setenv("NOTIFY_CONSOLE", "false")
    monkeypatch.delenv("NOTIFY_WEBHOOK_URL", raising=False)
    monkeypatch.setenv("NOTIFY_SLACK_WEBHOOK_URL", "https://slack.example.com/hook")
    monkeypatch.setenv("NOTIFY_EMAIL_HOST", "smtp.example.com")
    monkeypatch.setenv("NOTIFY_EMAIL_FROM", "cve@example.com")
    monkeypatch.setenv("NOTIFY_EMAIL_TO", "ops@example.com, sec@example.com")

    notifiers = build_notifiers_from_env()

    assert any(isinstance(n, SlackNotifier) for n in notifiers)
    email = next(n for n in notifiers if isinstance(n, EmailNotifier))
    assert email.recipients == ["ops@example.com", "sec@example.com"]
