"""Tests for notification backends."""

import asyncio
from types import SimpleNamespace

import pytest

from app.config import get_settings
from app.services import notifications
from app.services.notifications import (
    ConsoleNotifier,
    DiscordNotifier,
    EmailNotifier,
    SlackNotifier,
    TeamsNotifier,
    TelegramNotifier,
    WebhookNotifier,
    build_notifiers_from_env,
    check_telegram_chat_id,
    check_telegram_token,
    check_webhook_url,
    dispatch,
)

OK = SimpleNamespace(is_success=True, status_code=200)


def _as_async(fn):
    async def wrapper(*args, **kwargs):
        return fn(*args, **kwargs)

    return wrapper


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

    async def notify(self, findings):
        self.received = findings


def test_console_notifier_does_not_raise():
    asyncio.run(ConsoleNotifier().notify(FINDINGS))


def test_webhook_notifier_posts_findings(monkeypatch):
    captured = {}

    def fake_post(url, json, timeout):
        captured["url"] = url
        captured["json"] = json
        captured["timeout"] = timeout
        return OK

    monkeypatch.setattr(notifications, "_http_post", _as_async(fake_post))
    delivered = asyncio.run(
        WebhookNotifier("https://hook.example.com", timeout=7).notify(FINDINGS)
    )

    assert delivered is True
    assert captured["url"] == "https://hook.example.com"
    assert captured["json"] == {"findings": FINDINGS}
    assert captured["timeout"] == 7


def test_webhook_notifier_reports_http_error_status(monkeypatch):
    def fake_post(url, json, timeout):
        return SimpleNamespace(is_success=False, status_code=404)

    monkeypatch.setattr(notifications, "_http_post", _as_async(fake_post))
    notifier = WebhookNotifier("https://hook.example.com")
    assert asyncio.run(notifier.notify(FINDINGS)) is False


def test_webhook_notifier_swallows_http_errors(monkeypatch):
    import httpx

    def boom(*args, **kwargs):
        raise httpx.ConnectError("down")

    monkeypatch.setattr(notifications, "_http_post", _as_async(boom))
    # Should not raise.
    asyncio.run(WebhookNotifier("https://hook.example.com").notify(FINDINGS))


def test_dispatch_skips_when_no_findings():
    recorder = RecordingNotifier()
    asyncio.run(dispatch([], [recorder]))
    assert recorder.received is None


def test_dispatch_sends_to_all_notifiers():
    recorder = RecordingNotifier()
    asyncio.run(dispatch(FINDINGS, [recorder]))
    assert recorder.received == FINDINGS


def test_dispatch_isolates_failing_notifier():
    class FailingNotifier:
        async def notify(self, findings):
            raise RuntimeError("boom")

    recorder = RecordingNotifier()
    # The failing notifier must not prevent the recorder from being called.
    asyncio.run(dispatch(FINDINGS, [FailingNotifier(), recorder]))
    assert recorder.received == FINDINGS


def test_build_notifiers_from_env(monkeypatch):
    monkeypatch.setenv("NOTIFY_CONSOLE", "true")
    monkeypatch.delenv("NOTIFY_WEBHOOK_URL", raising=False)
    notifiers = build_notifiers_from_env()
    assert any(isinstance(n, ConsoleNotifier) for n in notifiers)
    assert not any(isinstance(n, WebhookNotifier) for n in notifiers)

    monkeypatch.setenv("NOTIFY_CONSOLE", "false")
    monkeypatch.setenv("NOTIFY_WEBHOOK_URL", "https://hook.example.com")
    get_settings.cache_clear()
    notifiers = build_notifiers_from_env()
    assert not any(isinstance(n, ConsoleNotifier) for n in notifiers)
    assert any(isinstance(n, WebhookNotifier) for n in notifiers)


def test_slack_notifier_posts_text(monkeypatch):
    captured = {}

    def fake_post(url, json, timeout):
        captured["url"] = url
        captured["json"] = json
        return OK

    monkeypatch.setattr(notifications, "_http_post", _as_async(fake_post))
    asyncio.run(SlackNotifier("https://slack.example.com/hook").notify(FINDINGS))

    assert captured["url"] == "https://slack.example.com/hook"
    text = captured["json"]["text"]
    assert "CVE-2024-1" in text
    assert "KEV" in text
    assert "EPSS 0.97" in text


def test_slack_notifier_escapes_mentions(monkeypatch):
    captured = {}

    def fake_post(url, json, timeout):
        captured["text"] = json["text"]
        return OK

    monkeypatch.setattr(notifications, "_http_post", _as_async(fake_post))
    finding = {**FINDINGS[0], "asset_name": "<!channel>"}
    asyncio.run(SlackNotifier("https://slack.example.com/hook").notify([finding]))

    assert "<!channel>" not in captured["text"]
    assert "&lt;!channel&gt;" in captured["text"]


def test_teams_notifier_posts_adaptive_card(monkeypatch):
    captured = {}

    def fake_post(url, json, timeout):
        captured["json"] = json
        return OK

    monkeypatch.setattr(notifications, "_http_post", _as_async(fake_post))
    asyncio.run(TeamsNotifier("https://x.webhook.office.com/hook").notify(FINDINGS))

    attachment = captured["json"]["attachments"][0]
    assert attachment["contentType"] == "application/vnd.microsoft.card.adaptive"
    texts = [block["text"] for block in attachment["content"]["body"]]
    assert "1 vulnerability alert(s)" in texts[0]
    assert "CVE-2024-1" in texts[1]


def test_discord_notifier_splits_long_messages_and_blocks_mentions(monkeypatch):
    posts = []

    def fake_post(url, json, timeout):
        posts.append(json)
        return OK

    monkeypatch.setattr(notifications, "_http_post", _as_async(fake_post))
    findings = [
        {**FINDINGS[0], "cve_id": f"CVE-2024-{i}", "asset_name": "x" * 100}
        for i in range(40)
    ]
    delivered = asyncio.run(
        DiscordNotifier("https://discord.com/api/webhooks/1/abc").notify(findings)
    )

    assert delivered is True
    assert len(posts) > 1
    assert all(len(p["content"]) <= 2000 for p in posts)
    assert all(p["allowed_mentions"] == {"parse": []} for p in posts)
    assert "CVE-2024-39" in posts[-1]["content"]


@pytest.mark.parametrize(
    "channel, url",
    [
        ("slack", "https://hooks.slack.com/services/T0/B0/xyz"),
        ("teams", "https://acme.webhook.office.com/webhookb2/abc"),
        ("teams", "https://prod-01.westeurope.logic.azure.com:443/workflows/abc"),
        ("discord", "https://discord.com/api/webhooks/123/abc"),
    ],
)
def test_check_webhook_url_accepts_service_hosts(channel, url):
    assert check_webhook_url(channel, f" {url} ") == url


@pytest.mark.parametrize(
    "channel, url",
    [
        ("slack", "http://hooks.slack.com/services/T0/B0/xyz"),
        ("slack", "https://hooks.slack.com.evil.com/services/x"),
        ("slack", "https://hooks.slack.com@169.254.169.254/latest"),
        ("slack", "https://hooks.slack.com:8443/services/x"),
        ("slack", "https://discord.com/api/webhooks/1/a"),
        ("teams", "https://webhook.office.com.evil.com/x"),
        ("discord", "https://discord.com/channels/1/2"),
        ("discord", "https://localhost/api/webhooks/1/a"),
        ("discord", "not a url"),
    ],
)
def test_check_webhook_url_rejects_other_hosts(channel, url):
    with pytest.raises(ValueError):
        check_webhook_url(channel, url)


def test_slack_notifier_swallows_http_errors(monkeypatch):
    import httpx

    def boom(*args, **kwargs):
        raise httpx.ConnectError("down")

    monkeypatch.setattr(notifications, "_http_post", _as_async(boom))
    asyncio.run(SlackNotifier("https://slack.example.com/hook").notify(FINDINGS))


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

    asyncio.run(
        EmailNotifier(
            host="smtp.example.com",
            port=587,
            sender="cve@example.com",
            recipients=["ops@example.com"],
            username="user",
            password="pass",
            use_tls=True,
        ).notify(FINDINGS)
    )

    assert sent["host"] == "smtp.example.com"
    assert sent["tls"] is True
    assert sent["login"] == ("user", "pass")
    assert sent["to"] == "ops@example.com"
    assert "CVE-2024-1" in sent["body"]


def test_email_notifier_swallows_smtp_errors(monkeypatch):
    def boom(*args, **kwargs):
        raise OSError("connection refused")

    monkeypatch.setattr(notifications.smtplib, "SMTP", boom)
    asyncio.run(
        EmailNotifier(
            host="smtp.example.com",
            port=587,
            sender="cve@example.com",
            recipients=["ops@example.com"],
        ).notify(FINDINGS)
    )


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


def test_admin_email_feed_includes_admin_emails(monkeypatch):
    monkeypatch.setenv("NOTIFY_EMAIL_HOST", "smtp.example.com")
    monkeypatch.setenv("NOTIFY_EMAIL_FROM", "cve@example.com")
    monkeypatch.setenv("NOTIFY_EMAIL_TO", "ops@example.com")
    monkeypatch.setenv("ADMIN_EMAILS", "Boss@Example.com, ops@example.com")

    email = next(n for n in build_notifiers_from_env() if isinstance(n, EmailNotifier))
    assert email.recipients == ["ops@example.com", "boss@example.com"]


TOKEN = "123456789:" + "A" * 35


def test_telegram_notifier_sends_plain_text_chunks(monkeypatch):
    posts = []

    def fake_post(url, json, timeout):
        posts.append((url, json))
        return OK

    monkeypatch.setattr(notifications, "_http_post", _as_async(fake_post))
    findings = [
        {**FINDINGS[0], "cve_id": f"CVE-2024-{i}", "asset_name": "x" * 150}
        for i in range(50)
    ]
    delivered = asyncio.run(TelegramNotifier(TOKEN, "-100123").notify(findings))

    assert delivered is True
    assert len(posts) > 1
    for url, payload in posts:
        assert url == f"https://api.telegram.org/bot{TOKEN}/sendMessage"
        assert payload["chat_id"] == "-100123"
        assert "parse_mode" not in payload
        assert len(payload["text"]) <= 4096
    assert "CVE-2024-49" in posts[-1][1]["text"]


def test_telegram_token_and_chat_id_validation():
    assert check_telegram_token(f" {TOKEN} ") == TOKEN
    assert check_telegram_chat_id("-100123") == "-100123"
    assert check_telegram_chat_id("@my_channel") == "@my_channel"
    for bad in ("123:short", "abc:" + "A" * 35, TOKEN + "/../x"):
        with pytest.raises(ValueError):
            check_telegram_token(bad)
    for bad in ("12ab", "@x", "-", "123/sendMessage"):
        with pytest.raises(ValueError):
            check_telegram_chat_id(bad)


def test_httpx_request_urls_are_not_logged():
    import logging

    import app.main  # noqa: F401

    # Webhook URLs embed their secret; httpx logs each request URL at INFO.
    assert not logging.getLogger("httpx").isEnabledFor(logging.INFO)


def test_format_finding_labels_escalations():
    kev = notifications._format_finding({**FINDINGS[0], "alert": "kev_added"})
    raised = notifications._format_finding(
        {**FINDINGS[0], "alert": "severity_raised", "previous_severity": "LOW"}
    )
    assert kev.startswith("[NOW IN KEV] CVE-2024-1")
    assert raised.startswith("[SEVERITY RAISED from LOW] CVE-2024-1")


def test_format_finding_labels_unscored_findings():
    line = notifications._format_finding(
        {"cve_id": "CVE-2099-1", "severity": None, "score": None}
    )
    assert line.startswith("CVE-2099-1 [UNKNOWN] ")
