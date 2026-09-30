"""Notification backends for vulnerability alerts.

Notifiers are intentionally simple so the application can run without any
external service. Each notifier receives a list of "finding" dicts and returns
whether it delivered them.
"""

import asyncio
import logging
import re
import smtplib
from email.message import EmailMessage
from typing import Any, Protocol
from urllib.parse import urlsplit

import httpx

from app.config import get_settings

logger = logging.getLogger(__name__)

Finding = dict[str, Any]

# Chat messages list at most this many findings and summarise the rest.
MAX_CHAT_LINES = 50
DISCORD_MAX_CHARS = 2000
TELEGRAM_MAX_CHARS = 4096

_ALERT_LABELS = {"kev_added": "NOW IN KEV", "test": "TEST"}


def _format_finding(finding: Finding) -> str:
    """One-line human summary of a finding, including KEV/EPSS triage signals."""
    rating = finding.get("severity") or "UNKNOWN"
    if finding.get("score") is not None:
        rating += f" {finding['score']}"
    parts = [
        f"{finding.get('cve_id')}",
        f"[{rating}]",
        f"{finding.get('asset_name')} v{finding.get('asset_version')}",
    ]
    alert = finding.get("alert")
    if alert == "severity_raised":
        previous = finding.get("previous_severity") or "UNKNOWN"
        parts.insert(0, f"[SEVERITY RAISED from {previous}]")
    elif alert in _ALERT_LABELS:
        parts.insert(0, f"[{_ALERT_LABELS[alert]}]")
    signals = []
    if finding.get("kev"):
        signals.append("KEV (actively exploited)")
    epss = finding.get("epss")
    if epss is not None:
        signals.append(f"EPSS {epss:.2f}")
    if signals:
        parts.append("— " + ", ".join(signals))
    url = finding.get("cve_url")
    if url:
        parts.append(f"— {url}")
    return " ".join(parts)


def _headline(findings: list[Finding]) -> str:
    return f"{len(findings)} vulnerability alert(s)"


def _chat_lines(findings: list[Finding]) -> list[str]:
    lines = [_format_finding(f) for f in findings[:MAX_CHAT_LINES]]
    if len(findings) > MAX_CHAT_LINES:
        lines.append(f"… and {len(findings) - MAX_CHAT_LINES} more")
    return lines


_WEBHOOK_HOSTS = {
    "slack": lambda host, path: host == "hooks.slack.com",
    "teams": lambda host, path: host.endswith(
        (".webhook.office.com", ".logic.azure.com", ".powerplatform.com")
    ),
    "discord": lambda host, path: (
        host
        in {"discord.com", "discordapp.com", "ptb.discord.com", "canary.discord.com"}
        and path.startswith("/api/webhooks/")
    ),
}


def check_webhook_url(channel: str, url: str) -> str:
    """Return the URL if it is an HTTPS webhook of ``channel``'s service.

    User-supplied URLs are fetched by the server, so only the chat services'
    own hosts are accepted (no requests to arbitrary or internal hosts).
    """
    url = url.strip()
    try:
        parts = urlsplit(url)
        port = parts.port
    except ValueError:
        port = -1
        parts = urlsplit("")
    host = (parts.hostname or "").lower()
    if (
        parts.scheme != "https"
        or parts.username is not None
        or port not in (None, 443)
        or not _WEBHOOK_HOSTS[channel](host, parts.path)
    ):
        raise ValueError(f"Not a valid {channel} webhook URL")
    return url


_TELEGRAM_TOKEN = re.compile(r"\d{5,20}:[A-Za-z0-9_-]{30,64}")
# A numeric chat/group id, or @username of a public channel.
_TELEGRAM_CHAT = re.compile(r"-?\d{1,20}|@[A-Za-z][A-Za-z0-9_]{4,31}")


def check_telegram_token(token: str) -> str:
    """Return the token if it looks like a BotFather bot token."""
    token = token.strip()
    if not _TELEGRAM_TOKEN.fullmatch(token):
        raise ValueError("Not a valid Telegram bot token")
    return token


def check_telegram_chat_id(chat_id: str) -> str:
    chat_id = chat_id.strip()
    if not _TELEGRAM_CHAT.fullmatch(chat_id):
        raise ValueError("Not a valid Telegram chat id")
    return chat_id


class Notifier(Protocol):
    async def notify(self, findings: list[Finding]) -> bool: ...


async def _http_post(url: str, **kwargs: Any) -> httpx.Response:
    async with httpx.AsyncClient() as client:
        return await client.post(url, **kwargs)


async def _post_json(channel: str, url: str, payload: Any, timeout: int) -> bool:
    # The URL is not logged: webhook URLs embed their credentials.
    try:
        response = await _http_post(url, json=payload, timeout=timeout)
    except httpx.HTTPError as e:
        logger.error("%s notification failed: %s", channel, type(e).__name__)
        return False
    if not response.is_success:
        logger.error("%s notification failed: HTTP %s", channel, response.status_code)
        return False
    return True


class ConsoleNotifier:
    """Logs each finding through the standard logging system."""

    async def notify(self, findings: list[Finding]) -> bool:
        for finding in findings:
            logger.warning(
                "Vulnerability alert for %s v%s (%s): %s",
                finding.get("asset_name"),
                finding.get("asset_version"),
                finding.get("user_email"),
                _format_finding(finding),
            )
        return True


class WebhookNotifier:
    """Posts findings as JSON to a configured HTTP endpoint."""

    def __init__(self, url: str, timeout: int = 10):
        self.url = url
        self.timeout = timeout

    async def notify(self, findings: list[Finding]) -> bool:
        return await _post_json(
            "Webhook", self.url, {"findings": findings}, self.timeout
        )


def _slack_escape(text: str) -> str:
    # Slack reads <...> as links and mentions (e.g. <!channel>).
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


class SlackNotifier:
    """Posts a formatted message to a Slack incoming webhook."""

    def __init__(self, webhook_url: str, timeout: int = 10):
        self.webhook_url = webhook_url
        self.timeout = timeout

    async def notify(self, findings: list[Finding]) -> bool:
        header = f"*CVE Watcher* — {_headline(findings)}"
        lines = "\n".join(f"• {_slack_escape(line)}" for line in _chat_lines(findings))
        return await _post_json(
            "Slack", self.webhook_url, {"text": f"{header}\n{lines}"}, self.timeout
        )


class TeamsNotifier:
    """Posts an Adaptive Card to a Microsoft Teams webhook (Workflows or legacy)."""

    def __init__(self, webhook_url: str, timeout: int = 10):
        self.webhook_url = webhook_url
        self.timeout = timeout

    async def notify(self, findings: list[Finding]) -> bool:
        body = [
            {
                "type": "TextBlock",
                "text": f"CVE Watcher — {_headline(findings)}",
                "weight": "Bolder",
                "wrap": True,
            }
        ] + [
            {"type": "TextBlock", "text": line, "wrap": True}
            for line in _chat_lines(findings)
        ]
        card = {
            "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
            "type": "AdaptiveCard",
            "version": "1.4",
            "body": body,
        }
        payload = {
            "type": "message",
            "attachments": [
                {
                    "contentType": "application/vnd.microsoft.card.adaptive",
                    "content": card,
                }
            ],
        }
        return await _post_json("Teams", self.webhook_url, payload, self.timeout)


class DiscordNotifier:
    """Posts messages to a Discord webhook, split to fit Discord's size limit."""

    def __init__(self, webhook_url: str, timeout: int = 10):
        self.webhook_url = webhook_url
        self.timeout = timeout

    async def notify(self, findings: list[Finding]) -> bool:
        delivered = True
        for content in _chunks(
            [f"**CVE Watcher** — {_headline(findings)}"] + _chat_lines(findings),
            DISCORD_MAX_CHARS,
        ):
            # Asset names are user text: never let them ping @everyone.
            payload = {"content": content, "allowed_mentions": {"parse": []}}
            if not await _post_json("Discord", self.webhook_url, payload, self.timeout):
                delivered = False
        return delivered


class TelegramNotifier:
    """Sends messages through a Telegram bot to a chat, split to fit the limit."""

    def __init__(self, bot_token: str, chat_id: str, timeout: int = 10):
        self.url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
        self.chat_id = chat_id
        self.timeout = timeout

    async def notify(self, findings: list[Finding]) -> bool:
        delivered = True
        for text in _chunks(
            [f"CVE Watcher — {_headline(findings)}"] + _chat_lines(findings),
            TELEGRAM_MAX_CHARS,
        ):
            # Plain text (no parse_mode): asset names can't inject markup.
            payload = {
                "chat_id": self.chat_id,
                "text": text,
                "disable_web_page_preview": True,
            }
            if not await _post_json("Telegram", self.url, payload, self.timeout):
                delivered = False
        return delivered


def _chunks(lines: list[str], limit: int) -> list[str]:
    chunks: list[str] = []
    current = ""
    for line in lines:
        line = line[: limit - 1]
        if current and len(current) + 1 + len(line) > limit:
            chunks.append(current)
            current = line
        else:
            current = f"{current}\n{line}" if current else line
    if current:
        chunks.append(current)
    return chunks


class EmailNotifier:
    """Sends findings as a plain-text email over SMTP."""

    def __init__(
        self,
        host: str,
        port: int,
        sender: str,
        recipients: list[str],
        username: str | None = None,
        password: str | None = None,
        use_tls: bool = True,
        timeout: int = 15,
    ):
        self.host = host
        self.port = port
        self.sender = sender
        self.recipients = recipients
        self.username = username
        self.password = password
        self.use_tls = use_tls
        self.timeout = timeout

    async def notify(self, findings: list[Finding]) -> bool:
        return await asyncio.to_thread(self._send, findings)

    def _send(self, findings: list[Finding]) -> bool:
        config = {
            "host": self.host,
            "port": self.port,
            "sender": self.sender,
            "username": self.username,
            "password": self.password,
            "use_tls": self.use_tls,
        }
        body = "\n".join(_format_finding(f) for f in findings)
        return send_email(
            self.recipients, f"CVE Watcher: {_headline(findings)}", body, config
        )


def smtp_config() -> dict[str, Any] | None:
    """SMTP relay settings, or None when email is not configured."""
    settings = get_settings()
    if not settings.notify_email_host or not settings.notify_email_from:
        return None
    return {
        "host": settings.notify_email_host,
        "port": settings.notify_email_port,
        "sender": settings.notify_email_from,
        "username": settings.notify_email_username,
        "password": settings.notify_email_password,
        "use_tls": settings.notify_email_use_tls,
    }


def send_email(
    recipients: list[str],
    subject: str,
    body: str,
    config: dict[str, Any] | None = None,
) -> bool:
    """Send a plain-text email via the configured SMTP relay; best-effort."""
    config = config or smtp_config()
    if not config or not recipients:
        logger.warning("Email not configured; skipping send of %r", subject)
        return False

    message = EmailMessage()
    message["Subject"] = subject
    message["From"] = config["sender"]
    message["To"] = ", ".join(recipients)
    message.set_content(body)
    try:
        with smtplib.SMTP(config["host"], config["port"], timeout=15) as server:
            if config["use_tls"]:
                server.starttls()
            if config["username"] and config["password"]:
                server.login(config["username"], config["password"])
            server.send_message(message)
        return True
    except (smtplib.SMTPException, OSError) as e:
        logger.error("Email send failed: %s", e)
        return False


def admin_email_recipients() -> list[str]:
    """Who receives every alert by email: NOTIFY_EMAIL_TO plus ADMIN_EMAILS."""
    settings = get_settings()
    recipients = list(settings.notify_email_recipients)
    seen = {r.lower() for r in recipients}
    for email in sorted(settings.admin_email_set):
        if email not in seen:
            recipients.append(email)
            seen.add(email)
    return recipients


def build_notifiers_from_env() -> list[Notifier]:
    """The instance-wide (admin) channels, which receive every alert."""
    settings = get_settings()
    notifiers: list[Notifier] = []

    if settings.notify_console:
        notifiers.append(ConsoleNotifier())

    if settings.notify_webhook_url:
        notifiers.append(WebhookNotifier(settings.notify_webhook_url))

    if settings.notify_slack_webhook_url:
        notifiers.append(SlackNotifier(settings.notify_slack_webhook_url))

    email = smtp_config()
    recipients = admin_email_recipients()
    if email and recipients:
        notifiers.append(EmailNotifier(recipients=recipients, **email))

    return notifiers


async def dispatch(findings: list[Finding], notifiers: list[Notifier]) -> None:
    """Send findings to every notifier; a failing notifier never blocks others."""
    if not findings:
        return
    for notifier in notifiers:
        try:
            await notifier.notify(findings)
        except Exception as e:
            logger.error("Notifier %s failed: %s", type(notifier).__name__, e)
