"""Notification backends for newly discovered vulnerabilities.

Notifiers are intentionally simple and configured from environment variables so
the application can run without any external service. Each notifier receives a
list of "finding" dicts and is responsible for delivering them.
"""

import logging
import os
import smtplib
from email.message import EmailMessage
from typing import Any, Protocol

import httpx

logger = logging.getLogger(__name__)

Finding = dict[str, Any]


def _format_finding(finding: Finding) -> str:
    """One-line human summary of a finding, including KEV/EPSS triage signals."""
    parts = [
        f"{finding.get('cve_id')}",
        f"[{finding.get('severity')} {finding.get('score')}]",
        f"{finding.get('asset_name')} v{finding.get('asset_version')}",
    ]
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


class Notifier(Protocol):
    def notify(self, findings: list[Finding]) -> None: ...


class ConsoleNotifier:
    """Logs each finding through the standard logging system."""

    def notify(self, findings: list[Finding]) -> None:
        for finding in findings:
            logger.warning(
                "New vulnerability for %s v%s (%s): %s [%s]%s - %s",
                finding.get("asset_name"),
                finding.get("asset_version"),
                finding.get("user_email"),
                finding.get("cve_id"),
                finding.get("severity"),
                " KEV" if finding.get("kev") else "",
                finding.get("cve_url"),
            )


class WebhookNotifier:
    """Posts findings as JSON to a configured HTTP endpoint."""

    def __init__(self, url: str, timeout: int = 10):
        self.url = url
        self.timeout = timeout

    def notify(self, findings: list[Finding]) -> None:
        try:
            httpx.post(self.url, json={"findings": findings}, timeout=self.timeout)
        except httpx.HTTPError as e:
            logger.error("Webhook notification to %s failed: %s", self.url, e)


class SlackNotifier:
    """Posts a formatted message to a Slack (or compatible) incoming webhook."""

    def __init__(self, webhook_url: str, timeout: int = 10):
        self.webhook_url = webhook_url
        self.timeout = timeout

    def notify(self, findings: list[Finding]) -> None:
        header = f"*CVE Watcher* — {len(findings)} new vulnerability finding(s)"
        lines = "\n".join(f"• {_format_finding(f)}" for f in findings)
        try:
            httpx.post(
                self.webhook_url,
                json={"text": f"{header}\n{lines}"},
                timeout=self.timeout,
            )
        except httpx.HTTPError as e:
            logger.error("Slack notification failed: %s", e)


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

    def notify(self, findings: list[Finding]) -> None:
        message = EmailMessage()
        message["Subject"] = (
            f"CVE Watcher: {len(findings)} new vulnerability finding(s)"
        )
        message["From"] = self.sender
        message["To"] = ", ".join(self.recipients)
        body = "\n".join(_format_finding(f) for f in findings)
        message.set_content(body)

        try:
            with smtplib.SMTP(self.host, self.port, timeout=self.timeout) as server:
                if self.use_tls:
                    server.starttls()
                if self.username and self.password:
                    server.login(self.username, self.password)
                server.send_message(message)
        except (smtplib.SMTPException, OSError) as e:
            logger.error("Email notification failed: %s", e)


def _is_truthy(value: str) -> bool:
    return value.strip().lower() in ("1", "true", "yes", "on")


def _email_config_from_env() -> dict[str, Any] | None:
    host = os.getenv("NOTIFY_EMAIL_HOST")
    sender = os.getenv("NOTIFY_EMAIL_FROM")
    if not host or not sender:
        return None
    return {
        "host": host,
        "port": int(os.getenv("NOTIFY_EMAIL_PORT", "587")),
        "sender": sender,
        "username": os.getenv("NOTIFY_EMAIL_USERNAME") or None,
        "password": os.getenv("NOTIFY_EMAIL_PASSWORD") or None,
        "use_tls": _is_truthy(os.getenv("NOTIFY_EMAIL_USE_TLS", "true")),
    }


def send_email(
    recipients: list[str],
    subject: str,
    body: str,
    config: dict[str, Any] | None = None,
) -> bool:
    """Send a plain-text email via the configured SMTP relay; best-effort."""
    config = config or _email_config_from_env()
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


def build_notifiers_from_env() -> list[Notifier]:
    notifiers: list[Notifier] = []

    if _is_truthy(os.getenv("NOTIFY_CONSOLE", "true")):
        notifiers.append(ConsoleNotifier())

    webhook_url = os.getenv("NOTIFY_WEBHOOK_URL")
    if webhook_url:
        notifiers.append(WebhookNotifier(webhook_url))

    slack_url = os.getenv("NOTIFY_SLACK_WEBHOOK_URL")
    if slack_url:
        notifiers.append(SlackNotifier(slack_url))

    email_host = os.getenv("NOTIFY_EMAIL_HOST")
    email_from = os.getenv("NOTIFY_EMAIL_FROM")
    email_to = os.getenv("NOTIFY_EMAIL_TO", "")
    recipients = [addr.strip() for addr in email_to.split(",") if addr.strip()]
    if email_host and email_from and recipients:
        notifiers.append(
            EmailNotifier(
                host=email_host,
                port=int(os.getenv("NOTIFY_EMAIL_PORT", "587")),
                sender=email_from,
                recipients=recipients,
                username=os.getenv("NOTIFY_EMAIL_USERNAME") or None,
                password=os.getenv("NOTIFY_EMAIL_PASSWORD") or None,
                use_tls=_is_truthy(os.getenv("NOTIFY_EMAIL_USE_TLS", "true")),
            )
        )

    return notifiers


def dispatch(findings: list[Finding], notifiers: list[Notifier]) -> None:
    """Send findings to every notifier; a failing notifier never blocks others."""
    if not findings:
        return
    for notifier in notifiers:
        try:
            notifier.notify(findings)
        except Exception as e:
            logger.error("Notifier %s failed: %s", type(notifier).__name__, e)
