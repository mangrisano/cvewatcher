"""Notification backends for newly discovered vulnerabilities.

Notifiers are intentionally simple and configured from environment variables so
the application can run without any external service. Each notifier receives a
list of "finding" dicts and is responsible for delivering them.
"""

import logging
import os
from typing import Any, Protocol

import httpx

logger = logging.getLogger(__name__)

Finding = dict[str, Any]


class Notifier(Protocol):
    def notify(self, findings: list[Finding]) -> None: ...


class ConsoleNotifier:
    """Logs each finding through the standard logging system."""

    def notify(self, findings: list[Finding]) -> None:
        for finding in findings:
            logger.warning(
                "New vulnerability for %s v%s (%s): %s [%s] - %s",
                finding.get("asset_name"),
                finding.get("asset_version"),
                finding.get("user_email"),
                finding.get("cve_id"),
                finding.get("severity"),
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


def _is_truthy(value: str) -> bool:
    return value.strip().lower() in ("1", "true", "yes", "on")


def build_notifiers_from_env() -> list[Notifier]:
    notifiers: list[Notifier] = []

    if _is_truthy(os.getenv("NOTIFY_CONSOLE", "true")):
        notifiers.append(ConsoleNotifier())

    webhook_url = os.getenv("NOTIFY_WEBHOOK_URL")
    if webhook_url:
        notifiers.append(WebhookNotifier(webhook_url))

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
