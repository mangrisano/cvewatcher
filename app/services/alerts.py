"""Vulnerability alerts: what changed in a monitoring pass, and who gets told.

Every alert goes to the instance-wide (admin) channels. Each asset owner also
gets the alerts on their own assets, filtered by their preferences, by email
and on the chat webhooks they configured.
"""

from collections import defaultdict
from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Optional

from sqlalchemy.orm import Session

from app.database.models import AssetCVE, NotificationPreference, User
from app.models import SUPPRESSED_STATUSES, FindingStatus
from app.services.notifications import (
    DiscordNotifier,
    EmailNotifier,
    Finding,
    Notifier,
    SlackNotifier,
    TeamsNotifier,
    TelegramNotifier,
    dispatch,
    smtp_config,
)
from app.services.severity import band_rank, severity_band


class AlertKind(StrEnum):
    NEW = "new"
    KEV_ADDED = "kev_added"
    SEVERITY_RAISED = "severity_raised"


# Findings nobody wants to hear about again, whatever happens to the CVE.
_SILENT_STATUSES = frozenset(
    {FindingStatus.FIXED.value, FindingStatus.FALSE_POSITIVE.value}
)

_ALERT_FIELDS = (
    "cve_id",
    "severity",
    "score",
    "cve_url",
    "publish_date",
    "kev",
    "epss",
    "status",
    "previous_severity",
)


def observe(link: AssetCVE, finding: Finding, kev_known: bool) -> list[Finding]:
    """Record a known finding's current KEV/severity on its link.

    Returns the escalation alerts (entered KEV, severity raised). A NULL
    last-seen value is a baseline: it is recorded without alerting.
    """
    alerts: list[Finding] = []
    status = str(link.status or FindingStatus.OPEN.value)
    in_kev = bool(finding.get("kev"))
    severity = severity_band(finding.get("severity"))
    previous = link.severity

    # KEV entries are never withdrawn, and an unavailable catalog says nothing.
    if kev_known:
        if in_kev and link.kev is False and status not in _SILENT_STATUSES:
            alerts.append({**finding, "alert": AlertKind.KEV_ADDED.value})
        if in_kev or link.kev is None:
            link.kev = in_kev  # type: ignore[assignment]

    if (
        not alerts
        and previous is not None
        and band_rank(severity) > band_rank(str(previous))
        and status not in SUPPRESSED_STATUSES
    ):
        alerts.append(
            {
                **finding,
                "alert": AlertKind.SEVERITY_RAISED.value,
                "previous_severity": previous,
            }
        )
    link.severity = severity  # type: ignore[assignment]
    return alerts


def extract_alerts(monitoring_results: dict[str, Any]) -> list[Finding]:
    """Flatten a monitoring pass into alerts tagged with asset and owner."""
    alerts: list[Finding] = []
    for asset_result in monitoring_results.get("asset_results", []):
        base = {
            "asset_name": asset_result.get("asset_name"),
            "asset_version": asset_result.get("asset_version"),
            "user_email": asset_result.get("user_email"),
        }
        for vuln in asset_result.get("new_vulnerabilities", []):
            alerts.append(_alert(base, vuln, AlertKind.NEW.value))
        for vuln in asset_result.get("escalations", []):
            alerts.append(_alert(base, vuln, vuln.get("alert", AlertKind.NEW.value)))
    return alerts


def _alert(base: dict[str, Any], vuln: Finding, kind: str) -> Finding:
    alert = {**base, **{key: vuln.get(key) for key in _ALERT_FIELDS}}
    alert["kev"] = bool(alert["kev"])
    alert["status"] = alert["status"] or FindingStatus.OPEN.value
    alert["alert"] = kind
    return alert


@dataclass(frozen=True)
class AlertPreferences:
    min_severity: str = "HIGH"
    always_kev: bool = True
    escalations: bool = True
    slack_webhook_url: Optional[str] = None
    teams_webhook_url: Optional[str] = None
    discord_webhook_url: Optional[str] = None
    telegram_bot_token: Optional[str] = None
    telegram_chat_id: Optional[str] = None

    @classmethod
    def from_row(cls, row: Optional[NotificationPreference]) -> "AlertPreferences":
        if row is None:
            return cls()
        return cls(
            min_severity=str(row.min_severity),
            always_kev=bool(row.always_kev),
            escalations=bool(row.escalations),
            slack_webhook_url=_optional_str(row.slack_webhook_url),
            teams_webhook_url=_optional_str(row.teams_webhook_url),
            discord_webhook_url=_optional_str(row.discord_webhook_url),
            telegram_bot_token=_optional_str(row.telegram_bot_token),
            telegram_chat_id=_optional_str(row.telegram_chat_id),
        )


def _optional_str(value: Any) -> Optional[str]:
    return str(value) if value else None


def wants(alert: Finding, prefs: AlertPreferences) -> bool:
    """Whether an owner with these preferences should receive the alert."""
    status = alert.get("status") or FindingStatus.OPEN.value
    kind = alert.get("alert") or AlertKind.NEW.value
    if status in _SILENT_STATUSES:
        return False
    if kind != AlertKind.NEW.value and not prefs.escalations:
        return False
    if status in SUPPRESSED_STATUSES and kind != AlertKind.KEV_ADDED.value:
        return False
    if alert.get("kev") and prefs.always_kev:
        return True
    # LOW is the lowest threshold: it also covers findings not yet scored.
    if prefs.min_severity == "LOW":
        return True
    return band_rank(alert.get("severity")) >= band_rank(prefs.min_severity)


def personal_notifiers(
    email: str, prefs: AlertPreferences, smtp: Optional[dict[str, Any]]
) -> dict[str, Notifier]:
    """A user's own channels by name: always email (if SMTP is set), plus chats."""
    notifiers: dict[str, Notifier] = {}
    if smtp:
        notifiers["email"] = EmailNotifier(recipients=[email], **smtp)
    if prefs.slack_webhook_url:
        notifiers["slack"] = SlackNotifier(prefs.slack_webhook_url)
    if prefs.teams_webhook_url:
        notifiers["teams"] = TeamsNotifier(prefs.teams_webhook_url)
    if prefs.discord_webhook_url:
        notifiers["discord"] = DiscordNotifier(prefs.discord_webhook_url)
    if prefs.telegram_bot_token and prefs.telegram_chat_id:
        notifiers["telegram"] = TelegramNotifier(
            prefs.telegram_bot_token, prefs.telegram_chat_id
        )
    return notifiers


def load_preferences(db: Session, emails: list[str]) -> dict[str, AlertPreferences]:
    users = db.query(User).filter(User.email.in_(emails)).all()
    rows = {
        row.user_id: row
        for row in db.query(NotificationPreference)
        .filter(NotificationPreference.user_id.in_([user.id for user in users]))
        .all()
    }
    return {
        str(user.email): AlertPreferences.from_row(rows.get(user.id)) for user in users
    }


async def deliver_alerts(
    db: Session, alerts: list[Finding], admin_notifiers: list[Notifier]
) -> None:
    """Send every alert to the admin channels and each owner's to their own."""
    if not alerts:
        return
    await dispatch(alerts, admin_notifiers)

    by_user: dict[str, list[Finding]] = defaultdict(list)
    for alert in alerts:
        if alert.get("user_email"):
            by_user[alert["user_email"]].append(alert)
    preferences = load_preferences(db, list(by_user))
    smtp = smtp_config()
    # Whoever gets the admin email feed already has every alert by email.
    admin_inbox = {
        recipient.lower()
        for notifier in admin_notifiers
        if isinstance(notifier, EmailNotifier)
        for recipient in notifier.recipients
    }

    for email, user_alerts in by_user.items():
        prefs = preferences.get(email, AlertPreferences())
        selected = [alert for alert in user_alerts if wants(alert, prefs)]
        if not selected:
            continue
        notifiers = personal_notifiers(email, prefs, smtp)
        if email.lower() in admin_inbox:
            notifiers.pop("email", None)
        await dispatch(selected, list(notifiers.values()))
