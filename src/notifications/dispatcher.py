#!/usr/bin/env python3
"""
KWTCyberWatch - Notification Dispatcher
Sends alerts via Email, Slack, Telegram, and Webhooks.
"""

import json
import logging
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timezone
from typing import Dict, List, Optional
from dataclasses import dataclass

logger = logging.getLogger("kwtcyberwatch.notifications")


@dataclass
class Alert:
    """Notification alert payload."""
    title: str
    message: str
    severity: str  # critical, high, medium, low
    domain: str
    alert_type: str
    details: Dict
    timestamp: str = ""

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.now(timezone.utc).isoformat()

    def to_dict(self) -> Dict:
        return {
            "title": self.title,
            "message": self.message,
            "severity": self.severity,
            "domain": self.domain,
            "alert_type": self.alert_type,
            "details": self.details,
            "timestamp": self.timestamp,
        }


class EmailNotifier:
    """Send alerts via SMTP email."""

    def __init__(self, config):
        self.server = config.email_smtp_server
        self.port = config.email_smtp_port
        self.username = config.email_username
        self.password = config.email_password
        self.recipients = config.email_recipients

    def send(self, alert: Alert) -> bool:
        if not self.server:
            logger.warning("Email not configured")
            return False
        try:
            msg = MIMEMultipart("alternative")
            msg["Subject"] = f"[KWTCyberWatch] [{alert.severity.upper()}] {alert.title}"
            msg["From"] = self.username
            msg["To"] = ", ".join(self.recipients)

            html = f"""
            <html><body style="font-family:Arial,sans-serif;background:#1a1a2e;color:#eee;padding:20px;">
            <div style="max-width:600px;margin:0 auto;background:#16213e;border-radius:8px;padding:24px;border-left:4px solid {'#ff4444' if alert.severity == 'critical' else '#ff8800' if alert.severity == 'high' else '#ffcc00'};">
            <h2 style="color:#00d4ff;margin-top:0;">🚨 KWTCyberWatch Alert</h2>
            <p><strong>Severity:</strong> <span style="color:{'#ff4444' if alert.severity == 'critical' else '#ff8800'};">{alert.severity.upper()}</span></p>
            <p><strong>Domain:</strong> <code style="background:#0f3460;padding:2px 6px;border-radius:3px;">{alert.domain}</code></p>
            <p><strong>Type:</strong> {alert.alert_type}</p>
            <p><strong>Details:</strong> {alert.message}</p>
            <hr style="border-color:#0f3460;">
            <p style="font-size:12px;color:#888;">KWTCyberWatch Phishing Detection Suite | {alert.timestamp}</p>
            </div></body></html>
            """

            msg.attach(MIMEText(html, "html"))

            with smtplib.SMTP(self.server, self.port) as server:
                server.starttls()
                server.login(self.username, self.password)
                server.sendmail(self.username, self.recipients, msg.as_string())

            logger.info(f"Email sent: {alert.title}")
            return True
        except Exception as e:
            logger.error(f"Email send failed: {e}")
            return False


class SlackNotifier:
    """Send alerts to Slack via webhook."""

    def __init__(self, config):
        self.webhook_url = config.slack_webhook_url
        self.channel = config.slack_channel

    def send(self, alert: Alert) -> bool:
        if not self.webhook_url:
            logger.warning("Slack not configured")
            return False
        try:
            import requests
            severity_emoji = {
                "critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵"
            }
            emoji = severity_emoji.get(alert.severity, "⚪")

            payload = {
                "channel": self.channel,
                "username": "KWTCyberWatch",
                "icon_emoji": ":shield:",
                "blocks": [
                    {
                        "type": "header",
                        "text": {"type": "plain_text", "text": f"{emoji} {alert.title}"}
                    },
                    {
                        "type": "section",
                        "fields": [
                            {"type": "mrkdwn", "text": f"*Severity:*\n{alert.severity.upper()}"},
                            {"type": "mrkdwn", "text": f"*Domain:*\n`{alert.domain}`"},
                            {"type": "mrkdwn", "text": f"*Type:*\n{alert.alert_type}"},
                            {"type": "mrkdwn", "text": f"*Time:*\n{alert.timestamp}"},
                        ]
                    },
                    {
                        "type": "section",
                        "text": {"type": "mrkdwn", "text": alert.message}
                    }
                ]
            }

            resp = requests.post(self.webhook_url, json=payload, timeout=10)
            resp.raise_for_status()
            logger.info(f"Slack notification sent: {alert.title}")
            return True
        except Exception as e:
            logger.error(f"Slack send failed: {e}")
            return False


class TelegramNotifier:
    """Send alerts via Telegram Bot API."""

    def __init__(self, config):
        self.token = config.telegram_bot_token
        self.chat_id = config.telegram_chat_id

    def send(self, alert: Alert) -> bool:
        if not self.token or not self.chat_id:
            logger.warning("Telegram not configured")
            return False
        try:
            import requests
            severity_emoji = {
                "critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵"
            }
            emoji = severity_emoji.get(alert.severity, "⚪")

            text = (
                f"{emoji} *KWTCyberWatch Alert*\n\n"
                f"*{alert.title}*\n"
                f"Severity: `{alert.severity.upper()}`\n"
                f"Domain: `{alert.domain}`\n"
                f"Type: {alert.alert_type}\n\n"
                f"{alert.message}\n\n"
                f"_{alert.timestamp}_"
            )

            url = f"https://api.telegram.org/bot{self.token}/sendMessage"
            resp = requests.post(url, json={
                "chat_id": self.chat_id,
                "text": text,
                "parse_mode": "Markdown",
            }, timeout=10)
            resp.raise_for_status()
            logger.info(f"Telegram notification sent: {alert.title}")
            return True
        except Exception as e:
            logger.error(f"Telegram send failed: {e}")
            return False


class WebhookNotifier:
    """Send alerts to generic webhook endpoints."""

    def __init__(self, config):
        self.url = config.webhook_url
        self.secret = config.webhook_secret

    def send(self, alert: Alert) -> bool:
        if not self.url:
            logger.warning("Webhook not configured")
            return False
        try:
            import requests
            import hmac
            payload = json.dumps(alert.to_dict())
            headers = {"Content-Type": "application/json"}
            if self.secret:
                sig = hmac.new(
                    self.secret.encode(), payload.encode(), "sha256"
                ).hexdigest()
                headers["X-KCW-Signature"] = sig

            resp = requests.post(
                self.url, data=payload, headers=headers, timeout=10
            )
            resp.raise_for_status()
            logger.info(f"Webhook sent: {alert.title}")
            return True
        except Exception as e:
            logger.error(f"Webhook send failed: {e}")
            return False


class NotificationDispatcher:
    """Central dispatcher that routes alerts to all configured channels."""

    def __init__(self, config):
        self.notifiers = []
        if config.email_enabled:
            self.notifiers.append(("email", EmailNotifier(config)))
        if config.slack_enabled:
            self.notifiers.append(("slack", SlackNotifier(config)))
        if config.telegram_enabled:
            self.notifiers.append(("telegram", TelegramNotifier(config)))
        if config.webhook_enabled:
            self.notifiers.append(("webhook", WebhookNotifier(config)))

    def dispatch(self, alert: Alert) -> Dict[str, bool]:
        """Send alert to all configured notification channels."""
        results = {}
        for name, notifier in self.notifiers:
            results[name] = notifier.send(alert)
        return results

    def dispatch_critical(self, alert: Alert) -> Dict[str, bool]:
        """Force-send to all channels regardless of severity filtering."""
        alert.severity = "critical"
        return self.dispatch(alert)
