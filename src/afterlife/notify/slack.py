"""Slack notifier via an Incoming Webhook URL.

Sends both a top-level `text` (used for the notification preview and as a
fallback) and Block Kit blocks for a nicer in-channel layout.
"""

from __future__ import annotations

import httpx

from afterlife.notify.base import Alert, Notifier

_MAX_LINES = 10


class SlackNotifier(Notifier):
    name = "slack"

    def __init__(self, webhook_url: str, *, timeout: float = 10.0):
        self.webhook_url = webhook_url
        self.timeout = timeout

    def _payload(self, alert: Alert) -> dict:
        lines = alert.lines()
        shown = lines[:_MAX_LINES]
        body = "\n".join(f"• {line}" for line in shown)
        if len(lines) > _MAX_LINES:
            body += f"\n…and {len(lines) - _MAX_LINES} more"
        text = f"{alert.title()}\n{body}"
        return {
            "text": text,
            "blocks": [
                {
                    "type": "header",
                    "text": {"type": "plain_text", "text": alert.title()},
                },
                {
                    "type": "section",
                    "text": {"type": "mrkdwn", "text": body or "_no details_"},
                },
            ],
        }

    def send(self, alert: Alert) -> None:
        response = httpx.post(
            self.webhook_url, json=self._payload(alert), timeout=self.timeout
        )
        response.raise_for_status()
