"""Generic webhook notifier: POST a JSON payload to any URL."""

from __future__ import annotations

import httpx

from afterlife.notify.base import Alert, Notifier


class WebhookNotifier(Notifier):
    name = "webhook"

    def __init__(self, url: str, *, timeout: float = 10.0):
        self.url = url
        self.timeout = timeout

    def _payload(self, alert: Alert) -> dict:
        return {
            "source": "afterlife",
            "title": alert.title(),
            "new": alert.new_count,
            "reopened": alert.reopened_count,
            "counts_by_severity": alert.counts_by_severity,
            "findings": [
                {
                    "rule_id": f.rule_id,
                    "severity": f.severity.value,
                    "title": f.title,
                    "description": f.description,
                    "evidence": f.evidence,
                    "blast_score": (
                        f.blast_radius.score if f.blast_radius else None
                    ),
                }
                for f in alert.ordered_findings()
            ],
        }

    def send(self, alert: Alert) -> None:
        response = httpx.post(
            self.url, json=self._payload(alert), timeout=self.timeout
        )
        response.raise_for_status()
