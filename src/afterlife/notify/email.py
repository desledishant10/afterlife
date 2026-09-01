"""Email notifier over SMTP (stdlib smtplib, no extra dependency)."""

from __future__ import annotations

import smtplib
from dataclasses import dataclass, field
from email.message import EmailMessage

from afterlife.notify.base import Alert, Notifier


@dataclass
class SMTPSettings:
    host: str
    port: int = 587
    username: str | None = None
    password: str | None = None
    use_tls: bool = True
    sender: str = "afterlife@localhost"
    recipients: list[str] = field(default_factory=list)


class EmailNotifier(Notifier):
    name = "email"

    def __init__(self, settings: SMTPSettings, *, timeout: float = 15.0):
        self.settings = settings
        self.timeout = timeout

    def _message(self, alert: Alert) -> EmailMessage:
        msg = EmailMessage()
        msg["Subject"] = alert.title()
        msg["From"] = self.settings.sender
        msg["To"] = ", ".join(self.settings.recipients)
        body = alert.title() + "\n\n" + "\n".join(alert.lines())
        msg.set_content(body)
        return msg

    def send(self, alert: Alert) -> None:
        s = self.settings
        with smtplib.SMTP(s.host, s.port, timeout=self.timeout) as server:
            if s.use_tls:
                server.starttls()
            if s.username and s.password:
                server.login(s.username, s.password)
            server.send_message(self._message(alert))
