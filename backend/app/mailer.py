"""Tiny SMTP sender — stdlib smtplib, lazy import, synchronous but bounded.

Fails soft: when SMTP is not configured the message is logged (dev boxes and
the RAM-constrained MVP) so flows like password reset remain testable.
"""
from __future__ import annotations

import logging
import smtplib
from email.message import EmailMessage

from . import config

log = logging.getLogger("lunaquest.mail")


def send_mail(to: str, subject: str, body: str) -> bool:
    """Send one plain-text mail.  Returns True on success. Never raises."""
    if not config.SMTP_HOST:
        log.info("[mail-not-configured] to=%s subject=%r body=%s", to, subject, body[:200])
        return False
    msg = EmailMessage()
    msg["From"] = config.SMTP_FROM
    msg["To"] = to
    msg["Subject"] = subject
    msg.set_content(body)
    try:
        with smtplib.SMTP(config.SMTP_HOST, config.SMTP_PORT, timeout=10) as s:
            if config.SMTP_TLS:
                s.starttls()
            if config.SMTP_USER:
                s.login(config.SMTP_USER, config.SMTP_PASS)
            s.send_message(msg)
        return True
    except Exception as exc:  # noqa: BLE001 — mail must never break a request
        log.warning("SMTP send failed: %s", exc)
        return False
