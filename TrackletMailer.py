# TrackletMailer.py
from __future__ import annotations

import os
import smtplib
from email.message import EmailMessage
import ssl
from typing import Optional

import requests

from config import settings



class MailerError(RuntimeError):
    pass

def _provider() -> str:
    return (settings.MAIL_PROVIDER or "smtp").strip().lower()

def is_configured() -> bool:
    if settings.MAIL_PROVIDER.lower() == "resend":
        return bool(settings.RESEND_API_KEY) and bool(settings.SMTP_FROM)
    return bool(settings.SMTP_HOST and settings.SMTP_USER and settings.SMTP_PASS and (settings.SMTP_FROM or settings.SMTP_USER))


def send_email(to: str, subject: str, body: str, *, from_addr: Optional[str] = None) -> None:

    if not is_configured():
        raise MailerError("Mailer not configured")

    sender = from_addr or settings.SMTP_FROM or settings.SMTP_USER
    p = _provider()

    # --- Resend (HTTPS) ---
    if p == "resend":
        api_key = settings.RESEND_API_KEY
        if not api_key:
            raise MailerError("RESEND_API_KEY missing")

        try:
            r = requests.post(
                "https://api.resend.com/emails",
                headers={
                    "Authorization": f"Bearer {api_key}",
                    "Content-Type": "application/json",
                },
                json={
                    "from": sender,
                    "to": [to],
                    "subject": subject,
                    "text": body,
                    "reply_to": sender
                },
                timeout=30,
            )

            print(f"[MAIL] Resend to={to} subject={subject} status={r.status_code}")
            print("RESEND configured?", bool(settings.RESEND_API_KEY), "FROM:", settings.SMTP_FROM, "provider:", _provider())

            if r.status_code >= 400:
                raise MailerError(f"Resend error {r.status_code}: {r.text}")
            return

        except Exception as e:
            raise MailerError(repr(e)) from e

    # --- SMTP fallback (local/dev) ---
    msg = EmailMessage()
    msg["From"] = sender
    msg["To"] = to
    msg["Subject"] = subject
    msg.set_content(body)

    try:
        port = int(settings.SMTP_PORT)
        host = settings.SMTP_HOST

        if port == 465:
            context = ssl.create_default_context()
            with smtplib.SMTP_SSL(host, port, timeout=30, context=context) as s:
                s.login(settings.SMTP_USER, settings.SMTP_PASS)
                s.send_message(msg)
        else:
            with smtplib.SMTP(host, port, timeout=30) as s:
                s.ehlo()
                context = ssl.create_default_context()
                s.starttls(context=context)
                s.ehlo()
                s.login(settings.SMTP_USER, settings.SMTP_PASS)
                s.send_message(msg)

    except Exception as e:
        raise MailerError(repr(e)) from e



# ----------------------------
# Domain helpers
# ----------------------------

def send_issue_assigned(
    to: str,
    recipient_name: str,
    issue_id: int,
    title: str,
    project_name: str,
    assigner_name: str,
    issue_url: str,
):
    subject = f"[Tracklet] Issue assigned to you: #{issue_id}"
    body = f"""
Hi {recipient_name},

{assigner_name} assigned you a Tracklet issue.

Issue: #{issue_id} — {title}
Project: {project_name}

Open:
{issue_url}

Thanks,
Tracklet
"""
    send_email(to=to, subject=subject, body=body)

def send_issue_reminder(
    *,
    to: str,
    assignee_name: str,
    issue_id: int,
    title: str,
    project_name: str,
    status: str,
    priority: str,
    sender_name: str,
    issue_url: str,
) -> None:
    subject = f"Reminder: Issue #{issue_id} – {title}"
    body = (
        f"Hi {assignee_name},\n\n"
        f"This is a reminder regarding the following issue:\n\n"
        f"Project: {project_name}\n"
        f"Issue #{issue_id}: {title}\n"
        f"Status: {status}\n"
        f"Priority: {priority}\n\n"
        f"Sent by: {sender_name}\n\n"
        f"Open issue:\n{issue_url}\n"
    )
    send_email(to, subject, body)

def send_issue_comment(
    to: str,
    recipient_name: str,
    issue_id: int,
    title: str,
    actor_name: str,
    comment_text: str,
    issue_url: str,
):
    subject = f"[Tracklet] New note on #{issue_id}: {title}"
    body = f"""Hi {recipient_name},

{actor_name} added a note on issue #{issue_id}:

{comment_text}

Open issue: {issue_url}
"""
    send_email(to=to, subject=subject, body=body)

def send_issue_status_changed(
    to: str,
    recipient_name: str,
    issue_id: int,
    title: str,
    actor_name: str,
    new_status: str,
    note_text: str,
    issue_url: str,
):
    subject = f"[Tracklet] Issue #{issue_id} is now {new_status}"
    note_part = f"\nNote:\n{note_text}\n" if note_text else ""
    body = f"""Hi {recipient_name},

{actor_name} changed issue #{issue_id} to: {new_status}.{note_part}

Open issue: {issue_url}
"""
    send_email(to=to, subject=subject, body=body)

def send_welcome_user(to: str, name: str, temp_password: str, login_url: str):
    subject = "[Tracklet] Your account is ready"
    body = f"""Hi {name},

Welcome to Tracklet.

Login here:
{login_url}

Temporary password:
{temp_password}

After login, go to "My Settings" and change your password.

Thanks,
Tracklet
"""
    send_email(to=to, subject=subject, body=body)