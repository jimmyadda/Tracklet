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
import base64

def _attachments_for_resend(attachments: list[dict]) -> list[dict]:
    out = []
    for a in attachments:
        with open(a["path"], "rb") as f:
            content = base64.b64encode(f.read()).decode("utf-8")
        out.append({
            "filename": a["filename"],
            "content": content,
        })
    return out

def _provider() -> str:
    return (settings.MAIL_PROVIDER or "smtp").strip().lower()

def is_configured() -> bool:
    if settings.MAIL_PROVIDER.lower() == "resend":
        return bool(settings.RESEND_API_KEY) and bool(settings.SMTP_FROM)
    return bool(settings.SMTP_HOST and settings.SMTP_USER and settings.SMTP_PASS and (settings.SMTP_FROM or settings.SMTP_USER))


import base64
import mimetypes
from email.message import EmailMessage
from pathlib import Path
from typing import Optional

def send_email(
    to: str,
    subject: str,
    body: str,
    *,
    from_addr: Optional[str] = None,
    attachments: Optional[list[dict]] = None,  # ✅ NEW
) -> None:

    if not is_configured():
        raise MailerError("Mailer not configured")

    sender = from_addr or settings.SMTP_FROM or settings.SMTP_USER
    p = _provider()
    attachments = attachments or []

    # --- Resend (HTTPS) ---
    if p == "resend":
        api_key = settings.RESEND_API_KEY
        if not api_key:
            raise MailerError("RESEND_API_KEY missing")

        resend_attachments = []
        try:
            for a in attachments:
                path = Path(a["path"])
                if not path.exists():
                    continue
                filename = a.get("filename") or path.name

                content_b64 = base64.b64encode(path.read_bytes()).decode("utf-8")
                resend_attachments.append({
                    "filename": filename,
                    "content": content_b64,
                })

            payload = {
                "from": sender,
                "to": [to],
                "subject": subject,
                "text": body,
                "reply_to": sender,
            }
            if resend_attachments:
                payload["attachments"] = resend_attachments

            r = requests.post(
                "https://api.resend.com/emails",
                headers={
                    "Authorization": f"Bearer {api_key}",
                    "Content-Type": "application/json",
                },
                json=payload,
                timeout=30,
            )

            print(f"[MAIL] Resend to={to} subject={subject} status={r.status_code}")
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

    # ✅ attach files for SMTP
    for a in attachments:
        path = Path(a["path"])
        if not path.exists():
            continue

        filename = a.get("filename") or path.name
        mime = (a.get("mime_type") or "").strip()
        if not mime:
            mime = mimetypes.guess_type(filename)[0] or "application/octet-stream"

        maintype, subtype = (mime.split("/", 1) + ["octet-stream"])[:2]
        msg.add_attachment(path.read_bytes(), maintype=maintype, subtype=subtype, filename=filename)

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
# Issues Watcher
# ----------------------------

def send_issue_created_watcher(
    to: str,
    watcher_name: str,
    issue_id: int,
    title: str,
    project_name: str,
    creator_name: str,
    issue_url: str,
):
    subject = f"[Tracklet] New issue #{issue_id}"
    body = f"""Hi {watcher_name},

A new issue was created.

Issue: #{issue_id} — {title}
Project: {project_name}
Created by: {creator_name}

Open:
{issue_url}

Thanks,
Tracklet
"""
    send_email(to=to, subject=subject, body=body)


def send_issue_status_watcher(
    to: str,
    watcher_name: str,
    issue_id: int,
    title: str,
    project_name: str,
    actor_name: str,
    new_status: str,
    issue_url: str,
):
    subject = f"[Tracklet] Issue #{issue_id} status changed"
    body = f"""Hi {watcher_name},

Issue status changed.

Issue: #{issue_id} — {title}
Project: {project_name}
Changed by: {actor_name}
New status: {new_status}

Open:
{issue_url}

Thanks,
Tracklet
"""
    send_email(to=to, subject=subject, body=body)



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
    attachments=None
):
    attachments = attachments or []
    subject = f"[Tracklet] New note on #{issue_id}: {title}"
    body = f"""Hi {recipient_name},

{actor_name} added a note on issue #{issue_id}:

{comment_text}

Open issue: {issue_url}
"""
    send_email(to=to, subject=subject, body=body , attachments=attachments)

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