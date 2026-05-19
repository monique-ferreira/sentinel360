"""
Sentinel360 – Notifier Service
"""
import os, json, smtplib, httpx
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import List
from datetime import datetime

SMTP_HOST = os.getenv("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_USER = os.getenv("SMTP_USER", "")
SMTP_PASS = os.getenv("SMTP_PASS", "")
SMTP_FROM = os.getenv("SMTP_FROM", "sentinel360@yourdomain.com")


async def send_email_alert(to: str, org_name: str, findings: List[dict]) -> bool:
    if not SMTP_USER or not SMTP_PASS:
        return False
    try:
        subject = f"\u26a8 Sentinel360 \u2013 {len(findings)} risco(s) em {org_name}"
        rows = "".join(
            f"<tr><td>{f.get('name','')}</td><td>{f.get('risk_level','')}</td></tr>"
            for f in findings[:20]
        )
        html = f"<h1>{subject}</h1><table>{rows}</table>"
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = SMTP_FROM
        msg["To"] = to
        msg.attach(MIMEText(html, "html"))
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as s:
            s.starttls()
            s.login(SMTP_USER, SMTP_PASS)
            s.send_message(msg)
        return True
    except Exception as e:
        print(f"[SMTP] Erro: {e}")
        return False


async def send_webhook(url: str, payload: dict) -> bool:
    try:
        async with httpx.AsyncClient(timeout=10) as c:
            r = await c.post(url, json=payload)
            r.raise_for_status()
            return True
    except Exception as e:
        print(f"[Webhook] Erro: {e}")
        return False


async def send_slack_alert(webhook_url: str, org_name: str, findings: List[dict]) -> bool:
    critical = sum(1 for f in findings if f.get("risk_level") == "critical")
    high = sum(1 for f in findings if f.get("risk_level") == "high")
    blocks = [
        {"type": "header", "text": {"type": "plain_text", "text": f"\u26a8 Sentinel360 - {org_name}"}},
        {"type": "section", "fields": [
            {"type": "mrkdwn", "text": f"*Cr\u00edticos:* {critical}"},
            {"type": "mrkdwn", "text": f"*Altos:* {high}"},
            {"type": "mrkdwn", "text": f"*Total:* {len(findings)}"},
        ]},
    ]
    return await send_webhook(webhook_url, {"blocks": blocks})


async def dispatch_alerts(org: dict, findings: List[dict]):
    """Dispara todas as notificacoes configuradas."""
    urgent = [f for f in findings if f.get("risk_level") in ("critical", "high")]
    if not urgent:
        return
    org_name = org.get("name", "Organizacao")
    tasks = []
    if org.get("alert_email"):
        tasks.append(send_email_alert(org["alert_email"], org_name, urgent))
    if org.get("webhook_url"):
        w = org["webhook_url"]
        if "hooks.slack.com" in w:
            tasks.append(send_slack_alert(w, org_name, urgent))
        else:
            tasks.append(send_webhook(w, {"event": "new_risks", "findings": urgent}))
    import asyncio
    await asyncio.gather(*tasks, return_exceptions=True)
