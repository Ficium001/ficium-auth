# =============================================================
# ficium-auth — Email service
# Transactional emails via Resend
# All templates bank-grade: clear, professional, no fluff
# =============================================================

import asyncio

import resend
from jinja2 import Environment, BaseLoader
from ..core.config import settings

resend.api_key = settings.resend_api_key

# ── Templates ─────────────────────────────────────────────────
_VERIFY_TEMPLATE = """
<!DOCTYPE html><html><body style="font-family:Inter Tight,sans-serif;color:#0A0A1A;background:#FAF7F0;padding:40px 20px;">
<div style="max-width:480px;margin:0 auto;background:white;border-radius:12px;padding:40px;border:1px solid rgba(10,10,26,0.08);">
  <div style="font-size:20px;font-weight:700;margin-bottom:8px;">Verify your email</div>
  <p style="color:#6B6B85;font-size:14px;line-height:1.6;">
    You registered for Ficium Portal. Click the button below to verify your email address.
    This link expires in 24 hours.
  </p>
  <a href="{{ url }}" style="display:inline-block;background:#2A1FE6;color:white;padding:14px 28px;border-radius:8px;text-decoration:none;font-weight:600;font-size:14px;margin:24px 0;">
    Verify email
  </a>
  <p style="color:#6B6B85;font-size:12px;">If you didn't create an account, ignore this email.</p>
  <hr style="border:none;border-top:1px solid rgba(10,10,26,0.07);margin:24px 0;">
  <p style="color:#6B6B85;font-size:11px;">Ficium Ltd · Port Louis, Mauritius</p>
</div>
</body></html>
"""

_RESET_TEMPLATE = """
<!DOCTYPE html><html><body style="font-family:Inter Tight,sans-serif;color:#0A0A1A;background:#FAF7F0;padding:40px 20px;">
<div style="max-width:480px;margin:0 auto;background:white;border-radius:12px;padding:40px;border:1px solid rgba(10,10,26,0.08);">
  <div style="font-size:20px;font-weight:700;margin-bottom:8px;">Reset your password</div>
  <p style="color:#6B6B85;font-size:14px;line-height:1.6;">
    A password reset was requested for your {{ product }} account.
    This link expires in <strong>1 hour</strong> and can only be used once.
  </p>
  <a href="{{ url }}" style="display:inline-block;background:#2A1FE6;color:white;padding:14px 28px;border-radius:8px;text-decoration:none;font-weight:600;font-size:14px;margin:24px 0;">
    Reset password
  </a>
  <p style="color:#6B6B85;font-size:13px;">
    If you didn't request this, your account may be at risk. 
    <a href="mailto:security@ficium.net" style="color:#2A1FE6;">Contact security immediately.</a>
  </p>
  <hr style="border:none;border-top:1px solid rgba(10,10,26,0.07);margin:24px 0;">
  <p style="color:#6B6B85;font-size:11px;">Ficium Ltd · Port Louis, Mauritius</p>
</div>
</body></html>
"""

_SUSPICIOUS_LOGIN_TEMPLATE = """
<!DOCTYPE html><html><body style="font-family:Inter Tight,sans-serif;color:#0A0A1A;background:#FAF7F0;padding:40px 20px;">
<div style="max-width:480px;margin:0 auto;background:white;border-radius:12px;padding:40px;border:1px solid #FCA5A5;">
  <div style="font-size:20px;font-weight:700;color:#DC2626;margin-bottom:8px;">⚠ New sign-in detected</div>
  <p style="color:#6B6B85;font-size:14px;line-height:1.6;">
    Your Ficium Portal account was accessed from a new location.
  </p>
  <table style="width:100%;font-size:13px;color:#0A0A1A;border-collapse:collapse;margin:16px 0;">
    <tr><td style="padding:8px 0;color:#6B6B85;">Time</td><td>{{ time }}</td></tr>
    <tr><td style="padding:8px 0;color:#6B6B85;">IP address</td><td>{{ ip }}</td></tr>
    <tr><td style="padding:8px 0;color:#6B6B85;">Device</td><td>{{ device }}</td></tr>
  </table>
  <p style="color:#6B6B85;font-size:13px;">
    If this was you, no action is needed. If not, 
    <a href="{{ revoke_url }}" style="color:#DC2626;font-weight:600;">revoke all sessions immediately</a>
    and contact <a href="mailto:security@ficium.net" style="color:#2A1FE6;">security@ficium.net</a>.
  </p>
  <hr style="border:none;border-top:1px solid rgba(10,10,26,0.07);margin:24px 0;">
  <p style="color:#6B6B85;font-size:11px;">Ficium Ltd · Port Louis, Mauritius</p>
</div>
</body></html>
"""

_LOCKOUT_ALERT_TEMPLATE = """
<!DOCTYPE html><html><body style="font-family:Inter Tight,sans-serif;color:#0A0A1A;background:#FAF7F0;padding:40px 20px;">
<div style="max-width:480px;margin:0 auto;background:white;border-radius:12px;padding:40px;border:1px solid #FCA5A5;">
  <div style="font-size:20px;font-weight:700;color:#DC2626;margin-bottom:8px;">⚠ Account locked</div>
  <p style="color:#6B6B85;font-size:14px;line-height:1.6;">
    Your Ficium Portal account has been temporarily locked after {{ attempts }} failed login attempts from IP {{ ip }}.
    The lockout lasts 15 minutes.
  </p>
  <p style="color:#6B6B85;font-size:13px;">
    If this wasn't you, contact <a href="mailto:security@ficium.net" style="color:#2A1FE6;">security@ficium.net</a> immediately.
  </p>
  <hr style="border:none;border-top:1px solid rgba(10,10,26,0.07);margin:24px 0;">
  <p style="color:#6B6B85;font-size:11px;">Ficium Ltd · Port Louis, Mauritius</p>
</div>
</body></html>
"""

# autoescape: device (User-Agent), IP and other values are attacker-controlled;
# unescaped they let a login with stolen credentials plant HTML in the victim's
# genuine security email (security audit 2026-10-24).
_jinja = Environment(loader=BaseLoader(), autoescape=True)


async def _send(payload: resend.Emails.SendParams) -> None:
    """resend.Emails.send is a blocking HTTP call. Run it on a worker thread so
    one slow or hanging send never stalls every other request on this server.
    Errors still propagate to the caller (fail loud)."""
    await asyncio.to_thread(resend.Emails.send, payload)


def _render(template: str, **ctx) -> str:
    return _jinja.from_string(template).render(**ctx)


async def send_verification_email(to: str, verify_url: str) -> None:
    await _send({
        "from":    f"{settings.email_from_name} <{settings.email_from}>",
        "to":      [to],
        "subject": "Verify your Ficium Portal email",
        "html":    _render(_VERIFY_TEMPLATE, url=verify_url),
    })


_INVITE_TEMPLATE = """
<!DOCTYPE html><html><body style="font-family:Inter Tight,sans-serif;color:#0A0A1A;background:#FAF7F0;padding:40px 20px;">
<div style="max-width:480px;margin:0 auto;background:white;border-radius:12px;padding:40px;border:1px solid rgba(10,10,26,0.08);">
  <div style="font-size:20px;font-weight:700;margin-bottom:8px;">You've been invited to Ficium Admin</div>
  <p style="color:#6B6B85;font-size:14px;line-height:1.6;">
    {{ inviter }} added you as Ficium staff. Your username is <strong>{{ username }}</strong>.
    Set a password with the button below; you'll then set up an authenticator app.
    This link expires in <strong>24 hours</strong> and can only be used once.
  </p>
  <a href="{{ url }}" style="display:inline-block;background:#2A1FE6;color:white;padding:14px 28px;border-radius:8px;text-decoration:none;font-weight:600;font-size:14px;margin:24px 0;">
    Set your password
  </a>
  <p style="color:#6B6B85;font-size:13px;">
    Not expecting this? <a href="mailto:security@ficium.net" style="color:#2A1FE6;">Tell security</a> and don't click the link.
  </p>
  <hr style="border:none;border-top:1px solid rgba(10,10,26,0.07);margin:24px 0;">
  <p style="color:#6B6B85;font-size:11px;">Ficium Ltd · Port Louis, Mauritius</p>
</div>
</body></html>
"""


async def send_staff_invite_email(to: str, url: str, username: str, inviter: str) -> None:
    await _send({
        "from":    f"{settings.email_from_name} <{settings.email_from}>",
        "to":      [to],
        "subject": "You've been invited to Ficium Admin",
        "html":    _render(_INVITE_TEMPLATE, url=url, username=username, inviter=inviter),
    })


async def send_password_reset_email(to: str, reset_url: str, product: str = "Ficium Portal") -> None:
    await _send({
        "from":    f"{settings.email_from_name} <{settings.email_from}>",
        "to":      [to],
        "subject": f"Reset your {product} password",
        "html":    _render(_RESET_TEMPLATE, url=reset_url, product=product),
    })


async def send_suspicious_login_alert(
    to: str,
    ip: str,
    device: str,
    time: str,
    revoke_url: str,
) -> None:
    await _send({
        "from":    f"{settings.email_from_name} <{settings.email_from}>",
        "to":      [to],
        "subject": "⚠ New sign-in to your Ficium Portal account",
        "html":    _render(_SUSPICIOUS_LOGIN_TEMPLATE, ip=ip, device=device, time=time, revoke_url=revoke_url),
    })


async def send_lockout_alert(to: str, ip: str, attempts: int) -> None:
    await _send({
        "from":    f"{settings.email_from_name} <{settings.email_from}>",
        "to":      [to],
        "subject": "⚠ Your Ficium Portal account has been locked",
        "html":    _render(_LOCKOUT_ALERT_TEMPLATE, ip=ip, attempts=attempts),
    })
