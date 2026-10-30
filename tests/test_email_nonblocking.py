"""Email sends must not block the event loop, and must still fail loudly."""

from __future__ import annotations

import asyncio
import threading
import time

import pytest

from src.services import email


def test_send_runs_off_the_event_loop_thread(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: dict[str, object] = {}

    def fake_send(payload: dict) -> None:
        seen["thread"] = threading.current_thread()
        seen["to"] = payload["to"]
        time.sleep(0.3)  # a slow provider

    monkeypatch.setattr(email.resend.Emails, "send", fake_send)

    async def run() -> float:
        ticks = 0

        async def heartbeat() -> None:
            nonlocal ticks
            while True:
                await asyncio.sleep(0.02)
                ticks += 1

        hb = asyncio.create_task(heartbeat())
        await email.send_password_reset_email("a@example.com", "https://x/reset")
        hb.cancel()
        return ticks

    ticks = asyncio.run(run())
    assert seen["thread"] is not threading.main_thread()
    assert seen["to"] == ["a@example.com"]
    assert ticks >= 5, "the event loop was blocked while the email was sending"


def test_a_failed_send_still_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(payload: dict) -> None:
        raise RuntimeError("domain not verified")

    monkeypatch.setattr(email.resend.Emails, "send", boom)
    with pytest.raises(RuntimeError, match="domain not verified"):
        asyncio.run(email.send_staff_invite_email("a@example.com", "https://x", "a", "KJ"))
