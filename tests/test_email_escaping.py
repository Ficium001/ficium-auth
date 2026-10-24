"""Security audit 2026-10-24: attacker-controlled values (User-Agent, IP) must be
escaped in security emails, not rendered as HTML."""
from src.services.email import _render


def test_user_agent_cannot_inject_html() -> None:
    evil = '<a href="https://evil.example/secure">Secure your account</a>'
    out = _render("<td>{{ device }}</td>", device=evil)
    assert "<a href" not in out
    assert "&lt;a href=" in out


def test_urls_still_render_in_links() -> None:
    out = _render('<a href="{{ url }}">x</a>', url="https://portal.ficium.net/verify?t=abc&u=1")
    assert 'href="https://portal.ficium.net/verify?t=abc&amp;u=1"' in out
