# =============================================================
# ficium-auth — get_client_ip tests
#
# Regression coverage for the IP-spoofing fix: X-Forwarded-For is
# client-controllable, so we must trust only the RIGHTMOST hop (the
# one appended by our trusted edge proxy), never the attacker-
# supplied left entries, and never X-Real-IP. If this behaviour
# regresses, per-IP rate limiting and lockout can be bypassed.
# =============================================================

from types import SimpleNamespace

from src.middleware.auth_middleware import get_client_ip


def _req(headers: dict, peer: str | None = "10.0.0.1"):
    client = SimpleNamespace(host=peer) if peer else None
    return SimpleNamespace(headers=headers, client=client)


def test_single_xff_hop():
    r = _req({"X-Forwarded-For": "203.0.113.5"})
    assert get_client_ip(r) == "203.0.113.5"


def test_multiple_hops_takes_rightmost():
    # Attacker forges the left entries; the real proxy-appended IP is last.
    r = _req({"X-Forwarded-For": "1.2.3.4, 5.6.7.8, 203.0.113.9"})
    assert get_client_ip(r) == "203.0.113.9"


def test_spoofed_left_entry_ignored():
    # Attacker tries to inject a fake IP as the first entry to evade lockout.
    r = _req({"X-Forwarded-For": "66.66.66.66"}, peer="203.0.113.1")
    # Single entry → that's the trusted rightmost; but multi-entry proves it:
    r2 = _req({"X-Forwarded-For": "66.66.66.66, 203.0.113.1"})
    assert get_client_ip(r2) == "203.0.113.1"  # NOT the spoofed 66.66.66.66


def test_x_real_ip_no_longer_trusted():
    # X-Real-IP is fully client-controllable and must be ignored now.
    r = _req({"X-Real-IP": "6.6.6.6"}, peer="203.0.113.2")
    assert get_client_ip(r) == "203.0.113.2"  # falls back to socket peer


def test_falls_back_to_socket_peer():
    r = _req({}, peer="198.51.100.7")
    assert get_client_ip(r) == "198.51.100.7"


def test_unknown_when_no_info():
    r = _req({}, peer=None)
    assert get_client_ip(r) == "unknown"


def test_empty_xff_falls_back():
    r = _req({"X-Forwarded-For": ""}, peer="198.51.100.9")
    assert get_client_ip(r) == "198.51.100.9"


def test_whitespace_only_hops_skipped():
    r = _req({"X-Forwarded-For": " , , 203.0.113.44"})
    assert get_client_ip(r) == "203.0.113.44"
