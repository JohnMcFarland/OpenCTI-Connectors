"""Observable validators (stdlib only)."""

from __future__ import annotations

import pytest

from src.observables import OBSERVABLE_KINDS, normalize_observable


@pytest.mark.parametrize("kind, raw, expected", [
    ("ip", "10.0.0.1", ("ipv4-addr", "10.0.0.1", None)),
    ("ip", "2001:0db8::0001", ("ipv6-addr", "2001:db8::1", None)),
    ("ipv4-addr", "2001:db8::1", None),
    ("ipv6-addr", "2001:db8::1", ("ipv6-addr", "2001:db8::1", None)),
    ("ipv6-addr", "10.0.0.1", None),
    ("ip", "not-an-ip", None),
    ("domain-name", "Evil.Example.COM.", ("domain-name", "evil.example.com", None)),
    ("domain-name", "xn--e1afmkfd.xn--p1ai", ("domain-name", "xn--e1afmkfd.xn--p1ai", None)),
    ("domain-name", "localhost", None),
    ("domain-name", "bad..example.com", None),
    ("url", "https://x.test/a?b=1", ("url", "https://x.test/a?b=1", None)),
    ("url", "x.test/a", None),
    ("email-addr", "Bob@Corp.test", ("email-addr", "bob@corp.test", None)),
    ("email-addr", "bob", None),
    ("mac-addr", "AA-BB-CC-DD-EE-FF", ("mac-addr", "aa:bb:cc:dd:ee:ff", None)),
    ("mac-addr", "aa:bb:cc-dd:ee:ff", ("mac-addr", "aa:bb:cc:dd:ee:ff", None)),
    ("mac-addr", "aabbccddeeff", None),
    ("file-hash", "D41D8CD98F00B204E9800998ECF8427E",
     ("file", "d41d8cd98f00b204e9800998ecf8427e", "MD5")),
    ("file-hash", "a" * 40, ("file", "a" * 40, "SHA-1")),
    ("file-hash", "a" * 64, ("file", "a" * 64, "SHA-256")),
    ("file-hash", "z" * 32, None),
    ("file-hash", "abc", None),
    ("port", "443", ("network-traffic", "443", None)),
    ("port", "443.0", ("network-traffic", "443", None)),
    ("port", "0", None),
    ("port", "70000", None),
    ("port", "1e400", None),
    ("port", "https", None),
    ("user-account", "alice", ("user-account", "alice", None)),
    ("user-account", "-", None),
    ("user-account", "Unknown", None),
    ("user-account", "  ", None),
])
def test_normalize_observable(kind, raw, expected):
    assert normalize_observable(kind, raw) == expected


def test_every_kind_has_a_validator():
    for kind in OBSERVABLE_KINDS:
        normalize_observable(kind, "x")  # must not KeyError
