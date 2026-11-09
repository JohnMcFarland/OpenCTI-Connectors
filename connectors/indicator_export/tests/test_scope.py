"""Scope filter: rules drawn from the 2026-11-07 dry-run sample (IE-SCOPE-FILTER-V1)."""

import pytest

from src.lifecycle import LifecycleManager
from src.scope import (
    REASON_BAD_SCHEME,
    REASON_EXCLUDED_DOMAIN,
    REASON_NON_GLOBAL_IP,
    REASON_PLACEHOLDER,
    REASON_RESERVED_NAME,
    REASON_SHARED_HOSTING,
    classify,
    refang,
)
from src.store import StateStore

from .fakes import FakeClient, FakeLogger, FakeStateHelper, ap_link, ipv4, settings


@pytest.mark.parametrize("value", [
    "192.168.5.30", "10.0.2.2", "192.168.200.4", "169.254.169.254",
    "100.100.100.200", "198.51.100.23", "127.0.0.1",
])
def test_non_global_ips_are_dropped(value):
    assert classify("IPv4-Addr", value)[0] == REASON_NON_GLOBAL_IP


def test_public_ip_is_kept():
    assert classify("IPv4-Addr", "23.240.77.233") == (None, "23.240.77.233")


@pytest.mark.parametrize("entity_type,value,reason", [
    ("Url", "https://www.bleepingcomputer.com/tag/edr-bypass/", REASON_EXCLUDED_DOMAIN),
    ("Url", "https://sec.cloudapps.cisco.com/security/center/x", REASON_EXCLUDED_DOMAIN),
    ("Url", "https://research.checkpoint.com/2026/x", REASON_EXCLUDED_DOMAIN),
    ("Domain-Name", "www.theregister.com", REASON_EXCLUDED_DOMAIN),
    ("Url", "https://login.microsoftonline.com/common/oauth2/v2.0/authorize?client_id=x", REASON_EXCLUDED_DOMAIN),
    ("Url", "https://microsoft.com/devicelogin", REASON_EXCLUDED_DOMAIN),
    ("Domain-Name", "graph.microsoft.com", REASON_EXCLUDED_DOMAIN),
    ("Url", "https://attacker-server.com", REASON_EXCLUDED_DOMAIN),
    ("Url", "https://share.google/placeholder", REASON_PLACEHOLDER),
    ("Domain-Name", "metadata.google.internal", REASON_RESERVED_NAME),
    ("Url", "file://c:/temp/malicious.ps1", REASON_BAD_SCHEME),
    ("Url", "https://198.51.100.23/api/w", REASON_NON_GLOBAL_IP),
    ("Domain-Name", "raw.githubusercontent.com", REASON_SHARED_HOSTING),
    ("Domain-Name", "drive.google.com", REASON_SHARED_HOSTING),
    ("Url", "https://dg.th/", REASON_SHARED_HOSTING),
])
def test_reference_and_shared_values_are_dropped(entity_type, value, reason):
    assert classify(entity_type, value)[0] == reason


@pytest.mark.parametrize("entity_type,value", [
    ("Url", "https://drive.google.com/uc?id=1TVJir&export=download"),
    ("Url", "https://canary.discord.com/api/webhooks/1438849130532438148/"),
    ("Url", "https://storage.googleapis.com/fundsavailabilityservicevanguardmeet/auth.html"),
    ("Url", "https://dg.th/9awb8zkpdi"),
    ("Url", "https://access-authority-2fa7abff0e.s3.us-east-1.amazonaws.com/index.html"),
    ("Domain-Name", "tdtqy-oyaaa-aaaae-af2dq-cai.raw.icp0.io"),
    ("Url", "https://vakhov.github.io/fresh-proxy-list/http.txt"),
    ("Domain-Name", "securityweek.cloud"),
    ("Domain-Name", "verify-lastpass.com"),
    ("Domain-Name", "pool.hashvault.pro"),
])
def test_attacker_controlled_values_are_kept(entity_type, value):
    assert classify(entity_type, value)[0] is None


def test_refang():
    assert refang("hxxps://quickcon.store/man/logo.php") == "https://quickcon.store/man/logo.php"
    assert refang("webman[.]w3school[.]cloudns[.]nz") == "webman.w3school.cloudns.nz"
    assert classify("Domain-Name", "rfa[.]ink") == (None, "rfa.ink")
    assert classify("Url", "hxxp://23.240.77.233:8085/") == (None, "http://23.240.77.233:8085/")


def test_files_pass_through():
    assert classify("StixFile", None) == (None, None)


def test_lists_are_additive_and_never_emptied():
    base = settings()
    extra = settings(INDICATOR_EXCLUDED_DOMAINS=" .Example-Pub.com. , ", INDICATOR_SHARED_HOSTING_DOMAINS="")
    assert "example-pub.com" in extra.excluded_domains
    assert base.excluded_domains <= extra.excluded_domains
    assert extra.shared_hosting_domains == base.shared_hosting_domains


def test_cycle_skips_out_of_scope_and_patterns_refanged_value():
    client = FakeClient()
    private = ipv4("obs-private", "192.168.5.30")
    article = {"id": "obs-url", "entity_type": "Url", "objectMarking": [], "objectLabel": [],
               "value": "https://thehackernews.com/2026/11/x.html"}
    defanged = {"id": "obs-dom", "entity_type": "Domain-Name", "objectMarking": [], "objectLabel": [],
                "value": "rfa[.]ink"}
    client.qualifying = [ap_link(private), ap_link(private, "ap-2"), ap_link(article), ap_link(defanged)]
    store = StateStore(FakeStateHelper())
    result = LifecycleManager(client, store, settings(), FakeLogger()).run_cycle()
    assert result.stats["out_of_scope"] == 2
    assert result.stats["promoted"] == 1
    assert [i["pattern"] for i in client.indicators.values()] == ["[domain-name:value = 'rfa.ink']"]
