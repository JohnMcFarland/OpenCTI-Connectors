import unittest
from unittest.mock import MagicMock, PropertyMock

import stix2
from pycti import Identity

from team_cymru_scout.stix_builder import (
    TeamCymruScoutStixBuilder,
    _note_id,
    rating_to_score,
)

_TLP_MARKING = "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da"

_FAKE_IDS = {
    "IPv4-Addr": "ipv4-addr--90a03625-500c-5813-abd1-5d5519f833d2",
    "IPv6-Addr": "ipv6-addr--a1b2c3d4-e5f6-5a7b-8c9d-0e1f2a3b4c5d",
    "Domain-Name": "domain-name--c3967e18-f6e3-5b6a-8d40-16dca535fca3",
}


def _make_builder(entity_type="IPv4-Addr", obs_value="8.8.8.8"):
    helper = MagicMock()
    type(helper).connect_confidence_level = PropertyMock(return_value=50)
    author = stix2.Identity(
        id=Identity.generate_id("Team Cymru Scout", "organization"),
        name="Team Cymru Scout",
        identity_class="organization",
    )
    stix_entity = {"id": _FAKE_IDS[entity_type]}
    opencti_entity = {
        "observable_value": obs_value,
        "entity_type": entity_type,
    }
    return TeamCymruScoutStixBuilder(
        helper, author, _TLP_MARKING, stix_entity, opencti_entity,
    )


class TestRatingToScore(unittest.TestCase):

    def test_malicious(self):
        self.assertEqual(rating_to_score("malicious"), 85)

    def test_suspicious(self):
        self.assertEqual(rating_to_score("suspicious"), 50)

    def test_no_rating(self):
        self.assertEqual(rating_to_score("no_rating"), 20)

    def test_none(self):
        self.assertIsNone(rating_to_score(None))

    def test_unknown_string(self):
        self.assertIsNone(rating_to_score("benign"))


class TestNoteId(unittest.TestCase):

    def test_deterministic(self):
        self.assertEqual(_note_id("8.8.8.8"), _note_id("8.8.8.8"))

    def test_different_values_differ(self):
        self.assertNotEqual(_note_id("8.8.8.8"), _note_id("1.1.1.1"))

    def test_starts_with_note(self):
        self.assertTrue(_note_id("x").startswith("note--"))


class TestCreateAsnBelongsTo(unittest.TestCase):

    def test_ipv4_creates_asn_and_relationship(self):
        builder = _make_builder("IPv4-Addr")
        builder.create_asn_belongs_to(13335, "CLOUDFLARENET")
        self.assertEqual(len(builder.bundle), 2)
        asn_obj = builder.bundle[0]
        rel_obj = builder.bundle[1]
        self.assertIsInstance(asn_obj, stix2.AutonomousSystem)
        self.assertEqual(asn_obj.number, 13335)
        self.assertEqual(asn_obj.name, "CLOUDFLARENET")
        self.assertEqual(rel_obj.relationship_type, "belongs-to")

    def test_ipv6_is_noop(self):
        builder = _make_builder("IPv6-Addr", "2001:db8::1")
        builder.create_asn_belongs_to(13335, "CLOUDFLARENET")
        self.assertEqual(len(builder.bundle), 0)

    def test_domain_is_noop(self):
        builder = _make_builder("Domain-Name", "example.com")
        builder.create_asn_belongs_to(13335, "CLOUDFLARENET")
        self.assertEqual(len(builder.bundle), 0)


class TestCreateLocationLocatedAt(unittest.TestCase):

    def test_ipv4_creates_location_and_relationship(self):
        builder = _make_builder("IPv4-Addr")
        builder.create_location_located_at("US")
        self.assertEqual(len(builder.bundle), 2)
        loc = builder.bundle[0]
        rel = builder.bundle[1]
        self.assertIsInstance(loc, stix2.Location)
        self.assertEqual(loc.country, "US")
        self.assertEqual(loc.name, "United States")
        self.assertEqual(rel.relationship_type, "located-at")

    def test_ipv6_is_noop(self):
        builder = _make_builder("IPv6-Addr", "2001:db8::1")
        builder.create_location_located_at("US")
        self.assertEqual(len(builder.bundle), 0)

    def test_unknown_country_code_uses_raw(self):
        builder = _make_builder("IPv4-Addr")
        builder.create_location_located_at("XX")
        loc = builder.bundle[0]
        self.assertEqual(loc.name, "XX")


class TestCreatePdnsResolvesTo(unittest.TestCase):

    def test_creates_domain_and_rel_per_entry(self):
        builder = _make_builder("IPv4-Addr")
        builder.create_pdns_resolves_to(["a.com", "b.com"])
        self.assertEqual(len(builder.bundle), 4)
        self.assertIsInstance(builder.bundle[0], stix2.DomainName)
        self.assertEqual(builder.bundle[0].value, "a.com")
        self.assertEqual(builder.bundle[1].relationship_type, "resolves-to")
        self.assertEqual(builder.bundle[2].value, "b.com")


class TestCreateDomainIpResolvesTo(unittest.TestCase):

    def test_ipv4_creates_sco_and_relationship(self):
        builder = _make_builder("Domain-Name", "example.com")
        builder.create_domain_ip_resolves_to("1.2.3.4", 1234, "TEST-AS")
        self.assertEqual(len(builder.bundle), 4)
        ipv4 = builder.bundle[0]
        self.assertIsInstance(ipv4, stix2.IPv4Address)
        self.assertEqual(ipv4.value, "1.2.3.4")
        rel = builder.bundle[1]
        self.assertEqual(rel.relationship_type, "resolves-to")
        asn = builder.bundle[2]
        self.assertIsInstance(asn, stix2.AutonomousSystem)

    def test_ipv6_is_skipped(self):
        builder = _make_builder("Domain-Name", "example.com")
        builder.create_domain_ip_resolves_to("2001:db8::1", 1234, "TEST-AS")
        self.assertEqual(len(builder.bundle), 0)

    def test_no_asn(self):
        builder = _make_builder("Domain-Name", "example.com")
        builder.create_domain_ip_resolves_to("1.2.3.4", None, None)
        self.assertEqual(len(builder.bundle), 2)


class TestCreateAssessmentNote(unittest.TestCase):

    def test_creates_note(self):
        builder = _make_builder("IPv4-Addr")
        builder.create_assessment_note(
            "malicious",
            [{"rating": "malicious", "message": "known C2"}],
            [{"name": "botnet"}],
            [{"port": 443, "protocol_text": "HTTPS"}],
        )
        self.assertEqual(len(builder.bundle), 1)
        note = builder.bundle[0]
        self.assertIsInstance(note, stix2.Note)
        self.assertIn("malicious", note.content)
        self.assertIn("known C2", note.content)
        self.assertIn("botnet", note.content)
        self.assertIn("443", note.content)

    def test_note_id_is_deterministic(self):
        b1 = _make_builder("IPv4-Addr", "8.8.8.8")
        b1.create_assessment_note("malicious", [], [], [])
        b2 = _make_builder("IPv4-Addr", "8.8.8.8")
        b2.create_assessment_note("suspicious", [], [], [])
        self.assertEqual(b1.bundle[0].id, b2.bundle[0].id)

    def test_none_rating(self):
        builder = _make_builder("IPv4-Addr")
        builder.create_assessment_note(None, [], [], [])
        self.assertIn("unknown", builder.bundle[0].content)

    def test_deduplicates_ports(self):
        builder = _make_builder("IPv4-Addr")
        builder.create_assessment_note(
            "no_rating", [], [],
            [{"port": 80, "protocol_text": "HTTP"}, {"port": 80, "protocol_text": "HTTP"}],
        )
        self.assertEqual(builder.bundle[0].content.count("- 80/"), 1)


class TestSendBundle(unittest.TestCase):

    def test_empty_bundle(self):
        builder = _make_builder("IPv4-Addr")
        result = builder.send_bundle()
        self.assertEqual(result, "No enrichment data to send.")

    def test_sends_bundle(self):
        builder = _make_builder("IPv4-Addr")
        builder.create_assessment_note("malicious", [], [], [])
        builder.helper.stix2_create_bundle.return_value = '{"objects":[]}'
        builder.helper.send_stix2_bundle.return_value = ["bundle-1"]
        result = builder.send_bundle()
        self.assertIn("1 bundle(s)", result)
        builder.helper.send_stix2_bundle.assert_called_once()

    def test_grouping_contains_all_objects(self):
        builder = _make_builder("IPv4-Addr")
        builder.create_asn_belongs_to(13335, "CLOUDFLARENET")
        builder.create_assessment_note("malicious", [], [], [])
        builder.helper.stix2_create_bundle.return_value = '{"objects":[]}'
        builder.helper.send_stix2_bundle.return_value = ["bundle-1"]
        builder.send_bundle()
        grouping = builder.bundle[-1]
        self.assertIsInstance(grouping, stix2.Grouping)
        self.assertEqual(grouping.context, "suspicious-activity")
        self.assertIn(_FAKE_IDS["IPv4-Addr"], grouping.object_refs)
        for obj in builder.bundle[:-1]:
            self.assertIn(obj.id, grouping.object_refs)

    def test_grouping_id_is_deterministic(self):
        b1 = _make_builder("IPv4-Addr", "8.8.8.8")
        b1.create_assessment_note("malicious", [], [], [])
        b1.helper.stix2_create_bundle.return_value = '{"objects":[]}'
        b1.helper.send_stix2_bundle.return_value = ["bundle-1"]
        b1.send_bundle()

        b2 = _make_builder("IPv4-Addr", "8.8.8.8")
        b2.create_assessment_note("suspicious", [], [], [])
        b2.helper.stix2_create_bundle.return_value = '{"objects":[]}'
        b2.helper.send_stix2_bundle.return_value = ["bundle-1"]
        b2.send_bundle()

        self.assertEqual(b1.bundle[-1].id, b2.bundle[-1].id)
