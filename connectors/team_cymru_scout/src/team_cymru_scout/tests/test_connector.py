import unittest

from team_cymru_scout.connector import _TLP_HIERARCHY, _parse_bool


class TestParseBool(unittest.TestCase):

    def test_true_bool(self):
        self.assertTrue(_parse_bool(True))

    def test_false_bool(self):
        self.assertFalse(_parse_bool(False))

    def test_true_string(self):
        self.assertTrue(_parse_bool("true"))
        self.assertTrue(_parse_bool("True"))
        self.assertTrue(_parse_bool("TRUE"))

    def test_false_string(self):
        self.assertFalse(_parse_bool("false"))
        self.assertFalse(_parse_bool("False"))

    def test_yes_one(self):
        self.assertTrue(_parse_bool("1"))
        self.assertTrue(_parse_bool("yes"))

    def test_no_zero(self):
        self.assertFalse(_parse_bool("0"))
        self.assertFalse(_parse_bool("no"))

    def test_empty_string(self):
        self.assertFalse(_parse_bool(""))


class TestTlpHierarchy(unittest.TestCase):

    def test_clear_is_lowest(self):
        self.assertEqual(_TLP_HIERARCHY.index("TLP:CLEAR"), 0)

    def test_red_is_highest(self):
        self.assertEqual(_TLP_HIERARCHY.index("TLP:RED"), len(_TLP_HIERARCHY) - 1)

    def test_amber_before_red(self):
        self.assertLess(
            _TLP_HIERARCHY.index("TLP:AMBER"),
            _TLP_HIERARCHY.index("TLP:RED"),
        )


class TestNormalization(unittest.TestCase):

    def _make_connector_stub(self):
        from unittest.mock import MagicMock, PropertyMock

        conn = object.__new__(
            type(
                "Stub",
                (),
                {
                    "_normalize_foundation": __import__(
                        "team_cymru_scout.connector", fromlist=["TeamCymruScoutConnector"]
                    ).TeamCymruScoutConnector._normalize_foundation,
                    "_normalize_details": __import__(
                        "team_cymru_scout.connector", fromlist=["TeamCymruScoutConnector"]
                    ).TeamCymruScoutConnector._normalize_details,
                    "max_pdns": 10,
                },
            )
        )
        return conn

    def test_foundation_with_nulls(self):
        conn = self._make_connector_stub()
        result = conn._normalize_foundation({
            "as_info": None,
            "insights": None,
            "pdns": None,
            "tags": None,
            "services": None,
        })
        self.assertIsNone(result["asn"])
        self.assertIsNone(result["as_name"])
        self.assertEqual(result["insights"], [])
        self.assertEqual(result["tags"], [])
        self.assertEqual(result["pdns_domains"], [])
        self.assertEqual(result["open_ports"], [])

    def test_foundation_with_missing_asn_keys(self):
        conn = self._make_connector_stub()
        result = conn._normalize_foundation({
            "as_info": [{"other_field": "value"}],
            "insights": None,
            "pdns": None,
            "tags": None,
            "services": None,
        })
        self.assertIsNone(result["asn"])
        self.assertIsNone(result["as_name"])

    def test_foundation_with_data(self):
        conn = self._make_connector_stub()
        result = conn._normalize_foundation({
            "as_info": [{"asn": 13335, "as_name": "CLOUDFLARENET"}],
            "insights": {"overall_rating": "malicious", "insights": [{"rating": "malicious"}]},
            "pdns": [{"domain": "a.com"}, {"domain": "b.com"}],
            "tags": [{"name": "cdn"}],
            "services": [{"port": 443}],
            "country_code": "US",
        })
        self.assertEqual(result["asn"], 13335)
        self.assertEqual(result["as_name"], "CLOUDFLARENET")
        self.assertEqual(result["insights_rating"], "malicious")
        self.assertEqual(result["pdns_domains"], ["a.com", "b.com"])
        self.assertEqual(result["country_code"], "US")

    def test_details_with_nulls(self):
        conn = self._make_connector_stub()
        result = conn._normalize_details({
            "identity": None,
            "whois": None,
            "summary": None,
        })
        self.assertIsNone(result["asn"])
        self.assertEqual(result["insights"], [])
        self.assertEqual(result["pdns_domains"], [])

    def test_details_with_data(self):
        conn = self._make_connector_stub()
        result = conn._normalize_details({
            "identity": {"asn": 13335, "as_name": "CLOUDFLARENET", "tags": []},
            "whois": {"cc": "US"},
            "summary": {
                "geo_ip_cc": "US",
                "insights": {"overall_rating": "suspicious", "insights": []},
                "pdns": {"top_pdns": [{"domain": "a.com"}]},
                "open_ports": {"top_open_ports": [{"port": 80}]},
                "tags": [{"name": "proxy"}],
            },
        })
        self.assertEqual(result["asn"], 13335)
        self.assertEqual(result["country_code"], "US")
        self.assertEqual(result["insights_rating"], "suspicious")


class TestTlpAllowed(unittest.TestCase):

    def _make_connector_with_max_tlp(self, max_tlp):
        from team_cymru_scout.connector import TeamCymruScoutConnector
        conn = object.__new__(TeamCymruScoutConnector)
        conn.max_tlp = max_tlp
        return conn

    def test_no_marking_is_allowed(self):
        conn = self._make_connector_with_max_tlp("TLP:AMBER")
        self.assertTrue(conn._is_tlp_allowed({"objectMarking": []}))

    def test_null_marking_is_allowed(self):
        conn = self._make_connector_with_max_tlp("TLP:AMBER")
        self.assertTrue(conn._is_tlp_allowed({"objectMarking": None}))

    def test_clear_below_amber(self):
        conn = self._make_connector_with_max_tlp("TLP:AMBER")
        entity = {"objectMarking": [{"definition": "TLP:CLEAR"}]}
        self.assertTrue(conn._is_tlp_allowed(entity))

    def test_red_above_amber(self):
        conn = self._make_connector_with_max_tlp("TLP:AMBER")
        entity = {"objectMarking": [{"definition": "TLP:RED"}]}
        self.assertFalse(conn._is_tlp_allowed(entity))

    def test_exact_match_allowed(self):
        conn = self._make_connector_with_max_tlp("TLP:AMBER")
        entity = {"objectMarking": [{"definition": "TLP:AMBER"}]}
        self.assertTrue(conn._is_tlp_allowed(entity))

    def test_unknown_tlp_denied(self):
        conn = self._make_connector_with_max_tlp("TLP:AMBER")
        entity = {"objectMarking": [{"definition": "TLP:UNKNOWN"}]}
        self.assertFalse(conn._is_tlp_allowed(entity))

    def test_missing_object_marking_key(self):
        conn = self._make_connector_with_max_tlp("TLP:AMBER")
        self.assertTrue(conn._is_tlp_allowed({}))
