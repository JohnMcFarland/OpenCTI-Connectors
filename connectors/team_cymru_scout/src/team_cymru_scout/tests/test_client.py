import unittest
from unittest.mock import MagicMock, patch

from team_cymru_scout.client import TeamCymruScoutClient


class TestTeamCymruScoutClient(unittest.TestCase):

    def setUp(self):
        self.helper = MagicMock()
        self.client = TeamCymruScoutClient(self.helper, "test-api-key")

    def test_auth_header(self):
        self.assertEqual(
            self.client.headers["Authorization"], "Token test-api-key"
        )

    @patch.object(TeamCymruScoutClient, "_get")
    def test_get_ip_details_encodes_ipv6(self, mock_get):
        mock_get.return_value = {"identity": {}}
        self.client.get_ip_details("2001:db8::1")
        url = mock_get.call_args[0][0]
        self.assertNotIn(":", url.split("/api/scout/ip/")[1].split("/details")[0])
        self.assertIn("2001%3Adb8%3A%3A1", url)

    @patch.object(TeamCymruScoutClient, "_get")
    def test_get_ip_details_ipv4_unchanged(self, mock_get):
        mock_get.return_value = {"identity": {}}
        self.client.get_ip_details("8.8.8.8")
        url = mock_get.call_args[0][0]
        self.assertIn("/api/scout/ip/8.8.8.8/details", url)

    @patch.object(TeamCymruScoutClient, "_get")
    def test_foundation_extracts_first_data(self, mock_get):
        mock_get.return_value = {"data": [{"ip": "1.2.3.4", "asn": 1234}]}
        result = self.client.get_ip_foundation("1.2.3.4")
        self.assertEqual(result, {"ip": "1.2.3.4", "asn": 1234})

    @patch.object(TeamCymruScoutClient, "_get")
    def test_foundation_returns_none_on_empty_data(self, mock_get):
        mock_get.return_value = {"data": []}
        self.assertIsNone(self.client.get_ip_foundation("1.2.3.4"))

    @patch.object(TeamCymruScoutClient, "_get")
    def test_foundation_returns_none_on_none(self, mock_get):
        mock_get.return_value = None
        self.assertIsNone(self.client.get_ip_foundation("1.2.3.4"))

    @patch.object(TeamCymruScoutClient, "_get")
    def test_search_passes_params(self, mock_get):
        mock_get.return_value = {"ips": []}
        self.client.search("example.com", size=5)
        _, kwargs = mock_get.call_args
        self.assertEqual(kwargs["params"], {"query": "example.com", "size": 5})

    def test_get_returns_none_on_http_error(self):
        import requests as req

        with patch.object(self.client.session, "get") as mock:
            mock.return_value.raise_for_status.side_effect = (
                req.exceptions.HTTPError("500")
            )
            result = self.client._get("https://scout.cymru.com/test")
            self.assertIsNone(result)

    def test_get_returns_none_on_json_error(self):
        import json

        with patch.object(self.client.session, "get") as mock:
            mock.return_value.raise_for_status.return_value = None
            mock.return_value.json.side_effect = json.JSONDecodeError(
                "bad", "doc", 0
            )
            mock.return_value.text = "not json"
            result = self.client._get("https://scout.cymru.com/test")
            self.assertIsNone(result)
