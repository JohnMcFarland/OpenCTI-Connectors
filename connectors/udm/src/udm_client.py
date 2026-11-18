"""UniFi Network API client for the UDM Pro (UniFi OS, local API key).

All calls go through UniFi OS's `/proxy/network` prefix with the `X-API-Key`
header. Two API generations are used, as the Network app still splits them:

  * legacy `/api/s/{site}/...`: clients (rest/user, stat/sta), devices (WAN IP).
  * v2 `/v2/api/site/{site}/traffic-flows`: the flow log behind the
    "Traffic" / "Flows" view.
  * v2 `/v2/api/site/{site}/system-log/all` with `categories: ["SECURITY"]`: IPS
    threats and honeypot hits (legacy stat/ips/event returns 404 on Network 9+).

Every error raises. A failed page must fail the run (so the cursor does not move
past data that was never read), never be returned as "no more data".
"""

from __future__ import annotations

from dataclasses import dataclass

import requests

from .config import Settings


_GATEWAY_TYPES = {"udm", "ugw", "uxg", "udr", "ucg"}


class UdmError(RuntimeError):
    pass


@dataclass
class FlowFetch:
    records: list[dict]
    pages: int
    stopped: str  # why paging ended: "end", "older-than-window", "max-pages"


class UdmClient:
    def __init__(self, settings: Settings, log, session: requests.Session | None = None) -> None:
        self.settings = settings
        self.log = log
        self.base = f"https://{settings.udm_host}/proxy/network"
        self.site = settings.udm_site
        self.session = session or requests.Session()
        self.session.headers.update({
            "X-API-Key": settings.udm_api_key,
            "Accept": "application/json",
        })
        self.verify = settings.verify
        if self.verify is False:
            import urllib3

            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    # -- transport ---------------------------------------------------------

    def _call(self, method: str, path: str, payload: dict | None = None):
        url = f"{self.base}{path}"
        try:
            resp = self.session.request(method, url, json=payload, verify=self.verify,
                                        timeout=self.settings.udm_request_timeout)
        except requests.RequestException as exc:
            raise UdmError(f"{method} {path} failed: {exc}") from exc
        if resp.status_code >= 400:
            raise UdmError(f"{method} {path} -> HTTP {resp.status_code}: {resp.text[:200]}")
        try:
            body = resp.json()
        except ValueError as exc:
            raise UdmError(f"{method} {path} returned non-JSON") from exc
        # Legacy endpoints wrap results as {"meta": {"rc": "ok"}, "data": [...]}.
        if isinstance(body, dict) and isinstance(body.get("meta"), dict):
            if body["meta"].get("rc") not in (None, "ok"):
                raise UdmError(f"{method} {path} -> {body['meta']}")
        return body

    def _legacy(self, method: str, endpoint: str, payload: dict | None = None) -> list[dict]:
        body = self._call(method, f"/api/s/{self.site}/{endpoint}", payload)
        data = body.get("data") if isinstance(body, dict) else body
        if not isinstance(data, list):
            raise UdmError(f"{endpoint}: unexpected response shape")
        return data

    # -- inventory ---------------------------------------------------------

    def check(self) -> None:
        """Fail fast on a bad host, key, site or TLS setting."""
        self._legacy("GET", "stat/sysinfo")

    def known_clients(self) -> list[dict]:
        """Every client the controller remembers (offline ones included), merged with
        the live list so current IPs are known. Keyed by MAC."""
        merged: dict[str, dict] = {}
        for c in self._legacy("GET", "rest/user"):
            mac = (c.get("mac") or "").lower()
            if mac:
                merged[mac] = dict(c)
        for c in self._legacy("GET", "stat/sta"):
            mac = (c.get("mac") or "").lower()
            if mac:
                merged.setdefault(mac, {}).update(c)
        return list(merged.values())

    def devices(self) -> list[dict]:
        """UniFi devices (gateway, switches, APs) with model, name, MAC, firmware."""
        return self._legacy("GET", "stat/device")

    def port_forwards(self) -> list[dict]:
        return self._legacy("GET", "rest/portforward")

    def wan_ips(self, devices: list[dict] | None = None) -> list[str]:
        """The gateway's WAN addresses. Switches and APs also report an `uplink.ip`,
        but that is their own LAN address, so only gateway devices are read."""
        ips: list[str] = []
        for device in self.devices() if devices is None else devices:
            if not is_gateway(device):
                continue
            for key in ("wan1", "wan2", "uplink"):
                ip = (device.get(key) or {}).get("ip")
                if ip and ip not in ips:
                    ips.append(ip)
        return ips

    # -- traffic-flows -------------------------------------------------------

    def blocked_flows(self, since_ms: int) -> FlowFetch:
        """Blocked flows whose last activity is at or after `since_ms`.

        The endpoint has no usable server-side time filter (it breaks the action
        filter), so pages are read until one lies wholly before `since_ms`. That
        early stop is only trusted while pages come back newest-first; if a page is
        not in descending time order, paging continues to the end (or max pages).
        """
        out: list[dict] = []
        page = 0
        descending = True
        prev_min: int | None = None
        while True:
            if page >= self.settings.udm_max_pages:
                self.log.warning("traffic-flows: hit UDM_MAX_PAGES; older flows not read",
                                 {"pages": page, "since_ms": since_ms})
                return FlowFetch(out, page, "max-pages")
            body = self._call("POST", f"/v2/api/site/{self.site}/traffic-flows",
                              self._flow_query(page))
            batch = body.get("data") if isinstance(body, dict) else None
            if batch is None:
                raise UdmError("traffic-flows: response has no 'data'")
            page += 1
            if not batch:
                return FlowFetch(out, page, "end")
            times = [_last_ms(r) for r in batch]
            ordered = ([prev_min] if prev_min is not None else []) + times
            prev_min = min(times)
            if descending and any(a < b for a, b in zip(ordered, ordered[1:])):
                descending = False
                self.log.warning("traffic-flows: pages are not newest-first; reading all pages")
            out.extend(r for r, t in zip(batch, times) if t >= since_ms)
            if descending and max(times) < since_ms:
                return FlowFetch(out, page, "older-than-window")
            if not body.get("has_next", False):
                return FlowFetch(out, page, "end")

    def _flow_query(self, page: int) -> dict:
        empty = ("risk", "policy", "policy_type", "protocol", "direction", "service",
                 "source_ip", "source_mac", "source_host", "source_domain", "source_port",
                 "source_region", "source_network_id", "source_zone_id",
                 "destination_ip", "destination_mac", "destination_host",
                 "destination_domain", "destination_port", "destination_region",
                 "destination_network_id", "destination_zone_id",
                 "in_network_id", "out_network_id", "except_for", "next_ai_query")
        query: dict = {k: [] for k in empty}
        query.update({
            "action": ["blocked"],
            "search_text": "",
            "skip_count": False,  # has_next may rely on the count
            "pageNumber": page,
            "pageSize": self.settings.udm_page_size,
        })
        return query

    # -- security log ---------------------------------------------------------------

    def security_events(self, start_ms: int, end_ms: int) -> FlowFetch:
        return self.system_log("SECURITY", start_ms, end_ms)

    def audit_events(self, start_ms: int, end_ms: int) -> FlowFetch:
        return self.system_log("AUDIT", start_ms, end_ms)

    def system_log(self, category: str, start_ms: int, end_ms: int) -> FlowFetch:
        """`category` entries of the system log in [start_ms, end_ms], filtered and
        time-bounded server-side, read page by page."""
        out: list[dict] = []
        page = 0
        while True:
            if page >= self.settings.udm_max_pages:
                return FlowFetch(out, page, "max-pages")
            body = self._call("POST", f"/v2/api/site/{self.site}/system-log/all", {
                "timestampFrom": start_ms, "timestampTo": end_ms,
                "pageSize": self.settings.udm_page_size, "pageNumber": page,
                "categories": [category],
            })
            batch = body.get("data") if isinstance(body, dict) else None
            if batch is None:
                raise UdmError("system-log: response has no 'data'")
            page += 1
            # Belt and braces: keep only `category` even if the filter were ignored.
            out.extend(e for e in batch if e.get("category") == category)
            if not batch or page >= (body.get("total_page_count") or 0):
                return FlowFetch(out, page, "end")


def is_gateway(device: dict) -> bool:
    return device.get("type") in _GATEWAY_TYPES or bool(device.get("wan1"))


def _last_ms(raw: dict) -> int:
    v = raw.get("time") or raw.get("flow_start_time") or 0
    try:
        v = float(v)
    except (TypeError, ValueError):
        return 0
    return int(v * 1000) if 0 < v < 1e11 else int(v)
