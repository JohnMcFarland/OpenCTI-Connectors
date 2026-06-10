from __future__ import annotations

import os
import re
import shlex
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from pycti import OpenCTIConnectorHelper

APP_NAME = "Procedure_Deconstruction"
APP_VERSION = "0.3.0"

_RE_WIN_FILEPATH  = re.compile(r'^[A-Za-z]:\\(?:[^\\/:*?"<>|\r\n]+\\)*[^\\/:*?"<>|\r\n]+\.[A-Za-z0-9]+$')
_RE_WIN_DIRPATH   = re.compile(r'^[A-Za-z]:\\(?:[^\\/:*?"<>|\r\n]+\\?)*$')
_RE_UNC_PATH      = re.compile(r'^\\\\[^\\]+\\[^\\]+')
_RE_UNIX_PATH     = re.compile(r'^/[^\s]+')
_RE_IPV4          = re.compile(r'^(?:\d{1,3}\.){3}\d{1,3}$')
_RE_DOMAIN        = re.compile(r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$')
_RE_FLAG          = re.compile(r'^-')
_RE_STRIP_QUOTES  = re.compile(r'^(["\'])(.*)\1$')
_WHITESPACE       = re.compile(r'\s+')

_ROLE_BADGE: Dict[str, str] = {
    "Command/Executable":   "⚙️",
    "Subcommand":           "▶️",
    "Flag/InteractionMode": "🔘",
    "Flag/IncludeSet":      "📎",
    "Variable":             "📄",
}


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _safe_str(x: Any) -> str:
    return "" if x is None else str(x)


def _classify_variable(token: str) -> str:
    t = token.strip()
    if _RE_IPV4.match(t):
        return "IPv4-Addr"
    if _RE_DOMAIN.match(t) and "." in t and not t.startswith("-"):
        return "Domain-Name"
    if _RE_WIN_FILEPATH.match(t):
        return "StixFile"
    if _RE_WIN_DIRPATH.match(t) or _RE_UNC_PATH.match(t):
        return "Directory"
    if _RE_UNIX_PATH.match(t):
        return "Directory" if t.endswith("/") else "StixFile"
    return "Text"


class ComponentType:
    __slots__ = ("token", "entity_type", "component_role", "index")

    def __init__(self, token: str, entity_type: str, component_role: str, index: int) -> None:
        self.token = token
        self.entity_type = entity_type
        self.component_role = component_role
        self.index = index


class ProcedureDeconstructionConnector:
    def __init__(self) -> None:
        self.helper = OpenCTIConnectorHelper(
            {
                "opencti_url": os.environ.get("OPENCTI_URL"),
                "opencti_token": os.environ.get("OPENCTI_TOKEN"),
                "connector_id": os.environ.get("CONNECTOR_ID"),
                "connector_type": os.environ.get("CONNECTOR_TYPE", "INTERNAL_ENRICHMENT"),
                "connector_name": os.environ.get("CONNECTOR_NAME", APP_NAME),
                "connector_scope": os.environ.get("CONNECTOR_SCOPE", "Report"),
                "connector_confidence_level": int(os.environ.get("CONNECTOR_CONFIDENCE_LEVEL", "0")),
                "connector_log_level": os.environ.get("CONNECTOR_LOG_LEVEL", "info"),
            }
        )
        self.api = self.helper.api
        self.max_first = int(os.environ.get("MAX_FIRST", "500"))
        self.helper.connector_logger.info(f"Starting {APP_NAME} v{APP_VERSION}")

    def _graphql(self, query: str, variables: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        return self.api.query(query, variables or {})

    def _list_processes_in_report(self, report_id: str) -> Tuple[str, List[Dict[str, Any]]]:
        q = """
        query ProcDecon_ReportObjects($id: String!, $first: Int!) {
          report(id: $id) {
            id
            name
            objects(first: $first) {
              edges {
                node {
                  ... on BasicObject { id entity_type }
                  ... on Process {
                    id
                    entity_type
                    pid
                    command_line
                    observable_value
                  }
                }
              }
            }
          }
        }
        """
        res = self._graphql(q, {"id": report_id, "first": self.max_first})
        r = ((res or {}).get("data") or {}).get("report") or {}
        report_name = _safe_str(r.get("name")) or "(untitled report)"
        edges = ((r.get("objects") or {}).get("edges")) or []
        procs: List[Dict[str, Any]] = []
        for e in edges:
            n = (e or {}).get("node") or {}
            etype = _safe_str(n.get("entity_type")).lower()
            if etype == "process" or ("command_line" in n and n.get("id")):
                procs.append(n)
        return report_name, procs

    def _tokenize(self, command_line: str) -> List[str]:
        s = (command_line or "").strip()
        if not s:
            return []
        try:
            tokens = shlex.split(s, posix=False)
        except Exception:
            tokens = _WHITESPACE.split(s)
        out: List[str] = []
        for t in tokens:
            t = t.strip()
            if not t:
                continue
            m = _RE_STRIP_QUOTES.match(t)
            if m:
                t = m.group(2)
            out.append(t)
        return out

    def _classify_tokens(self, tokens: List[str]) -> List[ComponentType]:
        components: List[ComponentType] = []
        for i, token in enumerate(tokens):
            if i == 0:
                role = "Command/Executable"
                etype = "Software"
            elif _RE_FLAG.match(token):
                role = "Flag/IncludeSet" if (":" in token or "=" in token) else "Flag/InteractionMode"
                etype = "Text"
            elif (
                _RE_WIN_FILEPATH.match(token)
                or _RE_WIN_DIRPATH.match(token)
                or _RE_UNC_PATH.match(token)
                or _RE_UNIX_PATH.match(token)
                or _RE_IPV4.match(token)
                or _RE_DOMAIN.match(token)
            ):
                role = "Variable"
                etype = _classify_variable(token)
            else:
                role = "Subcommand"
                etype = "Text"
            components.append(ComponentType(token=token, entity_type=etype, component_role=role, index=i))
        return components

    _SCO_TYPE_MAP: Dict[str, Tuple[str, str]] = {
        "Software":    ("software",    "name"),
        "Text":        ("text",        "value"),
        "Directory":   ("directory",   "path"),
        "StixFile":    ("file",        "name"),
        "IPv4-Addr":   ("ipv4-addr",   "value"),
        "Domain-Name": ("domain-name", "value"),
    }

    def _create_observable(self, comp: ComponentType, report_id: str, process_id: str) -> Optional[str]:
        mapping = self._SCO_TYPE_MAP.get(comp.entity_type)
        if not mapping:
            self.helper.connector_logger.error(
                "Unknown entity_type in SCO_TYPE_MAP",
                {"entity_type": comp.entity_type, "token": comp.token},
            )
            return None
        stix_type, value_field = mapping
        try:
            obj = self.api.stix_cyber_observable.create(
                observableData={"type": stix_type, value_field: comp.token}
            )
            oid = (obj or {}).get("id")
            if not oid:
                raise RuntimeError(f"stix_cyber_observable.create returned no id for type={stix_type!r}")
            self._add_to_report(report_id, oid)
            rid = self._create_related_to(oid, process_id)
            if rid:
                self._add_to_report(report_id, rid)
            return oid
        except Exception as e:
            self.helper.connector_logger.error(
                "Failed to create observable component",
                {"entity_type": comp.entity_type, "stix_type": stix_type, "token": comp.token, "error": str(e)},
            )
            return None

    def _create_component(self, comp: ComponentType, report_id: str, process_id: str) -> Optional[str]:
        return self._create_observable(comp, report_id, process_id)

    def _add_to_report(self, report_id: str, object_id: str) -> None:
        try:
            self.api.report.add_stix_object_or_stix_relationship(
                id=report_id,
                stixObjectOrStixRelationshipId=object_id,
            )
        except Exception as e:
            self.helper.connector_logger.warning(
                "Could not add object to report (may already be a member)",
                {"report_id": report_id, "object_id": object_id, "error": str(e)},
            )

    def _create_related_to(self, from_id: str, to_id: str) -> Optional[str]:
        try:
            rel = self.api.stix_core_relationship.create(
                fromId=from_id,
                toId=to_id,
                relationship_type="related-to",
            )
            rid = (rel or {}).get("id")
            if not rid:
                raise RuntimeError("stix_core_relationship.create returned no id")
            return rid
        except Exception as e:
            self.helper.connector_logger.error(
                "Failed to create related-to relationship",
                {"from_id": from_id, "to_id": to_id, "error": str(e)},
            )
            return None

    def _create_note(self, title: str, content: str, object_ids: List[str]) -> str:
        q = """
        mutation ProcDecon_NoteAdd($input: NoteAddInput!) {
          noteAdd(input: $input) { id }
        }
        """
        res = self._graphql(q, {"input": {
            "attribute_abstract": title,
            "content": content,
            "objects": object_ids,
            "note_types": [APP_NAME],
        }})
        nid = ((res or {}).get("data") or {}).get("noteAdd", {}).get("id")
        if not nid:
            raise RuntimeError(f"noteAdd returned no id: {res}")
        return nid

    def _process_message(self, data: Dict[str, Any]) -> str:
        entity_id   = _safe_str(data.get("entity_id") or data.get("entity") or data.get("id"))
        entity_type = _safe_str(data.get("entity_type") or data.get("type"))

        if not entity_id or not entity_type:
            self.helper.connector_logger.error("Skip: message missing entity_id/entity_type", {"data_keys": list((data or {}).keys())})
            return "SKIP"

        if entity_type.lower() != "report":
            self.helper.connector_logger.info("Skip: unsupported entity_type", {"entity_type": entity_type, "entity_id": entity_id})
            return "SKIP"

        try:
            report_name, procs = self._list_processes_in_report(entity_id)
        except Exception as e:
            self.helper.connector_logger.error("Enumeration failed", {"entity_id": entity_id, "error": str(e)})
            raise

        self.helper.connector_logger.info(f"Found {len(procs)} Process object(s) in report", {"report_id": entity_id, "report_name": report_name})

        if not procs:
            note_id = self._create_note(
                title=f"{APP_NAME}: {report_name}",
                content=(
                    f"## {APP_NAME} — Run Report\n\n"
                    f"| Field | Value |\n"
                    f"|---|---|\n"
                    f"| Version | {APP_VERSION} |\n"
                    f"| Generated | {utc_now_iso()} |\n"
                    f"| Report | {report_name} |\n\n"
                    f"> No Process objects found in this report. Nothing to deconstruct.\n"
                ),
                object_ids=[entity_id],
            )
            self.helper.connector_logger.info("No processes found; attached informational note", {"note_id": note_id})
            return "OK"

        note_lines: List[str] = [
            f"## {APP_NAME} — Run Report",
            "",
            "| Field | Value |",
            "|---|---|",
            f"| Version | {APP_VERSION} |",
            f"| Generated | {utc_now_iso()} |",
            f"| Report | {report_name} |",
            f"| Processes found | {len(procs)} |",
            "",
        ]

        total_components = 0

        for proc_num, proc in enumerate(procs, 1):
            proc_id = _safe_str(proc.get("id"))
            pid     = _safe_str(proc.get("pid")) or "—"
            cmd     = _safe_str(proc.get("command_line") or proc.get("observable_value"))

            note_lines += [
                "---",
                "",
                f"### Process {proc_num}",
                "",
                "| Field | Value |",
                "|---|---|",
                f"| PID | `{pid}` |",
                f"| Object ID | `{proc_id}` |",
                f"| Command Line | `{cmd or '(empty)'}` |",
                "",
            ]

            if not cmd:
                note_lines.append("> ⚠️ Skipped: no command_line value present.")
                note_lines.append("")
                continue

            tokens     = self._tokenize(cmd)
            components = self._classify_tokens(tokens)

            note_lines += [
                f"#### Components ({len(components)})",
                "",
                "| # | Role | Type | Value | Status |",
                "|---|---|---|---|---|",
            ]

            for comp in components:
                oid    = self._create_component(comp, entity_id, proc_id)
                badge  = _ROLE_BADGE.get(comp.component_role, "🔹")
                status = f"✅ `{oid}`" if oid else "❌ FAILED"
                note_lines.append(
                    f"| {comp.index} | {badge} {comp.component_role} "
                    f"| `{comp.entity_type}` | `{comp.token}` | {status} |"
                )
                if oid:
                    total_components += 1
                    self.helper.connector_logger.info(
                        "Created component",
                        {
                            "index": comp.index,
                            "role": comp.component_role,
                            "entity_type": comp.entity_type,
                            "token": comp.token,
                            "component_id": oid,
                            "process_id": proc_id,
                            "report_id": entity_id,
                        },
                    )

            note_lines.append("")

        note_lines += [
            "---",
            "",
            f"**Total components created: {total_components}**",
        ]

        try:
            note_id = self._create_note(
                title=f"{APP_NAME}: {report_name}",
                content="\n".join(note_lines).rstrip() + "\n",
                object_ids=[entity_id],
            )
            self.helper.connector_logger.info("Attached run note", {"note_id": note_id, "total_components": total_components})
        except Exception as e:
            self.helper.connector_logger.error("Failed to create run note", {"error": str(e)})
            raise

        return "OK"

    def run(self) -> None:
        self.helper.listen(self._process_message)


if __name__ == "__main__":
    ProcedureDeconstructionConnector().run()
