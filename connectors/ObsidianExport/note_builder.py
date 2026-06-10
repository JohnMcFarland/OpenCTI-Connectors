"""
note_builder.py — Obsidian Markdown Note Builder
=================================================
Converts a container graph dict (produced by GraphFetcher) into a structured
Obsidian-compatible Markdown note.

Output structure:
  1. YAML frontmatter (opencti_id, title, author, published, tlp, confidence,
     status, labels, external_ref, folder vault routing hint)
  2. H1 title
  3. Obsidian [!info] callout block with key container metadata
  4. ## Description (if present)
  5. One ## section per SDO entity type in CTI Ingestion Manual creation order
     Each entity gets a ### sub-heading (its name as a [[wikilink]]) followed
     by outgoing relationships rendered as prose sentences with [[wikilinks]]
  6. ## Observables table (Type | Value | Relationships)
  7. Export timestamp footer

Design decisions:
  WIKILINKS: Entity names are used as wikilink anchors without path prefix.
  Obsidian resolves wikilinks by filename across the vault.

  PROSE vs TABLE: Prose sentences for SDO-to-SDO relationships. Observables
  in a table — generating prose for 50+ IPs produces undifferentiated lines
  harder to scan than a table.

  RELATIONSHIP GROUPING: Grouped by source entity, rendered under source
  section only. Prevents the same edge appearing in both source and target.

  SECTION ORDER: Follows CTI Ingestion Manual Chapter 3 Step 4 creation order.

  DESCRIPTION TRUNCATION: Relationship descriptions truncated at 300 chars.
  Full descriptions always available in OpenCTI.

  ITALIC OBSERVABLES: Values italicised per Intelligence Production Standard
  typographic rules (section 3.4).
"""

import re
from datetime import datetime, timezone

from graph_fetcher import OBSERVABLE_ENTITY_TYPES

# ---------------------------------------------------------------------------
# Section ordering and heading mapping
# ---------------------------------------------------------------------------

SECTION_ORDER: list[str] = [
    "Threat-Actor-Group",
    "Threat-Actor-Individual",
    "Intrusion-Set",
    "Campaign",
    "Malware",
    "Tool",
    "Attack-Pattern",
    "Infrastructure",
    "Vulnerability",
    "Channel",
    "Narrative",
    "Organization",
    "Sector",
    "Individual",
    "System",
    "Country",
    "Region",
    "City",
    "Incident",
    "Course-Of-Action",
    "Malware-Analysis",
]

SECTION_HEADINGS: dict[str, str] = {
    "Threat-Actor-Group":       "Threat Actor Groups",
    "Threat-Actor-Individual":  "Threat Actor Individuals",
    "Intrusion-Set":            "Intrusion Sets",
    "Campaign":                 "Campaigns",
    "Malware":                  "Malware",
    "Tool":                     "Tools",
    "Attack-Pattern":           "Attack Patterns",
    "Infrastructure":           "Infrastructure",
    "Vulnerability":            "Vulnerabilities",
    "Channel":                  "Channels",
    "Narrative":                "Narratives",
    "Organization":             "Organisations",
    "Sector":                   "Sectors",
    "Individual":               "Individuals",
    "System":                   "Systems",
    "Country":                  "Countries",
    "Region":                   "Regions",
    "City":                     "Cities",
    "Incident":                 "Incidents",
    "Course-Of-Action":         "Courses of Action",
    "Malware-Analysis":         "Malware Analyses",
}

# ---------------------------------------------------------------------------
# Relationship verb mapping
# ---------------------------------------------------------------------------

REL_VERB: dict[str, str] = {
    "attributed-to":      "is attributed to",
    "uses":               "uses",
    "targets":            "targets",
    "exploits":           "exploits",
    "delivers":           "delivers",
    "related-to":         "is related to",
    "part-of":            "is part of",
    "belongs-to":         "belongs to",
    "resolves-to":        "resolves to",
    "communicates-with":  "communicates with",
    "has":                "has",
    "impersonates":       "impersonates",
    "sighted-at":         "was sighted at",
    "originates-from":    "originates from",
    "located-at":         "is located at",
    "variant-of":         "is a variant of",
    "drops":              "drops",
    "downloads":          "downloads",
    "beacons-to":         "beacons to",
    "exfiltrates-to":     "exfiltrates to",
    "compromises":        "compromises",
    "controls":           "controls",
    "indicates":          "indicates",
    "investigates":       "investigates",
    "remediates":         "remediates",
    "subtechnique-of":    "is a sub-technique of",
    "duplicate-of":       "is a duplicate of",
    "derived-from":       "is derived from",
    "consists-of":        "consists of",
    "revoked-by":         "is revoked by",
    "migrates-to":        "migrates to",
}

_WIKILINK_FORBIDDEN = re.compile(r"[\[\]#\^|\\]")
_REL_DESC_MAX_CHARS = 300


class NoteBuilder:
    """
    Builds Obsidian-compatible Markdown notes from OpenCTI container graph data.

    Stateless: all inputs are passed to build_note() as a single dict.
    A single NoteBuilder instance can safely be reused across export jobs.
    """

    def __init__(self, helper):
        """
        Args:
            helper: OpenCTIConnectorHelper instance — used for logging only.
        """
        self.helper = helper

    def build_note(self, container_data: dict) -> str:
        """
        Build the full Markdown note content for a container.

        Args:
            container_data: Dict produced by GraphFetcher.fetch_container().

        Returns:
            Complete Obsidian-compatible Markdown note as a string.
        """
        container = container_data["container"]
        entity_type = container_data["entity_type"]
        objects_by_type = container_data.get("objects_by_type", {})
        relationships = container_data.get("relationships", [])

        entity_lookup = self._build_entity_lookup(objects_by_type)
        container_id = container.get("id") or ""
        if container_id:
            entity_lookup[container_id] = {
                "name": container.get("name") or "Untitled",
                "entity_type": entity_type,
            }

        rel_by_source = self._build_rel_index(relationships)

        container_name = container.get("name") or "Untitled"
        parts: list[str] = []

        parts.append(self._build_frontmatter(container, entity_type))
        parts.append(f"# {self._escape_md_block(container_name)}\n")
        parts.append(self._build_metadata_callout(container, entity_type))

        description = (container.get("description") or "").strip()
        if description:
            parts.append("## Description\n")
            parts.append(description + "\n")

        for type_key in SECTION_ORDER:
            entities = objects_by_type.get(type_key, [])
            if not entities:
                continue
            section = self._build_sdo_section(
                entity_type_key=type_key,
                entities=entities,
                rel_by_source=rel_by_source,
                entity_lookup=entity_lookup,
            )
            if section:
                parts.append(section)

        # Forward-compatibility: render entity types not in SECTION_ORDER
        for type_key, entities in objects_by_type.items():
            if type_key in SECTION_ORDER:
                continue
            if type_key in OBSERVABLE_ENTITY_TYPES:
                continue
            if not entities:
                continue
            heading = type_key.replace("-", " ").title()
            section = self._build_sdo_section(
                entity_type_key=type_key,
                entities=entities,
                rel_by_source=rel_by_source,
                entity_lookup=entity_lookup,
                heading_override=heading,
            )
            if section:
                parts.append(section)

        observable_entities: list[dict] = []
        for obs_type in OBSERVABLE_ENTITY_TYPES:
            observable_entities.extend(objects_by_type.get(obs_type, []))

        if observable_entities:
            parts.append(
                self._build_observables_section(
                    observable_entities=observable_entities,
                    rel_by_source=rel_by_source,
                    entity_lookup=entity_lookup,
                )
            )

        now_utc = datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        parts.append(f"\n---\n*Exported from OpenCTI on {now_utc}*\n")

        return "\n".join(parts)

    def _build_frontmatter(self, container: dict, entity_type: str) -> str:
        """
        Build the YAML frontmatter block.

        Published date uses the source publication date, never ingestion date.
        TLP defaults to TLP:AMBER+STRICT if no marking is present.
        """
        published_raw = (
            container.get("published")
            or container.get("created")
            or ""
        )
        published = published_raw[:10] if published_raw else ""
        ingested = datetime.now(tz=timezone.utc).strftime("%Y-%m-%d")
        tlp = self._extract_tlp(container)
        created_by = container.get("createdBy") or {}
        author = (created_by.get("name") or "Unknown").strip()
        confidence = container.get("confidence") or 0
        status_obj = container.get("status") or {}
        status_template = (status_obj.get("template") or {})
        status = status_template.get("name") or ""
        labels_raw = container.get("labels") or []
        labels: list[str] = []
        for lbl in labels_raw:
            val = lbl.get("value") if isinstance(lbl, dict) else lbl
            if val and isinstance(val, str):
                labels.append(val.strip())
        external_ref = self._extract_external_ref(container)
        folder = "Reports" if entity_type == "Report" else "Cases"
        report_types = container.get("report_types") or []
        report_type = report_types[0] if report_types else ""

        lines: list[str] = ["---"]
        lines.append(f'opencti_id: "{self._yaml_escape(container.get("id") or "")}"')
        lines.append(f'title: "{self._yaml_escape(container.get("name") or "")}"')
        lines.append(f"container_type: {entity_type}")
        if report_type:
            lines.append(f"report_type: {report_type}")
        lines.append(f'author: "{self._yaml_escape(author)}"')
        if published:
            lines.append(f"published: {published}")
        lines.append(f"ingested: {ingested}")
        lines.append(f"tlp: {tlp}")
        lines.append(f"confidence: {confidence}")
        if status:
            lines.append(f"status: {status}")
        if labels:
            lines.append("labels:")
            for lbl in labels:
                lines.append(f'  - "{self._yaml_escape(lbl)}"')
        if external_ref:
            lines.append(f'external_ref: "{self._yaml_escape(external_ref)}"')
        lines.append(f"folder: {folder}")
        lines.append("---")

        return "\n".join(lines) + "\n"

    def _build_metadata_callout(self, container: dict, entity_type: str) -> str:
        """
        Build an Obsidian [!info] callout block with key container metadata.
        """
        tlp = self._extract_tlp(container)
        created_by = container.get("createdBy") or {}
        author = (created_by.get("name") or "Unknown").strip()
        published_raw = (container.get("published") or container.get("created") or "")
        published = published_raw[:10] if published_raw else "Unknown"
        confidence = container.get("confidence") or 0
        status_obj = container.get("status") or {}
        status_template = (status_obj.get("template") or {})
        status = status_template.get("name") or ""
        report_types = container.get("report_types") or []
        report_type = report_types[0] if report_types else ""
        external_ref = self._extract_external_ref(container)

        lines: list[str] = [f"> [!info] {entity_type} Metadata"]
        lines.append(f"> **Author:** {self._escape_md_inline(author)}  ")
        lines.append(f"> **Published:** {published}  ")
        lines.append(f"> **TLP:** {tlp}  ")
        lines.append(f"> **Confidence:** {confidence}/100  ")
        if report_type:
            lines.append(f"> **Type:** {self._escape_md_inline(report_type)}  ")
        if status:
            lines.append(f"> **Status:** {self._escape_md_inline(status)}  ")
        if external_ref:
            lines.append(f"> **Source:** [{external_ref}]({external_ref})  ")

        return "\n".join(lines) + "\n"

    def _build_sdo_section(
        self,
        entity_type_key: str,
        entities: list[dict],
        rel_by_source: dict[str, list],
        entity_lookup: dict[str, dict],
        heading_override: str | None = None,
    ) -> str:
        """
        Build a Markdown section for a given SDO entity type.

        Each entity: ### [[Name]] + context line + outgoing relationship prose.
        """
        heading = heading_override or SECTION_HEADINGS.get(
            entity_type_key, entity_type_key.replace("-", " ").title()
        )
        lines: list[str] = [f"## {heading}\n"]
        rendered_any = False

        for entity in entities:
            entity_id = entity.get("id") or ""
            name = self._get_entity_name(entity)
            if not name:
                self.helper.log_debug(
                    f"Skipping {entity_type_key} {entity_id}: no name found"
                )
                continue

            rendered_any = True
            lines.append(f"### [[{self._wikilink(name)}]]\n")

            context = self._get_entity_context(entity, entity_type_key)
            if context:
                lines.append(context + "\n")

            rels = rel_by_source.get(entity_id, [])
            if rels:
                for rel in rels:
                    prose = self._render_relationship_prose(
                        rel=rel,
                        entity_lookup=entity_lookup,
                        source_name=name,
                    )
                    if prose:
                        lines.append(prose)
                lines.append("")
            else:
                lines.append("")

        if not rendered_any:
            return ""

        return "\n".join(lines) + "\n"

    def _get_entity_context(self, entity: dict, entity_type: str) -> str:
        """
        Return a brief italicised context line for an entity (type-specific).
        """
        if entity_type == "Malware":
            malware_types = entity.get("malware_types") or []
            if malware_types:
                return f"*Type: {', '.join(malware_types)}*"
            is_family = entity.get("is_family")
            if is_family is True:
                return "*Malware family*"

        elif entity_type == "Tool":
            tool_types = entity.get("tool_types") or []
            if tool_types:
                return f"*Tool type: {', '.join(tool_types)}*"

        elif entity_type == "Attack-Pattern":
            ext_refs = entity.get("externalReferences") or {}
            if isinstance(ext_refs, dict):
                ext_refs = [e.get("node", e) for e in ext_refs.get("edges", [])]
            for ref in ext_refs:
                ext_id = ref.get("external_id") or ""
                source = ref.get("source_name") or ""
                if ext_id.startswith("T") and "mitre" in source.lower():
                    return f"*ATT&CK ID: {ext_id}*"
            mitre_id = entity.get("x_mitre_id") or ""
            if mitre_id:
                return f"*ATT&CK ID: {mitre_id}*"

        elif entity_type == "Infrastructure":
            infra_types = entity.get("infrastructure_types") or []
            if infra_types:
                return f"*Infrastructure type: {', '.join(infra_types)}*"

        elif entity_type == "Vulnerability":
            name = entity.get("name") or ""
            if name.upper().startswith("CVE-"):
                cvss = entity.get("x_opencti_cvss_base_score")
                if cvss is not None:
                    return f"*CVSS base score: {cvss}*"

        elif entity_type == "Channel":
            channel_types = entity.get("channel_types") or []
            if channel_types:
                return f"*Channel type: {', '.join(channel_types)}*"

        elif entity_type in ("Organization", "Sector"):
            desc = (entity.get("description") or "").strip()
            if desc:
                first = desc.split(".")[0].strip()
                if first and len(first) < 120:
                    return f"*{self._escape_md_inline(first)}*"

        return ""

    def _build_observables_section(
        self,
        observable_entities: list[dict],
        rel_by_source: dict[str, list],
        entity_lookup: dict[str, dict],
    ) -> str:
        """
        Build the Observables section as a Markdown table.

        Observable values are italicised per the Intelligence Production Standard.
        Columns: Type | Value | Relationships
        """
        if not observable_entities:
            return ""

        lines: list[str] = ["## Observables\n"]
        lines.append("| Type | Value | Relationships |")
        lines.append("|------|-------|---------------|")

        for obs in observable_entities:
            obs_id = obs.get("id") or ""
            obs_type = obs.get("entity_type") or "Unknown"
            value = (
                obs.get("value")
                or obs.get("observable_value")
                or obs.get("name")
                or (obs.get("hashes") or {}).get("SHA-256")
                or (obs.get("hashes") or {}).get("MD5")
                or obs_id[:16]
            )
            value_str = str(value).strip()
            value_display = f"*{self._escape_md_inline(value_str)}*"

            rels = rel_by_source.get(obs_id, [])
            rel_parts: list[str] = []
            for rel in rels:
                to_obj = rel.get("to") or {}
                to_id = to_obj.get("id") or rel.get("toId") or ""
                to_info = entity_lookup.get(to_id, {})
                to_name = to_info.get("name") or to_obj.get("name") or ""
                if not to_name:
                    continue
                rel_type = rel.get("relationship_type") or "related-to"
                verb = REL_VERB.get(rel_type, rel_type.replace("-", " "))
                rel_parts.append(
                    f"{verb} [[{self._wikilink(to_name)}]]"
                )

            rel_str = "; ".join(rel_parts) if rel_parts else ""
            lines.append(f"| {obs_type} | {value_display} | {rel_str} |")

        return "\n".join(lines) + "\n"

    def _render_relationship_prose(
        self,
        rel: dict,
        entity_lookup: dict[str, dict],
        source_name: str,
    ) -> str:
        """
        Render a relationship as a prose sentence with [[wikilinks]].

        Format: [[Source]] {verb} [[Target]].
        If description present: indented italic sub-bullet follows.
        Returns empty string if target cannot be resolved.
        """
        rel_type = rel.get("relationship_type") or "related-to"
        verb = REL_VERB.get(rel_type, rel_type.replace("-", " "))

        to_obj = rel.get("to") or {}
        to_id = to_obj.get("id") or rel.get("toId") or ""
        to_info = entity_lookup.get(to_id, {})
        to_name = (
            to_info.get("name")
            or to_obj.get("name")
            or to_obj.get("value")
            or ""
        )

        if not to_name:
            self.helper.log_debug(
                f"Skipping relationship {rel.get('id')}: "
                f"unresolvable target entity_id={to_id}"
            )
            return ""

        prose = (
            f"[[{self._wikilink(source_name)}]] "
            f"{verb} "
            f"[[{self._wikilink(to_name)}]]."
        )

        description = (rel.get("description") or "").strip()
        if description:
            if len(description) > _REL_DESC_MAX_CHARS:
                description = description[:_REL_DESC_MAX_CHARS - 3] + "..."
            prose += f"\n  - *{self._escape_md_inline(description)}*"

        return prose + "\n"

    def _build_entity_lookup(self, objects_by_type: dict[str, list]) -> dict[str, dict]:
        """Build flat dict: entity_id -> {name, entity_type}."""
        lookup: dict[str, dict] = {}
        for entity_type, entities in objects_by_type.items():
            for entity in entities:
                eid = entity.get("id")
                if not eid:
                    continue
                lookup[eid] = {
                    "name": self._get_entity_name(entity),
                    "entity_type": entity_type,
                }
        return lookup

    def _build_rel_index(self, relationships: list[dict]) -> dict[str, list[dict]]:
        """Build dict: source_entity_id -> [outgoing relationship dicts]."""
        index: dict[str, list[dict]] = {}
        for rel in relationships:
            from_obj = rel.get("from") or {}
            from_id = from_obj.get("id") or rel.get("fromId") or ""
            if not from_id:
                continue
            if from_id not in index:
                index[from_id] = []
            index[from_id].append(rel)
        return index

    def _extract_tlp(self, container: dict) -> str:
        """Extract TLP marking. Defaults to TLP:AMBER+STRICT if absent."""
        markings = container.get("objectMarking") or []
        for m in markings:
            defn = (
                m.get("definition")
                or m.get("definition_type")
                or m.get("name")
                or ""
            )
            if defn.upper().startswith("TLP"):
                return defn
        return "TLP:AMBER+STRICT"

    def _extract_external_ref(self, container: dict) -> str:
        """Extract the first valid http(s) external reference URL."""
        ext_refs = container.get("externalReferences") or {}
        if isinstance(ext_refs, dict):
            ext_refs = [
                e.get("node", e) for e in ext_refs.get("edges", [])
            ]
        for ref in ext_refs:
            url = ref.get("url") or ""
            if url.startswith("http"):
                return url
        return ""

    @staticmethod
    def _get_entity_name(entity: dict) -> str:
        """Extract display name: SDOs use 'name', SCOs use 'value'."""
        return (
            entity.get("name")
            or entity.get("value")
            or entity.get("observable_value")
            or entity.get("standard_id")
            or ""
        ).strip()

    @staticmethod
    def _wikilink(name: str) -> str:
        """Sanitize name for Obsidian [[wikilink]] syntax."""
        return _WIKILINK_FORBIDDEN.sub("", name).strip()

    @staticmethod
    def _escape_md_block(text: str) -> str:
        """Escape Markdown special characters for block-level contexts."""
        return re.sub(r"([*_`<>&])", r"\\\1", text)

    @staticmethod
    def _escape_md_inline(text: str) -> str:
        """Escape Markdown special characters for inline and table cell contexts."""
        return re.sub(r"([*_`|<>&\\])", r"\\\1", text)

    @staticmethod
    def _yaml_escape(text: str) -> str:
        """Escape string for YAML double-quoted scalar values."""
        return text.replace("\\", "\\\\").replace('"', '\\"')
