"""
connector.py — Obsidian Export Connector
=========================================
INTERNAL_EXPORT_FILE connector for OpenCTI 6.9.x.

Triggered from the Export button on any Report or Case container in the
OpenCTI UI. Fetches the full container knowledge graph (SDOs, relationships,
and Observables) and returns a structured Obsidian-compatible Markdown note
to the entity's Data tab as an export attachment.

Output contract:
  - YAML frontmatter (opencti_id, title, author, published, tlp, confidence,
    status, labels, external_ref, folder)
  - Obsidian [!info] callout block with container metadata
  - One Markdown section per SDO entity type (CTI Ingestion Manual creation order)
  - Relationships rendered as prose sentences with [[wikilinks]]
  - Observables rendered in a compact Markdown table
  - Export timestamp footer

Design principles:
  - Non-destructive: this connector only reads from OpenCTI and writes a
    file attachment. It never modifies graph entities or relationships.
  - Full-fidelity: the note reflects everything the container asserts.
  - Obsidian-native: wikilink syntax, YAML frontmatter, callout blocks,
    and table formatting aligned with Obsidian's rendering model.
  - Forward-compatible: unrecognized entity types fall back gracefully.

Upload mechanism (confirmed against pycti 6.9.13 source):
  self.helper.api.stix_domain_object.push_entity_export()
  GraphQL mutation: stixDomainObjectEdit(id) { exportPush(file, file_markings) }
  This routes to the entity's Data tab export section, which is the correct
  destination for INTERNAL_EXPORT_FILE connector output.
"""

import io
import sys

from pycti import OpenCTIConnectorHelper, get_config_variable

from graph_fetcher import GraphFetcher
from note_builder import NoteBuilder


def _parse_bool(value) -> bool:
    """
    Safely parse a boolean config value returned by get_config_variable.

    pycti 6.9.13 coerces env var strings that look like booleans into native
    Python bools before returning them. This function handles both the native
    bool case and the string case so callers don't need to guard separately.

    Args:
        value: Value returned by get_config_variable — may be bool or str.

    Returns:
        True if the value is boolean True or a truthy string ("true", "1", "yes").
        False otherwise.
    """
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.lower() in ("true", "1", "yes")
    return bool(value)


def _parse_int(value, default: int) -> int:
    """
    Safely parse an integer config value returned by get_config_variable.

    Args:
        value:   Value returned by get_config_variable.
        default: Fallback if value cannot be parsed.

    Returns:
        Integer value, or default on parse failure.
    """
    if isinstance(value, int):
        return value
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


class ObsidianExportConnector:
    """
    OpenCTI INTERNAL_EXPORT_FILE connector that produces Obsidian Markdown notes.

    Lifecycle:
      1. start() registers the connector and calls helper.listen()
      2. For each export job, process_message() is called by the helper
      3. process_message() drives GraphFetcher -> NoteBuilder -> _upload_export()
      4. The generated .md file is returned to the entity's Data tab
    """

    def __init__(self):
        """
        Load configuration from environment variables and initialise
        the connector helper, graph fetcher, and note builder.
        """
        config = {
            "opencti": {
                "url": get_config_variable("OPENCTI_URL", ["opencti", "url"]),
                "token": get_config_variable("OPENCTI_TOKEN", ["opencti", "token"]),
            },
            "connector": {
                "id": get_config_variable("CONNECTOR_ID", ["connector", "id"]),
                # INTERNAL_EXPORT_FILE: job-driven, not polling-based.
                # OpenCTI surfaces this connector in the Export dialog for
                # compatible entity types based on the scope MIME type.
                "type": "INTERNAL_EXPORT_FILE",
                "name": get_config_variable(
                    "CONNECTOR_NAME",
                    ["connector", "name"],
                    default="Obsidian Export",
                ),
                # text/markdown registers this connector in the Export dialog
                # for Report and Case entities
                "scope": get_config_variable(
                    "CONNECTOR_SCOPE",
                    ["connector", "scope"],
                    default="text/markdown",
                ),
                "log_level": get_config_variable(
                    "CONNECTOR_LOG_LEVEL",
                    ["connector", "log_level"],
                    default="INFO",
                ),
                # auto=False: INTERNAL_EXPORT_FILE connectors are job-triggered,
                # not self-scheduling
                "auto": False,
            },
        }

        self.helper = OpenCTIConnectorHelper(config)

        # Safety cap on objects fetched per container. Objects beyond this
        # limit are truncated with a warning — not lost from OpenCTI.
        self.max_objects = _parse_int(
            get_config_variable(
                "EXPORT_MAX_OBJECTS",
                ["export", "max_objects"],
                default="500",
            ),
            default=500,
        )

        # Controls whether SCO Observables are included in the export.
        # _parse_bool handles pycti returning either a native bool or a string.
        self.include_observables = _parse_bool(
            get_config_variable(
                "EXPORT_INCLUDE_OBSERVABLES",
                ["export", "include_observables"],
                default="true",
            )
        )

        self.graph_fetcher = GraphFetcher(
            helper=self.helper,
            max_objects=self.max_objects,
        )
        self.note_builder = NoteBuilder(helper=self.helper)

    def process_message(self, data: dict) -> None:
        """
        Main callback invoked by the OpenCTI worker queue for each export job.

        Args:
            data: Export job dict from the OpenCTI worker queue.
                  Keys: entity_id, entity_type, file_name, export_scope,
                        file_markings, work_id.

        Raises:
            Exception: Re-raised after logging and error-signalling the work item.
        """
        entity_id = data.get("entity_id")
        entity_type = data.get("entity_type")
        work_id = data.get("work_id")
        # file_markings: list of marking definition IDs passed through from
        # the export job — forwarded to push_entity_export so the exported
        # file inherits the correct TLP markings in the Data tab
        file_markings = data.get("file_markings") or []

        # Respect OpenCTI's suggested filename but enforce .md extension
        raw_name = data.get("file_name") or f"export_{(entity_id or 'unknown')[:8]}"
        if raw_name.endswith(".md"):
            file_name = raw_name
        else:
            file_name = raw_name.rsplit(".", 1)[0] + ".md"

        self.helper.log_info(
            f"Export job received — type={entity_type} id={entity_id} file={file_name}"
        )

        try:
            if work_id:
                self.helper.api.work.to_progress(
                    work_id=work_id,
                    message="Fetching container graph from OpenCTI",
                )

            container_data = self.graph_fetcher.fetch_container(
                entity_id=entity_id,
                entity_type=entity_type,
                include_observables=self.include_observables,
            )

            n_types = len(container_data.get("objects_by_type", {}))
            n_rels = len(container_data.get("relationships", []))
            if work_id:
                self.helper.api.work.to_progress(
                    work_id=work_id,
                    message=f"Building note — {n_types} entity types, {n_rels} relationships",
                )

            md_content = self.note_builder.build_note(container_data)

            self.helper.log_info(
                f"Note built — {len(md_content):,} characters, "
                f"{n_types} entity types, {n_rels} relationships"
            )

            self._upload_export(
                file_name=file_name,
                content=md_content,
                entity_id=entity_id,
                entity_type=entity_type,
                file_markings=file_markings,
                work_id=work_id,
            )

            if work_id:
                self.helper.api.work.to_processed(
                    work_id=work_id,
                    message=f"Obsidian note exported: {file_name}",
                )

            self.helper.log_info(f"Export complete — {file_name}")

        except Exception as exc:
            self.helper.log_error(
                f"Export failed — entity_type={entity_type} "
                f"entity_id={entity_id} error={exc}"
            )
            if work_id:
                try:
                    self.helper.api.work.to_processed(
                        work_id=work_id,
                        message=f"Export failed: {exc}",
                        in_error=True,
                    )
                except Exception:
                    pass
            raise

    def _upload_export(
        self,
        file_name: str,
        content: str,
        entity_id: str,
        entity_type: str,
        file_markings: list,
        work_id: str | None,
    ) -> None:
        """
        Push the generated .md file to the entity's Data tab export section.

        Uses stix_domain_object.push_entity_export(), which calls the
        stixDomainObjectEdit(id) { exportPush(file, file_markings) } GraphQL
        mutation. This is the same mechanism used by the native OpenCTI export
        connectors (export-file-stix, export-file-csv) to return files to the
        entity's Data tab.

        Confirmed against pycti 6.9.13 source:
          pycti/entities/opencti_stix_domain_object.py:push_entity_export()

        Args:
            file_name:     Filename for the attachment (ends in .md)
            content:       String content of the Markdown note
            entity_id:     OpenCTI entity ID of the source container
            entity_type:   OpenCTI entity type string (e.g. "Report")
            file_markings: List of marking definition IDs from the export job
            work_id:       Work queue item ID (may be None in test invocations)
        """
        file_bytes = content.encode("utf-8")

        self.helper.log_info(
            f"Pushing export file to Data tab — "
            f"file={file_name} entity_id={entity_id}"
        )

        self.helper.api.stix_domain_object.push_entity_export(
            entity_id=entity_id,
            file_name=file_name,
            data=file_bytes,
            file_markings=file_markings,
            mime_type="text/markdown",
        )

        self.helper.log_info(f"push_entity_export completed — {file_name}")

    def start(self) -> None:
        """Start the connector and listen for export jobs on the queue."""
        self.helper.log_info(
            f"Obsidian Export connector starting — "
            f"max_objects={self.max_objects}, "
            f"include_observables={self.include_observables}"
        )
        self.helper.listen(self.process_message)


if __name__ == "__main__":
    try:
        connector = ObsidianExportConnector()
        connector.start()
    except Exception as exc:
        print(f"[FATAL] Connector startup failed: {exc}", file=sys.stderr)
        sys.exit(1)
