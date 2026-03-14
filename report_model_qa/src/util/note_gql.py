from __future__ import annotations

from typing import Any, Dict, List, Optional


def create_note_gql(
    helper: Any,
    title: str,
    content: str,
    objects: List[str],
    note_types: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """
    Create a Note using GraphQL (schema-stable vs pycti method drift).

    Your schema:
      - NoteAddInput does NOT accept `abstract`
      - NoteAddInput DOES accept `content`, `objects`, `note_types`
    """
    mutation = """
    mutation NoteAdd($input: NoteAddInput!) {
      noteAdd(input: $input) { id }
    }
    """

    full_content = f"# {title}\n\n{content}"

    input_obj: Dict[str, Any] = {
        "content": full_content,
        "objects": objects,
    }
    if note_types:
        input_obj["note_types"] = note_types

    res = helper.api.query(mutation, {"input": input_obj})
    data = (res or {}).get("data", {}).get("noteAdd")
    if not data:
        raise RuntimeError(f"noteAdd returned no data: {res}")
    return data
