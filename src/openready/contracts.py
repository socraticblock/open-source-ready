"""A small validator for the JSON Schema subset the Open-Ready contracts use.

Why not ``jsonschema``: the core must run on a stranger's machine with no install
step (handoff ``docs/02-ARCHITECTURE.md`` -- "no server, cloud database, runtime
internet, vendor AI SDK"). A dependency would also mean the validator itself
becomes part of the trust surface it is meant to keep small.

The honest limitation: this is a *subset* validator. :func:`unsupported_keywords`
reports any keyword present in a schema that this module does not implement, so a
contract that grows a new keyword fails loudly instead of validating vacuously.
That check is what makes the subset safe to rely on.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Dict, List, Sequence

DRAFT_2020_12 = "https://json-schema.org/draft/2020-12/schema"

IMPLEMENTED = frozenset({
    "$schema", "$id", "title", "description", "type", "required",
    "additionalProperties", "properties", "const", "enum", "pattern",
    "minLength", "minItems", "uniqueItems", "items", "format", "default",
})

_TYPES = {
    "object": dict, "array": list, "string": str, "boolean": bool,
    "number": (int, float), "integer": int, "null": type(None),
}

_DATETIME_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}[Tt]\d{2}:\d{2}:\d{2}(\.\d+)?([Zz]|[+-]\d{2}:\d{2})$"
)


class SchemaError(Exception):
    """Raised when a contract file is missing, malformed or uses unsupported keywords."""


def load_schema(path: Path) -> Dict[str, Any]:
    schema = json.loads(Path(path).read_text(encoding="utf-8"))
    if schema.get("$schema") != DRAFT_2020_12:
        raise SchemaError(f"{path}: not a JSON Schema Draft 2020-12 document")
    unsupported = unsupported_keywords(schema)
    if unsupported:
        raise SchemaError(
            f"{path}: schema uses keywords this validator does not implement: "
            f"{sorted(unsupported)}. Extend contracts.py before using this contract."
        )
    return schema


def unsupported_keywords(schema_or_fragment: Any) -> set:
    """Every schema keyword in the document that :func:`validate` ignores."""
    found = set()

    def walk(node: Any) -> None:
        if isinstance(node, dict):
            for key, value in node.items():
                if key not in IMPLEMENTED:
                    found.add(key)
                # 'properties'/'items' hold schemas keyed by name or a schema;
                # walk their values, not the container keys.
                if key in ("properties", "$defs", "definitions", "patternProperties"):
                    for sub in value.values() if isinstance(value, dict) else []:
                        walk(sub)
                elif key in ("items", "additionalProperties", "not", "contains", "propertyNames"):
                    walk(value)
                elif key in ("allOf", "anyOf", "oneOf", "prefixItems"):
                    for sub in value if isinstance(value, list) else []:
                        walk(sub)
        elif isinstance(node, list):
            for item in node:
                walk(item)

    walk(schema_or_fragment)
    return found


def validate(instance: Any, schema: Dict[str, Any]) -> List[str]:
    """Return a list of human-readable errors. Empty list means valid."""
    errors: List[str] = []
    _validate(instance, schema, "$", errors)
    return errors


def _type_matches(value: Any, expected: str) -> bool:
    if expected == "boolean":
        return isinstance(value, bool)
    if expected in ("number", "integer") and isinstance(value, bool):
        return False  # bool is a subclass of int in Python; never a number here
    python_type = _TYPES.get(expected)
    return isinstance(value, python_type) if python_type else True


def _validate(instance: Any, schema: Any, path: str, errors: List[str]) -> None:
    if not isinstance(schema, dict):
        return

    if "const" in schema and instance != schema["const"]:
        errors.append(f"{path}: expected constant {schema['const']!r}, got {instance!r}")

    if "enum" in schema and instance not in schema["enum"]:
        errors.append(f"{path}: {instance!r} is not one of {schema['enum']}")

    declared = schema.get("type")
    if declared is not None:
        allowed: Sequence[str] = declared if isinstance(declared, list) else [declared]
        if not any(_type_matches(instance, t) for t in allowed):
            errors.append(
                f"{path}: expected type {'/'.join(allowed)}, got "
                f"{type(instance).__name__}"
            )
            return  # further keyword checks would be noise on a type mismatch

    if isinstance(instance, str):
        if "pattern" in schema and not re.search(schema["pattern"], instance):
            errors.append(f"{path}: {instance!r} does not match {schema['pattern']!r}")
        if "minLength" in schema and len(instance) < schema["minLength"]:
            errors.append(f"{path}: shorter than minLength {schema['minLength']}")
        if schema.get("format") == "date-time" and not _DATETIME_RE.match(instance):
            errors.append(f"{path}: {instance!r} is not an RFC 3339 date-time")

    if isinstance(instance, list):
        if "minItems" in schema and len(instance) < schema["minItems"]:
            errors.append(f"{path}: fewer than minItems {schema['minItems']}")
        if schema.get("uniqueItems"):
            seen = [json.dumps(x, sort_keys=True) for x in instance]
            if len(seen) != len(set(seen)):
                errors.append(f"{path}: items are not unique")
        if "items" in schema:
            for i, item in enumerate(instance):
                _validate(item, schema["items"], f"{path}[{i}]", errors)

    if isinstance(instance, dict):
        for key in schema.get("required", []):
            if key not in instance:
                errors.append(f"{path}: missing required property {key!r}")
        properties = schema.get("properties", {})
        for key, value in instance.items():
            if key in properties:
                _validate(value, properties[key], f"{path}.{key}", errors)
            elif schema.get("additionalProperties") is False:
                errors.append(f"{path}: unexpected property {key!r}")


def tool_root() -> Path:
    """The installed Open-Ready tree (holds contracts/).

    Contracts belong to the *tool*, never to the project being checked. Passing a
    project root here would look for ``<project>/contracts/`` and fail.
    """
    # The contracts live INSIDE the package, so they travel in a wheel and an
    # installed copy still finds them. A checkout resolves to the same place.
    return Path(__file__).resolve().parent


def contract_paths(root: Path) -> Dict[str, Path]:
    """The three vendored contracts, by short name."""
    contracts = Path(root) / "contracts"
    return {
        "project": contracts / "project.schema.json",
        "result": contracts / "result.schema.json",
        "release-packet": contracts / "release-packet.schema.json",
    }


def validate_against(root: Path, name: str, instance: Any) -> List[str]:
    return validate(instance, load_schema(contract_paths(root)[name]))


def validate_project_contract(instance: Any) -> List[str]:
    """Validate against the tool's own vendored project contract."""
    return validate_against(tool_root(), "project", instance)


def validate_result_contract(instance: Any) -> List[str]:
    return validate_against(tool_root(), "result", instance)
