"""JSON Schema for source packs.

Packs are purely declarative: no code, no eval, no shell. Any regex inside a pack
is compiled with RE2. Unknown keys are rejected so a typo (or an injected field
from an AI draft) cannot silently change behaviour.
"""
from __future__ import annotations

import jsonschema

_COND = {
    "type": "object",
    "properties": {
        "field": {"type": "string"},
        "equals": {}, "in": {"type": "array"}, "contains": {"type": "string"},
        "startswith": {"type": "string"}, "regex": {"type": "string", "maxLength": 1000},
        "exists": {"type": "boolean"},
        "all": {"type": "array", "items": {"$ref": "#/$defs/cond"}},
        "any": {"type": "array", "items": {"$ref": "#/$defs/cond"}},
        "not": {"$ref": "#/$defs/cond"},
    },
    "additionalProperties": False,
}

_SPEC_OBJ = {
    "type": "object",
    "properties": {
        "field": {"oneOf": [{"type": "string"}, {"type": "array", "items": {"type": "string"}}]},
        "join": {"type": "string"},
        "const": {},
        "template": {"type": "string"},
        "cast": {"enum": ["int", "float", "str", "bool", "ip", "timestamp", "lower", "upper", "auto"]},
        "format": {"type": "string"},
        "tz": {"type": "string"},
        "map": {"type": "object"},
        "map_default_passthrough": {"type": "boolean"},
        "default": {},
        "scale": {"type": "number"},
        "regex": {"type": "string", "maxLength": 1000},
        "split": {"type": "object", "properties": {"sep": {"type": "string"}, "index": {"type": "integer"}},
                  "required": ["sep", "index"], "additionalProperties": False},
        "when": {"$ref": "#/$defs/cond"},
    },
    "additionalProperties": False,
}

_SPEC = {"oneOf": [
    {"type": "string"},
    {"$ref": "#/$defs/spec_obj"},
    {"type": "array", "items": {"oneOf": [{"type": "string"}, {"$ref": "#/$defs/spec_obj"}]}, "minItems": 1},
]}

_STAGE = {
    "type": "object",
    "properties": {
        "type": {"enum": ["json", "xml", "csv", "kv", "grok", "regex", "cef", "leef", "syslog"]},
        "source": {"type": "string"},
        "prefix": {"type": "string"},
        "required": {"type": "boolean"},
        "when": {"$ref": "#/$defs/cond"},
    },
    "required": ["type"],
    "additionalProperties": True,  # extractor-specific options, validated by the extractor
}

PACK_SCHEMA = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "type": "object",
    "$defs": {"cond": _COND, "spec_obj": _SPEC_OBJ, "spec": _SPEC},
    "properties": {
        "id": {"type": "string", "pattern": r"^[a-z0-9_\-]+(\.[a-z0-9_\-]+)+$"},
        "version": {"type": "string"},
        "vendor": {"type": "string"},
        "product": {"type": "string"},
        "category": {"type": "string"},
        "description": {"type": "string"},
        "priority": {"type": "integer"},
        "tz": {"type": "string"},
        "provenance": {"type": "object"},
        "match": {
            "type": "object",
            "properties": {
                "formats": {"type": "array", "items": {"type": "string"}},
                "contains": {"type": "array", "items": {"type": "string"}},
                "any_contains": {"type": "array", "items": {"type": "string"}},
                "regex": {"type": "string", "maxLength": 1000},
                "sources": {"type": "array", "items": {"type": "string"}},
            },
            "additionalProperties": False,
        },
        "parse": {"type": "array", "items": _STAGE, "minItems": 1},
        "mapping": {"type": "object", "additionalProperties": {"$ref": "#/$defs/spec"}},
        "severity_id": {"$ref": "#/$defs/spec"},
        "classes": {
            "type": "array",
            "minItems": 1,
            "items": {
                "type": "object",
                "properties": {
                    "name": {"type": "string"},
                    "when": {"$ref": "#/$defs/cond"},
                    "class": {"type": "string"},
                    "activity_id": {"$ref": "#/$defs/spec"},
                    "severity_id": {"$ref": "#/$defs/spec"},
                    "mapping": {"type": "object", "additionalProperties": {"$ref": "#/$defs/spec"}},
                },
                "required": ["class"],
                "additionalProperties": False,
            },
        },
        "tests": {"type": "array"},
    },
    "required": ["id", "version", "vendor", "product", "match", "parse", "classes"],
    "additionalProperties": False,
}

_validator = jsonschema.Draft202012Validator(PACK_SCHEMA)


def validate_pack(doc: dict) -> list[str]:
    return [f"{'/'.join(map(str, e.absolute_path)) or '<root>'}: {e.message}" for e in _validator.iter_errors(doc)]
