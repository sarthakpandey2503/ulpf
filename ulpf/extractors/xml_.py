"""XML extractor.

Uses defusedxml, which rejects external entities (XXE), DTD retrieval and entity
expansion bombs ("billion laughs"). Windows EventLog ``<Data Name="X">v</Data>``
elements are flattened to ``X: v`` so Sysmon/Security fields map naturally.
"""
from __future__ import annotations

from typing import Any

from defusedxml import ElementTree as SafeET

from ..config import settings
from ..security import InputRejected


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _put(out: dict, key: str, value: Any) -> None:
    if key in out:
        cur = out[key]
        out[key] = cur + [value] if isinstance(cur, list) else [cur, value]
    else:
        out[key] = value


def _walk(el, path: str, out: dict, windows_data: bool) -> None:
    tag = _local(el.tag)
    name_attr = el.attrib.get("Name")
    if windows_data and tag == "Data" and name_attr:
        _put(out, name_attr, (el.text or "").strip())
        return
    here = f"{path}.{tag}" if path else tag
    for k, v in el.attrib.items():
        _put(out, f"{here}.{_local(k)}", v)
    children = list(el)
    text = (el.text or "").strip()
    if text and not children:
        _put(out, here, text)
    elif text:
        _put(out, f"{here}._text", text)
    for child in children:
        _walk(child, here, out, windows_data)
    if len(out) > settings.max_fields:
        raise InputRejected(f"more than {settings.max_fields} fields")


def extract_xml(text: str, opts: dict) -> dict[str, Any]:
    root = SafeET.fromstring(text.strip(), forbid_dtd=True)
    out: dict[str, Any] = {}
    windows_data = opts.get("windows_eventdata", True)
    strip_root = opts.get("strip_root", True)
    if strip_root:
        for k, v in root.attrib.items():
            _put(out, _local(k), v)
        for child in root:
            _walk(child, "", out, windows_data)
    else:
        _walk(root, "", out, windows_data)
    return out
