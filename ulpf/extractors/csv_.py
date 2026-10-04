from __future__ import annotations

import csv
import io
from typing import Any


def extract_csv(text: str, opts: dict) -> dict[str, Any]:
    """Positional CSV (e.g. Palo Alto) using a declared column list.

    Extra trailing values are kept as ``_col<N>`` so nothing is lost. When the
    layout depends on a discriminator column (Palo Alto TRAFFIC vs THREAT,
    pfSense tcp vs udp) use ``columns_by: {index: N, map: {VALUE: [...]}}``.
    """
    delimiter = opts.get("delimiter", ",")
    row = next(csv.reader(io.StringIO(text.strip()), delimiter=delimiter, quotechar=opts.get("quote", '"')), [])
    columns: list[str] = list(opts.get("columns", []))
    by = opts.get("columns_by")
    if by:
        idx = by["index"]
        key = row[idx] if idx < len(row) else ""
        extra = by["map"].get(key) or by["map"].get("default") or []
        columns = columns + list(extra) if by.get("append", False) else list(extra) or columns
    out: dict[str, Any] = {}
    for i, value in enumerate(row):
        name = columns[i] if i < len(columns) and columns[i] else f"_col{i}"
        if name == "_skip":
            continue
        if value != "" or opts.get("keep_empty", False):
            out[name] = value
    return out
