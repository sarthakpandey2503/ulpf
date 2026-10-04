"""Minimal, dependency-free Sigma evaluator (single-event rules).

Supports: field maps (AND), lists of maps (OR), keyword lists, null values,
wildcards ``*``/``?``, modifiers contains / startswith / endswith / all / re /
cidr / windash / exists / gt / gte / lt / lte / base64 / base64offset, and
conditions with and / or / not / parentheses / ``1 of x*`` / ``all of x*`` /
``1 of them`` / ``all of them``.

Rules are evaluated against a *view* object exposing ``get(field) -> list`` and
``values() -> list[str]`` so identical logic runs over the raw vendor view and
the OCSF view (the Schema Fidelity comparison).
"""
from __future__ import annotations

import base64
import fnmatch
import ipaddress
import re
from typing import Any, Callable

from ..security import safe_regex

Pred = Callable[[Any], bool]


class SigmaError(ValueError):
    pass


def _s(v: Any) -> str:
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, float) and v.is_integer():
        return str(int(v))
    return str(v)


_WILD_CACHE: dict[str, re.Pattern] = {}


def _wild(pattern: str, prefix: str = "", suffix: str = "") -> re.Pattern:
    """Sigma value -> regex. Escapes are interpreted on the value itself, before
    modifier wildcards (``prefix``/``suffix``) are added, so ``' D:\\'`` stays literal."""
    key = f"{prefix}\0{pattern}\0{suffix}"
    rx = _WILD_CACHE.get(key)
    if rx is None:
        out, i = [], 0
        while i < len(pattern):
            c = pattern[i]
            if c == "\\" and i + 1 < len(pattern) and pattern[i + 1] in "*?\\":
                out.append(re.escape(pattern[i + 1]))
                i += 2
                continue
            out.append(".*" if c == "*" else "." if c == "?" else re.escape(c))
            i += 1
        rx = re.compile(prefix + "".join(out) + suffix, re.S | re.I)
        _WILD_CACHE[key] = rx
    return rx


def _windash(v: str) -> list[str]:
    if not v.startswith(("-", "/")):
        return [v]
    return [p + v[1:] for p in ("-", "/", "\u2013", "\u2014", "\u2015")]


def _b64_offsets(v: str) -> list[str]:
    b, out = v.encode(), []
    for i in range(3):
        enc = base64.b64encode(b" " * i + b).decode()
        trim = (0, 3, 2)[(len(b) + i) % 3]
        out.append(enc[(0, 2, 3)[i]:len(enc) - trim])
    return out


def _value_pred(mods: list[str], value: Any) -> Pred:
    if value is None:
        return lambda vals: not vals or all(_s(x) == "" for x in vals)
    if "exists" in mods:
        want = bool(value)
        return lambda vals: bool(vals) == want
    sval = _s(value)
    if "base64offset" in mods:
        candidates = _b64_offsets(sval)
        return lambda vals: any(c in _s(x) for x in vals for c in candidates)
    if "base64" in mods:
        sval = base64.b64encode(sval.encode()).decode()
    variants = _windash(sval) if "windash" in mods else [sval]
    if "re" in mods:
        rx = safe_regex(sval)
        return lambda vals: any(rx.search(_s(x)) for x in vals)
    if "cidr" in mods:
        net = ipaddress.ip_network(sval, strict=False)

        def cidr(vals):
            for x in vals:
                try:
                    if ipaddress.ip_address(_s(x).strip("[]")) in net:
                        return True
                except ValueError:
                    continue
            return False
        return cidr
    for op in ("gte", "gt", "lte", "lt"):
        if op in mods:
            ref = float(sval)
            cmp = {"gte": float.__ge__, "gt": float.__gt__, "lte": float.__le__, "lt": float.__lt__}[op]

            def num(vals, cmp=cmp, ref=ref):
                for x in vals:
                    try:
                        if cmp(float(x), ref):
                            return True
                    except (TypeError, ValueError):
                        continue
                return False
            return num
    num_ref = None
    if not mods and "*" not in sval and "?" not in sval:
        try:
            num_ref = int(sval, 0)
        except ValueError:
            num_ref = None
    pats = []
    pre = ".*" if ("contains" in mods or "endswith" in mods) else ""
    suf = ".*" if ("contains" in mods or "startswith" in mods) else ""
    for v in variants:
        pats.append(_wild(v, pre, suf))
    if num_ref is not None:
        def num_eq(vals):
            for x in vals:
                if any(p.fullmatch(_s(x)) for p in pats):
                    return True
                if isinstance(x, int) and not isinstance(x, bool) and x == num_ref:
                    return True
            return False
        return num_eq
    return lambda vals: any(p.fullmatch(_s(x)) for x in vals for p in pats)


def _field_pred(key: str, value: Any) -> tuple[str, Pred]:
    parts = key.split("|")
    field, mods = parts[0], [m.lower() for m in parts[1:]]
    values = value if isinstance(value, list) else [value]
    preds = [_value_pred(mods, v) for v in values] or [lambda vals: False]
    if "all" in mods:
        return field, lambda vals: all(p(vals) for p in preds)
    return field, lambda vals: any(p(vals) for p in preds)


def compile_selection(body: Any) -> Callable[[Any], bool]:
    """Return pred(view)."""
    if isinstance(body, dict):
        fps = [_field_pred(k, v) for k, v in body.items()]
        return lambda view: all(p(view.get(f)) for f, p in fps)
    if isinstance(body, list):
        if all(isinstance(x, dict) for x in body):
            subs = [compile_selection(x) for x in body]
            return lambda view: any(s(view) for s in subs)
        kws = [_wild(_s(x), ".*", ".*") for x in body if not isinstance(x, dict)]
        maps = [compile_selection(x) for x in body if isinstance(x, dict)]
        return lambda view: any(s(view) for s in maps) or any(
            k.fullmatch(v) for v in view.values() for k in kws)
    if isinstance(body, (str, int, float)):
        kw = _wild(_s(body), ".*", ".*")
        return lambda view: any(kw.fullmatch(v) for v in view.values())
    raise SigmaError(f"unsupported selection type {type(body).__name__}")


_TOKEN = re.compile(r"\s*(\(|\)|\bnot\b|\band\b|\bor\b|\b1 of\b|\ball of\b|[\w*.\-]+)", re.I)


def _tokenize(cond: str) -> list[str]:
    pos, toks = 0, []
    cond = cond.strip()
    while pos < len(cond):
        m = _TOKEN.match(cond, pos)
        if not m:
            raise SigmaError(f"bad condition near {cond[pos:pos + 20]!r}")
        toks.append(m.group(1))
        pos = m.end()
        while pos < len(cond) and cond[pos].isspace():
            pos += 1
    return toks


def compile_condition(cond: str, selections: dict[str, Callable]) -> Callable[[Any], bool]:
    toks = _tokenize(cond)
    i = 0

    def peek():
        return toks[i].lower() if i < len(toks) else None

    def take():
        nonlocal i
        i += 1
        return toks[i - 1]

    def group(name: str) -> list[Callable]:
        if name.lower() == "them":
            return [v for k, v in selections.items() if not k.startswith("_")]
        return [v for k, v in selections.items() if fnmatch.fnmatchcase(k, name)]

    def atom():
        t = peek()
        if t == "(":
            take()
            node = expr()
            if peek() != ")":
                raise SigmaError("missing )")
            take()
            return node
        if t == "not":
            take()
            inner = atom()
            return lambda v: not inner(v)
        if t in ("1 of", "all of"):
            take()
            members = group(take())
            if not members:
                raise SigmaError(f"no selections match in condition {cond!r}")
            if t == "1 of":
                return lambda v: any(m(v) for m in members)
            return lambda v: all(m(v) for m in members)
        name = take()
        if name not in selections:
            raise SigmaError(f"unknown selection {name!r}")
        return selections[name]

    def conj():
        node = atom()
        while peek() == "and":
            take()
            left, right = node, atom()
            node = lambda v, l=left, r=right: l(v) and r(v)
        return node

    def expr():
        node = conj()
        while peek() == "or":
            take()
            left, right = node, conj()
            node = lambda v, l=left, r=right: l(v) or r(v)
        return node

    tree = expr()
    if i != len(toks):
        raise SigmaError(f"trailing tokens in condition {cond!r}")
    return tree


class SigmaRule:
    def __init__(self, doc: dict):
        det = doc.get("detection")
        if not isinstance(det, dict):
            raise SigmaError("rule has no detection")
        self.doc = doc
        self.id = str(doc.get("id", ""))
        self.title = str(doc.get("title", ""))
        self.logsource = doc.get("logsource") or {}
        self.fields: set[str] = set()
        sels = {}
        for name, body in det.items():
            if name in ("condition", "timeframe"):
                continue
            sels[name] = compile_selection(body)
            for item in body if isinstance(body, list) else [body]:
                if isinstance(item, dict):
                    self.fields.update(k.split("|")[0] for k in item)
        conds = det.get("condition")
        conds = conds if isinstance(conds, list) else [conds]
        if not conds or conds == [None]:
            raise SigmaError("missing condition")
        compiled = [compile_condition(str(c), sels) for c in conds]
        self._match = lambda view: any(c(view) for c in compiled)

    def match(self, view) -> bool:
        return self._match(view)
