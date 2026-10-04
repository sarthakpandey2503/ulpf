"""Compile a declarative source pack into a fast parse -> map function.

Result of ``CompiledPack.apply``:
  ocsf     - mapped OCSF attributes (class, activity, attributes)
  fields   - every extracted field
  consumed - fields used by a mapping (the rest become ``unmapped``)
  lineage  - OCSF path -> raw field(s) it came from
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Callable

from .. import extractors
from ..normalizer import ocsf
from ..security import safe_regex

_TEMPLATE_VAR = re.compile(r"\{([^{}]+)\}")  # fixed, trusted pattern


# ---------------------------------------------------------------- conditions

def compile_cond(c: dict | None) -> Callable[[dict], bool]:
    if not c:
        return lambda f: True
    if "all" in c:
        subs = [compile_cond(x) for x in c["all"]]
        return lambda f: all(s(f) for s in subs)
    if "any" in c:
        subs = [compile_cond(x) for x in c["any"]]
        return lambda f: any(s(f) for s in subs)
    if "not" in c:
        sub = compile_cond(c["not"])
        return lambda f: not sub(f)
    name = c.get("field", "")
    if "exists" in c:
        want = c["exists"]
        return lambda f: (f.get(name) not in (None, "")) == want
    if "equals" in c:
        v = str(c["equals"]).lower()
        return lambda f: str(f.get(name, "")).lower() == v
    if "in" in c:
        vs = {str(x).lower() for x in c["in"]}
        return lambda f: str(f.get(name, "")).lower() in vs
    if "contains" in c:
        v = c["contains"].lower()
        return lambda f: v in str(f.get(name, "")).lower()
    if "startswith" in c:
        v = c["startswith"].lower()
        return lambda f: str(f.get(name, "")).lower().startswith(v)
    if "regex" in c:
        rx = safe_regex(c["regex"])
        return lambda f: rx.search(str(f.get(name, ""))) is not None
    return lambda f: True


# ------------------------------------------------------------ mapping specs

@dataclass
class Resolved:
    value: Any
    sources: list[str]


def _norm_str(v: Any) -> str:
    if isinstance(v, float) and v.is_integer():
        v = int(v)
    return str(v).strip().lower()


def _verbatim(raw: Any, val: Any) -> bool:
    if raw is None:
        return False
    items = val if isinstance(val, list) else [val]
    r = _norm_str(raw)
    return any(_norm_str(x) == r for x in items)


def _cast(value: Any, cast: str | None, fmt: str | None, tz: str | None) -> Any:
    if cast is None or value is None:
        return value
    if cast == "int":
        return ocsf.coerce(value, "integer_t")
    if cast == "float":
        return float(value)
    if cast == "str":
        return str(value)
    if cast == "bool":
        return ocsf.coerce(value, "boolean_t")
    if cast == "ip":
        return ocsf.coerce(value, "ip_t")
    if cast == "timestamp":
        return ocsf.parse_timestamp(value, fmt=fmt, tz=tz)
    if cast == "lower":
        return str(value).lower()
    if cast == "upper":
        return str(value).upper()
    return value


def compile_spec(spec: Any, pack_tz: str | None) -> Callable[[dict], Resolved | None]:
    if isinstance(spec, list):
        subs = [compile_spec(s, pack_tz) for s in spec]

        def coalesce(f: dict) -> Resolved | None:
            for s in subs:
                r = s(f)
                if r is not None and r.value not in (None, ""):
                    return r
            return None
        return coalesce
    if isinstance(spec, str):
        name = spec

        def direct(f: dict) -> Resolved | None:
            v = f.get(name)
            return None if v in (None, "", "-") else Resolved(v, [name])
        return direct

    cond = compile_cond(spec.get("when")) if spec.get("when") else None
    names = spec.get("field")
    names = [names] if isinstance(names, str) else (names or [])
    join = spec.get("join", " ")
    template = spec.get("template")
    tmpl_vars = _TEMPLATE_VAR.findall(template) if template else []
    const = spec.get("const", None)
    has_const = "const" in spec
    cast, fmt, tz = spec.get("cast"), spec.get("format"), spec.get("tz", pack_tz)
    vmap = {str(k).lower(): v for k, v in (spec.get("map") or {}).items()}
    passthrough = spec.get("map_default_passthrough", False)
    has_default = "default" in spec
    default = spec.get("default")
    rx = safe_regex(spec["regex"]) if spec.get("regex") else None
    split = spec.get("split")
    scale = spec.get("scale")

    def resolve(f: dict) -> Resolved | None:
        if cond is not None and not cond(f):
            return None
        sources: list[str] = []
        value: Any = None
        if has_const:
            value = const
        elif template:
            parts = {}
            for var in tmpl_vars:
                v = f.get(var)
                if v in (None, ""):
                    break
                parts[var] = v
                sources.append(var)
            else:
                value = _TEMPLATE_VAR.sub(lambda m: str(parts[m.group(1)]), template)
        elif names:
            vals = [f.get(n) for n in names]
            present = [(n, v) for n, v in zip(names, vals) if v not in (None, "", "-")]
            if len(names) > 1 and len(present) == len(names):
                value = join.join(str(v) for _, v in present)
                sources = [n for n, _ in present]
            elif len(names) == 1 and present:
                value, sources = present[0][1], [present[0][0]]
        if value is not None and split:
            parts_ = str(value).split(split["sep"])
            value = parts_[split["index"]] if -len(parts_) <= split["index"] < len(parts_) else None
        if value is not None and rx is not None:
            m = rx.search(str(value))
            if not m:
                value = None
            else:
                gd = m.groupdict()
                value = gd.get("v") if "v" in gd else (m.group(1) if m.groups() else m.group(0))
        if value is not None and vmap:
            key = str(value).lower()
            if key in vmap:
                value = vmap[key]
            elif not passthrough:
                value = None
        if value in (None, "") and has_default:
            return Resolved(default, sources or ["default"])
        if value in (None, ""):
            return None
        value = _cast(value, cast, fmt, tz)
        if scale is not None:
            value = int(float(value) * scale)
        return Resolved(value, sources or (["const"] if has_const else []))
    return resolve


# ------------------------------------------------------------------ packs

@dataclass
class CompiledClass:
    name: str
    cond: Callable[[dict], bool]
    class_name: str
    class_def: dict
    activity: Callable[[dict], Resolved | None] | None
    severity: Callable[[dict], Resolved | None] | None
    mapping: list[tuple[str, Callable[[dict], Resolved | None]]]


@dataclass
class CompiledPack:
    doc: dict
    id: str
    version: str
    vendor: str
    product: str
    priority: int
    formats: set[str]
    contains: list[str]
    any_contains: list[str]
    match_rx: Any
    sources: set[str]
    stages: list[tuple[dict, Callable[[str, dict], dict], Callable[[dict], bool]]]
    common: list[tuple[str, Callable[[dict], Resolved | None]]]
    severity: Callable[[dict], Resolved | None] | None
    classes: list[CompiledClass]
    trust: float = 1.0
    signed: bool = False
    path: str = ""
    errors: list[str] = field(default_factory=list)

    @property
    def ref(self) -> str:
        return f"{self.id}@{self.version}"

    def matches(self, raw: str, tags: set[str], source: str | None = None) -> bool:
        if self.sources and source and source in self.sources:
            return True
        if self.sources and not (self.formats or self.contains or self.any_contains or self.match_rx):
            return False
        if self.formats and not (self.formats & tags):
            return False
        for s in self.contains:
            if s not in raw:
                return False
        if self.any_contains and not any(s in raw for s in self.any_contains):
            return False
        if self.match_rx is not None and self.match_rx.search(raw) is None:
            return False
        return True

    def extract(self, raw: str) -> dict:
        fields: dict[str, Any] = {}
        consumed_sources: set[str] = set()
        for opts, fn, cond in self.stages:
            if not cond(fields):
                continue
            src = opts.get("source")
            text = raw if not src else fields.get(src)
            if text in (None, ""):
                if opts.get("required", True) and src is None:
                    raise ValueError(f"stage {opts['type']} has no input")
                continue
            try:
                out = fn(str(text), opts)
            except Exception:
                if opts.get("required", True):
                    raise
                continue
            prefix = opts.get("prefix", "")
            if src:
                consumed_sources.add(src)
            for k, v in out.items():
                fields[f"{prefix}{k}"] = v
        fields["__consumed_sources__"] = consumed_sources
        return fields

    def apply(self, raw: str) -> dict:
        fields = self.extract(raw)
        consumed: set[str] = set(fields.pop("__consumed_sources__"))
        cls = next((c for c in self.classes if c.cond(fields)), None)
        if cls is None:
            raise ValueError("no class rule matched")
        attrs: dict[str, Any] = {}
        lineage: dict[str, Any] = {}
        errors: list[str] = []
        for path, fn in self.common + cls.mapping:
            try:
                r = fn(fields)
            except (ValueError, TypeError) as exc:
                errors.append(f"{path}: {exc}")
                continue
            if r is None:
                continue
            t = ocsf.attr_type(cls.class_name, path) if cls.class_name != "base_event" else None
            if t is None and cls.class_name != "base_event":
                continue  # path not defined for this class: keep the source field in `unmapped`
            try:
                if t is not None and ocsf.attr_is_array(cls.class_name, path):
                    items = r.value if isinstance(r.value, list) else [r.value]
                    val = [ocsf.coerce(x, t, self.doc.get("tz")) for x in items]
                else:
                    val = ocsf.coerce(r.value, t, self.doc.get("tz"))
            except (ValueError, TypeError) as exc:
                errors.append(f"{path}: cannot coerce {r.value!r} to {t}: {exc}")
                continue
            attrs[path] = val
            src = [s for s in r.sources if s not in ("const", "default")]
            if len(src) == 1:
                lineage[path] = src[0]
                # A source leaves `unmapped` only when OCSF carries it verbatim (lossless);
                # enum maps, hex->int casts, regex extracts etc. keep the original too.
                if t == "timestamp_t" or _verbatim(fields.get(src[0]), val):
                    consumed.add(src[0])
            elif src:
                lineage[path] = src
            else:
                lineage[path] = r.sources[0] if r.sources else "const"
        activity = cls.activity(fields) if cls.activity else None
        severity = (cls.severity or self.severity)
        sev = severity(fields) if severity else None
        if activity is not None:
            lineage["activity_id"] = activity.sources[0] if activity.sources else "const"
        if sev is not None:
            lineage["severity_id"] = sev.sources[0] if sev.sources else "const"
        return {
            "class_name": cls.class_name,
            "class_def": cls.class_def,
            "class_rule": cls.name,
            "activity_id": _int_or(activity.value if activity else None, 0),
            "severity_id": _int_or(sev.value if sev else None, 1),
            "attrs": attrs,
            "fields": fields,
            "consumed": consumed,
            "lineage": lineage,
            "errors": errors,
        }


def _int_or(v: Any, d: int) -> int:
    try:
        return int(v)
    except (TypeError, ValueError):
        return d


def compile_pack(doc: dict) -> CompiledPack:
    tz = doc.get("tz")
    match = doc.get("match", {})
    stages = []
    for st in doc["parse"]:
        fn = extractors.get(st["type"])
        stages.append((st, fn, compile_cond(st.get("when"))))
    common = [(p, compile_spec(s, tz)) for p, s in (doc.get("mapping") or {}).items()]
    classes = []
    for i, c in enumerate(doc["classes"]):
        cname, cdef = ocsf.get_class(c["class"])
        classes.append(CompiledClass(
            name=c.get("name", f"class{i}"),
            cond=compile_cond(c.get("when")),
            class_name=cname,
            class_def=cdef,
            activity=compile_spec(c["activity_id"], tz) if "activity_id" in c else None,
            severity=compile_spec(c["severity_id"], tz) if "severity_id" in c else None,
            mapping=[(p, compile_spec(s, tz)) for p, s in (c.get("mapping") or {}).items()],
        ))
    return CompiledPack(
        doc=doc, id=doc["id"], version=str(doc["version"]), vendor=doc["vendor"], product=doc["product"],
        priority=int(doc.get("priority", 50)),
        formats=set(match.get("formats", [])), contains=list(match.get("contains", [])),
        any_contains=list(match.get("any_contains", [])),
        match_rx=safe_regex(match["regex"]) if match.get("regex") else None,
        sources=set(match.get("sources", [])),
        stages=stages, common=common,
        severity=compile_spec(doc["severity_id"], tz) if "severity_id" in doc else None,
        classes=classes,
    )
