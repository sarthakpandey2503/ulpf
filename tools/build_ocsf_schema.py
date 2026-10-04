"""Compile the OCSF source repository into a compact, offline schema bundle.

Usage: python tools/build_ocsf_schema.py third_party/ocsf-schema ulpf/normalizer/ocsf_schema.json

The bundle contains every event class (with fully resolved attributes, requirement
levels, types and enums) and every object, so ULPF can validate events without
network access.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path


def _load(p: Path) -> dict:
    return json.loads(p.read_text(encoding="utf-8"))


def _merge_attrs(dst: dict, src: dict) -> None:
    for name, spec in src.items():
        if name == "$include":
            continue
        cur = dst.setdefault(name, {})
        cur.update({k: v for k, v in spec.items() if k != "profile"})


class Compiler:
    def __init__(self, root: Path):
        self.root = root
        self.dictionary = _load(root / "dictionary.json")
        self.categories = _load(root / "categories.json")["attributes"]
        self.events: dict[str, dict] = {}
        for p in (root / "events").rglob("*.json"):
            d = _load(p)
            self.events[d["name"]] = d
        self.objects: dict[str, dict] = {}
        for p in (root / "objects").glob("*.json"):
            d = _load(p)
            self.objects[d["name"]] = d
        # Extensions (e.g. Windows registry classes). Class uid = ext_uid*100000 + category*1000 + uid.
        self.ext_uid: dict[str, int] = {}
        for ext in sorted((root / "extensions").glob("*/extension.json")):
            meta = _load(ext)
            base = ext.parent
            if (base / "dictionary.json").exists():
                for k, v in _load(base / "dictionary.json").get("attributes", {}).items():
                    self.dictionary["attributes"].setdefault(k, v)
            for p in (base / "objects").glob("*.json") if (base / "objects").exists() else []:
                d = _load(p)
                name = d.get("name") or d.get("extends")
                if name in self.objects and not d.get("name"):
                    _merge_attrs(self.objects[name].setdefault("attributes", {}), d.get("attributes", {}))
                elif d.get("name"):
                    if d["name"] in self.objects:
                        _merge_attrs(self.objects[d["name"]].setdefault("attributes", {}), d.get("attributes", {}))
                    else:
                        self.objects[d["name"]] = d
            for p in (base / "events").rglob("*.json") if (base / "events").exists() else []:
                d = _load(p)
                if d.get("name") and "uid" in d:
                    self.events[d["name"]] = d
                    self.ext_uid[d["name"]] = meta["uid"]

    def _resolve_includes(self, attrs: dict) -> dict:
        out: dict = {}
        for inc in attrs.get("$include", []):
            inc_path = self.root / inc
            if not inc_path.exists():
                continue
            inc_attrs = self._resolve_includes(_load(inc_path).get("attributes", {}))
            if inc.startswith("profiles/"):
                # Profile attributes only apply when the profile is declared by the producer.
                inc_attrs = {k: {**v, "requirement": "optional"} for k, v in inc_attrs.items()}
            _merge_attrs(out, inc_attrs)
        _merge_attrs(out, attrs)
        return out

    def _category(self, name: str) -> str | None:
        d = self.events.get(name, {})
        cat = d.get("category")
        if cat and cat != "other":
            return cat
        parent = d.get("extends")
        return self._category(parent) if parent else None

    def _resolve(self, name: str, table: dict[str, dict]) -> dict:
        d = table[name]
        attrs: dict = {}
        parent = d.get("extends")
        if parent and parent in table:
            attrs = json.loads(json.dumps(self._resolve(parent, table)))
        _merge_attrs(attrs, self._resolve_includes(d.get("attributes", {})))
        return attrs

    def _typed(self, attrs: dict) -> dict:
        dattrs = self.dictionary["attributes"]
        out = {}
        for name, spec in attrs.items():
            base = dattrs.get(name, {})
            entry = {
                "type": spec.get("type") or base.get("type", "string_t"),
                "requirement": spec.get("requirement", "optional"),
            }
            if base.get("is_array") or spec.get("is_array"):
                entry["is_array"] = True
            enum = {**(base.get("enum") or {}), **(spec.get("enum") or {})}
            if enum:
                entry["enum"] = {k: v.get("caption", "") for k, v in enum.items()}
            out[name] = entry
        return out

    def build(self) -> dict:
        classes = {}
        for name, d in self.events.items():
            cat = self._category(name)
            if not cat or "uid" not in d or cat not in self.categories:
                continue
            cat_uid = self.categories[cat]["uid"]
            class_uid = self.ext_uid.get(name, 0) * 100000 + cat_uid * 1000 + d["uid"]
            classes[name] = {
                "uid": class_uid,
                "caption": d.get("caption", name),
                "category": cat,
                "category_uid": cat_uid,
                "attributes": self._typed(self._resolve(name, self.events)),
            }
        objects = {n: {"attributes": self._typed(self._resolve(n, self.objects))} for n in self.objects}
        version = _load(self.root / "version.json")["version"]
        return {"version": version, "classes": classes, "objects": objects,
                "types": list(self.dictionary["types"]["attributes"].keys())}


def main() -> None:
    src, dst = Path(sys.argv[1]), Path(sys.argv[2])
    bundle = Compiler(src).build()
    dst.parent.mkdir(parents=True, exist_ok=True)
    dst.write_text(json.dumps(bundle, separators=(",", ":"), sort_keys=True), encoding="utf-8")
    print(f"OCSF {bundle['version']}: {len(bundle['classes'])} classes, "
          f"{len(bundle['objects'])} objects -> {dst}")


if __name__ == "__main__":
    main()
