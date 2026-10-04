"""Template mining for free-text logs (Drain3) and template -> named-regex synthesis.

Drain3 clusters messages into templates such as
``forward: <*> <*> src-mac <MAC>, proto TCP <*> <IP>:<NUM>-><IP>:<NUM>, len <NUM>``.
Each wildcard is then aligned back to the cluster's sample tokens to recover
literal prefixes/suffixes (``in:``, ``out:``, ``,``) and every variable part
becomes an RE2 named group whose name is inferred from context
(``key:value``, ``key value``, ``ip:port->ip:port``).
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from os.path import commonprefix

_MASKS = [
    ("MAC", r"((?<=[^A-Za-z0-9])|^)([0-9a-fA-F]{2}[:\-]){5}[0-9a-fA-F]{2}((?=[^A-Za-z0-9])|$)"),
    ("IP", r"((?<=[^A-Za-z0-9])|^)(\d{1,3}\.){3}\d{1,3}((?=[^A-Za-z0-9])|$)"),
    ("NUM", r"((?<=[^A-Za-z0-9.])|^)\d+((?=[^A-Za-z0-9.])|$)"),
]
GROUP_RX = {
    "IP": r"(?:\d{1,3}(?:\.\d{1,3}){3}|[0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4}){2,7})",
    "NUM": r"\d+",
    "MAC": r"(?:[0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}",
}
_MARK = re.compile(r"<(\*|IP|NUM|MAC)>")
_PROTOS = {"tcp", "udp", "icmp", "gre", "esp", "sctp", "icmpv6"}
_KV_TOKEN = re.compile(r"^([A-Za-z][\w\-]*)([:=])([^(\[\s:=][^\s]*?)([,;]?)$")


def _miner():
    from drain3 import TemplateMiner
    from drain3.masking import MaskingInstruction
    from drain3.template_miner_config import TemplateMinerConfig

    cfg = TemplateMinerConfig()
    cfg.masking_instructions = [MaskingInstruction(rx, name) for name, rx in _MASKS]
    cfg.profiling_enabled = False
    cfg.drain_sim_th = 0.4
    cfg.drain_depth = 4
    return TemplateMiner(config=cfg)


@dataclass
class Cluster:
    template: str
    samples: list[str] = field(default_factory=list)
    size: int = 0


def mine(messages: list[str], max_samples: int = 50) -> list[Cluster]:
    """Cluster messages; falls back to a digit-masking signature if Drain3 is unavailable."""
    clusters: dict[int | str, Cluster] = {}
    try:
        tm = _miner()
        for msg in messages:
            r = tm.add_log_message(msg)
            cid = r["cluster_id"]
            c = clusters.setdefault(cid, Cluster(""))
            c.size += 1
            if len(c.samples) < max_samples:
                c.samples.append(msg)
        for cl in tm.drain.clusters:
            if cl.cluster_id in clusters:
                clusters[cl.cluster_id].template = cl.get_template()
    except ImportError:  # pragma: no cover
        for msg in messages:
            sig = re.sub(r"\d+", "<NUM>", msg)
            c = clusters.setdefault(sig, Cluster(sig))
            c.size += 1
            if len(c.samples) < max_samples:
                c.samples.append(msg)
    return sorted(clusters.values(), key=lambda c: -c.size)


def _snake(s: str) -> str:
    s = re.sub(r"[^0-9A-Za-z]+", "_", s).strip("_").lower()
    return s if s and not s[0].isdigit() else (f"f_{s}" if s else "")


class _Namer:
    def __init__(self) -> None:
        self.used: dict[str, int] = {}

    def __call__(self, base: str) -> str:
        base = _snake(base) or "field"
        n = self.used.get(base, 0) + 1
        self.used[base] = n
        return base if n == 1 else f"{base}_{n}"


def _key_before(text: str) -> str:
    """'in:' -> 'in', 'connection-state:' -> 'connection_state', 'len ' -> ''."""
    m = re.search(r"([A-Za-z][\w\-]*)[:=]$", text)
    return m.group(1) if m else ""


def _token_regex(tpl_tok: str, sample_toks: list[str], prev_literal: str, namer: _Namer,
                 arrow_state: dict) -> tuple[str, list[str]]:
    parts = _MARK.split(tpl_tok)  # literal, kind, literal, kind, ...
    if len(parts) == 1:
        kv = _KV_TOKEN.match(tpl_tok)
        if kv:  # 'in:ether1' is a key with a value that merely happened to be constant in this cluster
            name = namer(kv.group(1))
            return re.escape(kv.group(1) + kv.group(2)) + f"(?P<{name}>.+?)" + re.escape(kv.group(4)), [name]
        bare = tpl_tok.rstrip(",;")
        if bare.lower() in _PROTOS:  # protocol literals differ between clusters of the same source
            name = namer("proto")
            return f"(?P<{name}>[A-Za-z0-9]+)" + re.escape(tpl_tok[len(bare):]), [name]
        return re.escape(tpl_tok), []
    if tpl_tok == "<*>" and sample_toks:
        # recover common literal prefix / suffix from the actual tokens
        pre = commonprefix(sample_toks)
        m = re.match(r"^(.*[:=(\[])", pre)
        pre = m.group(1) if m else ""
        rev = [t[len(pre):][::-1] for t in sample_toks]
        suf = commonprefix(rev)[::-1]
        m = re.search(r"([,;)\]]+)$", suf)
        suf = m.group(1) if m else ""
        key = _key_before(pre)
        if not key:
            key = f"{prev_literal}_flags" if prev_literal.lower() in _PROTOS else (prev_literal or "value")
        name = namer(key)
        return re.escape(pre) + f"(?P<{name}>.+?)" + re.escape(suf), [name]
    out, names = [], []
    for i, p in enumerate(parts):
        if i % 2 == 0:
            out.append(re.escape(p))
            if "->" in p or "=>" in p:
                arrow_state["side"] = "dst"
            continue
        kind = p
        lit_before = parts[i - 1]
        if kind == "IP":
            base = f"{arrow_state['side']}_ip"
            arrow_state["last"] = arrow_state["side"]
        elif kind == "NUM" and lit_before.endswith(":") and i >= 2 and parts[i - 2] == "IP":
            base = f"{arrow_state.get('last', 'src')}_port"
        elif kind == "*":
            base = _key_before(lit_before) or prev_literal or "value"
        else:
            base = _key_before(lit_before) or (prev_literal if i == 1 else "") or kind.lower()
            if kind == "MAC" and not base.endswith("mac"):
                base = f"{base}_mac" if base != "mac" else base
        name = namer(base)
        names.append(name)
        out.append(f"(?P<{name}>{GROUP_RX.get(kind, '.+?')})")
    return "".join(out), names


def template_to_regex(template: str, samples: list[str]) -> tuple[str, list[str]]:
    """Build an anchored RE2-compatible regex with named groups for one cluster."""
    tpl_toks = template.split()
    sample_toks = [s.split() for s in samples]
    sample_toks = [t for t in sample_toks if len(t) == len(tpl_toks)]
    namer = _Namer()
    arrow = {"side": "src"}
    pieces, names = [], []
    prev_literal = ""
    for idx, tok in enumerate(tpl_toks):
        rx, n = _token_regex(tok, [t[idx] for t in sample_toks], prev_literal, namer, arrow)
        pieces.append(rx)
        names += n
        if not _MARK.search(tok):
            words = re.findall(r"[A-Za-z][\w\-]*", tok)
            prev_literal = words[-1] if words else ""
    body = r"\s+".join(pieces)
    body = re.sub(r"\(\?P<(\w+)>\.\+\?\)$", r"(?P<\1>.+)", body)  # last lazy group -> greedy
    return "^" + body + "$", names


def cluster_patterns(clusters: list[Cluster]) -> list[tuple[str, list[str], int]]:
    """Regex per cluster, de-duplicated, most frequent first: [(regex, group_names, support)]."""
    seen: dict[str, list] = {}
    for c in clusters:
        rx, names = template_to_regex(c.template, c.samples)
        if rx in seen:
            seen[rx][2] += c.size
        else:
            seen[rx] = [rx, names, c.size]
    return sorted((tuple(v) for v in seen.values()), key=lambda v: -v[2])
