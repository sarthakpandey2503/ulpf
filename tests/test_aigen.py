from ulpf.aigen.synth import synthesize
from ulpf.aigen.unknown import fingerprint
from ulpf.packs.loader import PackRegistry
from ulpf.sniffer import sniff


def test_synth_sophos_passes_without_llm(settings, root):
    lines = (root / "samples" / "unknown" / "sophos_xg.log").read_text(encoding="utf-8").splitlines()
    reg = PackRegistry(settings).load()
    draft = synthesize(lines, settings, "Sophos", "XG Firewall", use_llm="off", registry=reg)
    assert draft.report["passed"] is True
    assert draft.report["parse_rate"] == 1.0
    mapping = draft.doc["classes"][0]["mapping"]
    assert "src_endpoint.ip" in mapping
    assert "dst_endpoint.ip" in mapping


def test_unknown_fingerprint_is_stable():
    raw = "<30>device=\"SFW\" src_ip=10.0.0.1 dst_ip=1.2.3.4 status=Allow"
    assert fingerprint(raw, sniff(raw)) == fingerprint(raw, sniff(raw))
