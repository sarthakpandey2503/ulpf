from ulpf.packs.loader import PackRegistry
from ulpf.runtime import Runtime

FGT = ('<189>date=2026-09-28 time=10:15:02 devname="FGT" devid="FG1" logid="0000000013" type="traffic" '
       'subtype="forward" level="notice" srcip=10.0.0.1 srcport=1234 dstip=8.8.8.8 dstport=53 proto=17 action="accept"')


def test_chain_and_builtin_signatures(settings):
    settings.sinks = ["sqlite"]
    settings.require_signed_packs = True
    rt = Runtime(settings)
    assert rt.registry.rejected == {}
    assert all(p.signed for p in rt.registry.packs)
    out = rt.ingest([FGT], {"transport": "test"})
    proof = rt.ledger.verify_event(out[0])
    assert proof["verified"] is True
    assert rt.ledger.verify_chain()["verified"] is True
    assert rt.audit.verify()["verified"] is True


def test_registry_still_constructs(settings):
    reg = PackRegistry(settings).load()
    assert reg.get("fortinet.fortigate") is not None
