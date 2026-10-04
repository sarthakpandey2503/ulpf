import asyncio
import socket

from ulpf.collector.batcher import AsyncBatcher
from ulpf.collector.syslog import SyslogServer
from ulpf.pipeline import Pipeline

FGT = ('<189>date=2026-09-28 time=10:15:02 devname="FGT" devid="FG1" logid="0000000013" type="traffic" '
       'subtype="forward" level="notice" srcip=10.0.0.1 srcport=1234 dstip=8.8.8.8 dstport=53 proto=17 action="accept"')
ASA = "<164>Sep 28 2026 10:15:05 ASA : %ASA-4-106023: Deny tcp src outside:1.2.3.4/4432 dst inside:10.0.0.9/3389 by access-group \"x\" [0x0, 0x0]"


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def test_syslog_udp_tcp_octet_counting(settings):
    settings.max_line_bytes = 4096
    pipeline = Pipeline(settings)
    got: list = []

    async def main():
        batcher = AsyncBatcher(lambda b: got.extend(pipeline.process(b)), max_batch=10, max_delay=0.05)
        batcher.start()
        server = SyslogServer(settings, batcher)
        udp, tcp = _free_port(), _free_port()
        servers = await server.start("127.0.0.1", udp, tcp)
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.sendto(FGT.encode(), ("127.0.0.1", udp))
        s.sendto(b"x" * (settings.max_line_bytes + 10), ("127.0.0.1", udp))  # oversized -> rejected
        r, w = await asyncio.open_connection("127.0.0.1", tcp)
        w.write(ASA.encode() + b"\n")
        framed = FGT.encode()
        w.write(str(len(framed)).encode() + b" " + framed)
        await w.drain()
        for _ in range(50):
            await asyncio.sleep(0.05)
            if len(got) >= 3:
                break
        w.close()
        for srv in servers:
            srv.close()
        return server

    server = asyncio.run(main())
    assert len(got) == 3
    assert {e["ulpf"]["pack"] for e in got} == {"fortinet.fortigate@1.0", "cisco.asa@1.0"}
    assert {e["ulpf"]["source"]["transport"] for e in got} == {"syslog-udp", "syslog-tcp"}
    assert server.rejected == 1
