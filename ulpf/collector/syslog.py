"""Syslog receiver: UDP (RFC 5426), TCP (RFC 6587 octet-counting or LF framing) and
TLS (RFC 5425) with optional mutual-TLS client authentication.

Hardening: per-peer token-bucket rate limit, bounded frame size, bounded number of
concurrent TCP connections, idle timeouts. Plain UDP is unauthenticated by nature;
use TLS+mTLS for untrusted network segments.
"""
from __future__ import annotations

import asyncio
import logging
import ssl
import time

from ..config import Settings
from ..pipeline import RawEvent
from ..security import TokenBucket
from .batcher import AsyncBatcher

log = logging.getLogger("ulpf.syslog")


class _UDP(asyncio.DatagramProtocol):
    def __init__(self, server: "SyslogServer"):
        self.server = server

    def datagram_received(self, data: bytes, addr) -> None:
        self.server.accept(data, {"transport": "syslog-udp", "peer": addr[0]})


class SyslogServer:
    def __init__(self, settings: Settings, batcher: AsyncBatcher, max_connections: int = 512,
                 idle_timeout: float = 300.0):
        self.settings = settings
        self.batcher = batcher
        self.limiter = TokenBucket(settings.rate_limit_eps)
        self.max_frame = settings.max_line_bytes
        self.max_connections = max_connections
        self.idle_timeout = idle_timeout
        self._conns = 0
        self.rejected = 0

    def accept(self, data: bytes, source: dict) -> None:
        if len(data) > self.max_frame:
            self.rejected += 1
            return
        if not self.limiter.allow(source.get("peer", "?")):
            self.rejected += 1
            return
        text = data.decode("utf-8", errors="replace").rstrip("\r\n\x00")
        if text:
            self.batcher.put(RawEvent(text, source, int(time.time() * 1000)))

    async def _handle_tcp(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, transport: str) -> None:
        peer = (writer.get_extra_info("peername") or ("?",))[0]
        if self._conns >= self.max_connections:
            writer.close()
            return
        self._conns += 1
        source = {"transport": transport, "peer": peer}
        cert = writer.get_extra_info("peercert")
        if cert:
            subject = dict(x[0] for x in cert.get("subject", ()))
            source["client_cn"] = subject.get("commonName")
        try:
            while True:
                first = await asyncio.wait_for(reader.read(1), self.idle_timeout)
                if not first:
                    break
                if first.isdigit():  # RFC 6587 octet counting: "<len> <msg>"
                    digits = first + await asyncio.wait_for(reader.readuntil(b" "), self.idle_timeout)
                    n = int(digits[:-1])
                    if n > self.max_frame:
                        self.rejected += 1
                        break
                    frame = await asyncio.wait_for(reader.readexactly(n), self.idle_timeout)
                else:                # non-transparent framing: newline terminated
                    rest = await asyncio.wait_for(reader.readuntil(b"\n"), self.idle_timeout)
                    frame = first + rest
                self.accept(frame, source)
        except (asyncio.TimeoutError, asyncio.IncompleteReadError, asyncio.LimitOverrunError, ConnectionError, ValueError):
            pass
        finally:
            self._conns -= 1
            writer.close()

    @staticmethod
    def tls_context(cert: str, key: str, ca: str | None) -> ssl.SSLContext:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.load_cert_chain(cert, key)
        if ca:
            ctx.load_verify_locations(ca)
            ctx.verify_mode = ssl.CERT_REQUIRED  # mutual TLS: only enrolled devices may send
        return ctx

    async def start(self, host: str = "0.0.0.0", udp_port: int = 5514, tcp_port: int = 5514,
                    tls_port: int | None = None, tls_cert: str | None = None, tls_key: str | None = None,
                    tls_ca: str | None = None) -> list:
        loop = asyncio.get_running_loop()
        servers: list = []
        transport, _ = await loop.create_datagram_endpoint(lambda: _UDP(self), local_addr=(host, udp_port))
        servers.append(transport)
        servers.append(await asyncio.start_server(lambda r, w: self._handle_tcp(r, w, "syslog-tcp"), host, tcp_port,
                                                  limit=self.max_frame + 16))
        if tls_port and tls_cert and tls_key:
            ctx = self.tls_context(tls_cert, tls_key, tls_ca)
            servers.append(await asyncio.start_server(lambda r, w: self._handle_tcp(r, w, "syslog-tls"), host,
                                                      tls_port, ssl=ctx, limit=self.max_frame + 16))
        log.info("syslog listening udp/%s tcp/%s tls/%s", udp_port, tcp_port, tls_port if tls_cert else "off")
        return servers
