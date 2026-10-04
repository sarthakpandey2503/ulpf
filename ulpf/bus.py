"""Message bus for the scale-out topology.

memory : collectors call the pipeline in-process (single node, air-gap lite).
kafka  : collectors publish raw events to ``ulpf.raw``; N stateless workers
         (consumer group ``ulpf-workers``) normalize and publish to
         ``ulpf.normalized``, which SIEM / data-lake loaders consume. Works with
         Redpanda or Apache Kafka. Partitioning by source peer keeps per-device order.
"""
from __future__ import annotations

import asyncio
import json
import logging

from .config import Settings
from .pipeline import Pipeline, RawEvent

log = logging.getLogger("ulpf.bus")
RAW_TOPIC = "ulpf.raw"
NORM_TOPIC = "ulpf.normalized"
DLQ_TOPIC = "ulpf.deadletter"


class KafkaPublisher:
    def __init__(self, settings: Settings):
        from aiokafka import AIOKafkaProducer

        self.producer = AIOKafkaProducer(bootstrap_servers=settings.kafka_bootstrap, acks="all",
                                         enable_idempotence=True, compression_type="lz4", linger_ms=20)

    async def start(self) -> None:
        await self.producer.start()

    async def publish_raw(self, batch: list[RawEvent]) -> None:
        for ev in batch:
            text = ev.text if isinstance(ev.text, str) else ev.text.decode("utf-8", "replace")
            payload = json.dumps({"text": text, "source": ev.source, "received_ms": ev.received_ms}).encode()
            await self.producer.send(RAW_TOPIC, payload, key=str(ev.source.get("peer", "")).encode())


async def run_worker(settings: Settings, pipeline: Pipeline, batch_size: int = 500) -> None:
    from aiokafka import AIOKafkaConsumer, AIOKafkaProducer

    consumer = AIOKafkaConsumer(RAW_TOPIC, bootstrap_servers=settings.kafka_bootstrap, group_id="ulpf-workers",
                                enable_auto_commit=False, auto_offset_reset="earliest", max_poll_records=batch_size)
    producer = AIOKafkaProducer(bootstrap_servers=settings.kafka_bootstrap, acks="all", enable_idempotence=True,
                                compression_type="lz4", linger_ms=20)
    await consumer.start()
    await producer.start()
    log.info("worker consuming %s -> %s", RAW_TOPIC, NORM_TOPIC)
    try:
        while True:
            records = await consumer.getmany(timeout_ms=500, max_records=batch_size)
            batch: list[RawEvent] = []
            for msgs in records.values():
                for m in msgs:
                    try:
                        d = json.loads(m.value)
                        batch.append(RawEvent(d["text"], d.get("source", {}), d.get("received_ms")))
                    except (ValueError, KeyError):
                        await producer.send(DLQ_TOPIC, m.value)
            if not batch:
                continue
            before = len(pipeline.dead_letters)
            out = await asyncio.to_thread(pipeline.process, batch)
            for e in out:
                await producer.send(NORM_TOPIC, json.dumps(e, default=str).encode(),
                                    key=str(e["class_uid"]).encode())
            for dl in list(pipeline.dead_letters)[before:]:
                await producer.send(DLQ_TOPIC, json.dumps(dl, default=str).encode())
            await producer.flush()
            await consumer.commit()  # at-least-once: commit only after outputs are durable
    finally:
        await consumer.stop()
        await producer.stop()
