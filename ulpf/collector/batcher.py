"""Micro-batching between collectors and the pipeline (throughput + one ledger batch per flush)."""
from __future__ import annotations

import asyncio
import logging
from typing import Callable

from ..pipeline import RawEvent

log = logging.getLogger("ulpf.collector")


class AsyncBatcher:
    def __init__(self, handler: Callable[[list[RawEvent]], object], max_batch: int = 256,
                 max_delay: float = 0.2, max_queue: int = 100_000):
        self.handler = handler
        self.max_batch = max_batch
        self.max_delay = max_delay
        self.queue: asyncio.Queue[RawEvent] = asyncio.Queue(maxsize=max_queue)
        self.dropped = 0
        self._task: asyncio.Task | None = None

    def put(self, ev: RawEvent) -> None:
        try:
            self.queue.put_nowait(ev)
        except asyncio.QueueFull:  # back-pressure: shed load rather than exhaust memory
            self.dropped += 1

    async def run(self) -> None:
        loop = asyncio.get_running_loop()
        while True:
            first = await self.queue.get()
            batch = [first]
            deadline = loop.time() + self.max_delay
            while len(batch) < self.max_batch:
                timeout = deadline - loop.time()
                if timeout <= 0:
                    break
                try:
                    batch.append(await asyncio.wait_for(self.queue.get(), timeout))
                except asyncio.TimeoutError:
                    break
            try:
                await asyncio.to_thread(self.handler, batch)
            except Exception as exc:
                log.error("batch handler failed: %s", exc)

    def start(self) -> asyncio.Task:
        self._task = asyncio.create_task(self.run())
        return self._task
