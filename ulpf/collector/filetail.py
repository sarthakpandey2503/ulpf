"""File ingestion: one-shot import or follow mode with rotation (inode change / truncation)."""
from __future__ import annotations

import os
import time
from pathlib import Path
from typing import Callable, Iterator

from ..pipeline import RawEvent


def read_file(path: Path, source_hint: str | None = None) -> Iterator[RawEvent]:
    src = {"transport": "file", "file": str(path)}
    if source_hint:
        src["source_hint"] = source_hint
    with path.open("rb") as fh:
        for line in fh:
            line = line.rstrip(b"\r\n")
            if line:
                yield RawEvent(line, dict(src))


def follow(path: Path, handler: Callable[[list[RawEvent]], object], batch: int = 256, poll: float = 0.5,
           from_start: bool = False, stop: Callable[[], bool] = lambda: False) -> None:
    fh = None
    inode = None
    buf: list[RawEvent] = []
    partial = b""
    while not stop():
        try:
            st = os.stat(path)
        except FileNotFoundError:
            time.sleep(poll)
            continue
        if fh is None or st.st_ino != inode or st.st_size < fh.tell():
            if fh:
                fh.close()
            fh = path.open("rb")
            if not from_start and inode is None:
                fh.seek(0, os.SEEK_END)
            inode = st.st_ino
            partial = b""
        chunk = fh.read(1 << 20)
        if chunk:
            data = partial + chunk
            lines = data.split(b"\n")
            partial = lines.pop()
            for ln in lines:
                ln = ln.rstrip(b"\r")
                if ln:
                    buf.append(RawEvent(ln, {"transport": "file", "file": str(path)}))
                if len(buf) >= batch:
                    handler(buf)
                    buf = []
        else:
            if buf:
                handler(buf)
                buf = []
            time.sleep(poll)
