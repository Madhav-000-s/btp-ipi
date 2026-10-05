"""Append-only trajectory logging. One JSONL line per event; never overwrite.

You will re-analyse these logs many times and cannot cheaply re-run. Every event carries the full
episode key so lines are self-describing even if files get concatenated.
"""
from __future__ import annotations

import json
import threading
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any


def _jsonable(o: Any):
    if hasattr(o, "model_dump"):
        return o.model_dump()
    if hasattr(o, "__dataclass_fields__"):
        return asdict(o)
    if isinstance(o, (set, frozenset, tuple)):
        return list(o)
    if hasattr(o, "value"):
        return o.value
    return str(o)


class JsonlSink:
    _lock = threading.Lock()

    def __init__(self, path: Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def write(self, record: dict) -> None:
        line = json.dumps(record, default=_jsonable, ensure_ascii=False)
        with self._lock, open(self.path, "a", encoding="utf-8") as f:
            f.write(line + "\n")


@dataclass
class Episode:
    run_id: str
    suite: str
    user_task: str
    injection_task: str | None
    attack: str
    defense: str
    model: str
    repeat: int = 0
    attempt: int = 0  # adaptive attacker iteration within its query budget
    sink: JsonlSink | None = None
    events: list[dict] = field(default_factory=list)

    @property
    def key(self) -> dict:
        return {
            "run_id": self.run_id, "suite": self.suite, "user_task": self.user_task,
            "injection_task": self.injection_task, "attack": self.attack, "defense": self.defense,
            "model": self.model, "repeat": self.repeat, "attempt": self.attempt,
        }

    def log(self, event: str, **payload) -> None:
        rec = {"ts": time.time(), "event": event, **self.key, **payload}
        self.events.append(rec)
        if self.sink:
            self.sink.write(rec)

    def tool_events(self) -> list[dict]:
        return [e for e in self.events if e["event"] == "tool_call"]
