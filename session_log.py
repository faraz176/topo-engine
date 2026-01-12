from __future__ import annotations

from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


@dataclass
class SessionEvent:
    ts: str
    kind: str
    data: Dict[str, Any]


class SessionLogger:
    """In-memory session log for debugging and iteration.

    Captures UI interactions, topology/apply operations, and agent prompts/replies.
    Optionally can be saved to a JSON file.
    """

    def __init__(self, max_events: int = 5000):
        self.max_events = max_events
        self.events: List[SessionEvent] = []

    def _now(self) -> str:
        return datetime.now(timezone.utc).isoformat()

    def add(self, kind: str, **data: Any) -> None:
        ev = SessionEvent(ts=self._now(), kind=str(kind), data=dict(data))
        self.events.append(ev)
        if len(self.events) > self.max_events:
            # keep the newest events
            self.events = self.events[-self.max_events :]

    def clear(self) -> None:
        self.events.clear()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema": "topo-session-log/v1",
            "eventCount": len(self.events),
            "events": [asdict(e) for e in self.events],
        }

    def save_json(self, path: str) -> None:
        import json

        with open(path, "w", encoding="utf-8") as f:
            json.dump(self.to_dict(), f, indent=2, ensure_ascii=False)
