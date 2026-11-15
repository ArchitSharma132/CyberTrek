from collections import defaultdict, deque
import time
from typing import Any

class SynFloodDetector:
    def __init__(self, threshold: int = 40, window_seconds: int = 5):
        self.threshold = max(5, int(threshold))
        self.window_seconds = max(1, int(window_seconds))
        self._events: dict[tuple[str, str], deque[float]] = defaultdict(deque)
        self._last_trigger: dict[tuple[str, str], float] = {}

    def inspect(self, packet: dict[str, Any]) -> dict[str, Any] | None:
        flags = packet.get("flags", "")
        if packet.get("protocol") != "TCP" or "S" not in flags or "A" in flags:
            return None
        key = (packet["source"], packet["destination"])
        now = time.monotonic()
        events = self._events[key]
        events.append(now)
        while events and now - events[0] > self.window_seconds:
            events.popleft()
        if len(events) < self.threshold or now - self._last_trigger.get(key, 0) < self.window_seconds:
            return None
        self._last_trigger[key] = now
        return {
            "type": "Possible SYN Flood",
            "severity": "High",
            "source": key[0],
            "destination": key[1],
            "description": f"Observed {len(events)} TCP SYN packets from one source to one destination within {self.window_seconds} seconds. This may indicate a SYN flood.",
            "evidence": {"syn_packets_in_window": len(events), "window_seconds": self.window_seconds},
        }
