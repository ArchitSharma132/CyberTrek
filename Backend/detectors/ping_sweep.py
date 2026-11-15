from collections import defaultdict, deque
import time
from typing import Any


class PingSweepDetector:
    def __init__(self, threshold: int = 10, window_seconds: int = 10):
        self.threshold = max(3, int(threshold))
        self.window_seconds = max(1, int(window_seconds))
        self._events: dict[str, deque[tuple[float, str]]] = defaultdict(deque)
        self._last_trigger: dict[str, float] = {}

    def inspect(self, packet: dict[str, Any]) -> dict[str, Any] | None:
        if packet.get("protocol") != "ICMP" or packet.get("icmp_type") != 8:
            return None
        source = packet["source"]
        now = time.monotonic()
        events = self._events[source]
        events.append((now, packet["destination"]))
        while events and now - events[0][0] > self.window_seconds:
            events.popleft()
        targets = {destination for _, destination in events}
        if len(targets) < self.threshold or now - self._last_trigger.get(source, 0) < self.window_seconds:
            return None
        self._last_trigger[source] = now
        return {
            "alert_type": "Possible ICMP Ping Sweep",
            "severity": "High" if len(targets) >= self.threshold * 2 else "Medium",
            "source": source,
            "destination": "Multiple",
            "description": f"Source sent ICMP echo requests to {len(targets)} distinct destination IPs within {self.window_seconds} seconds.",
            "evidence": {"unique_targets": sorted(targets), "target_count": len(targets), "window_seconds": self.window_seconds},
        }
