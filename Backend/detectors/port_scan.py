from collections import defaultdict, deque
import time
from typing import Any

class PortScanDetector:
    def __init__(self, threshold: int = 8, window_seconds: int = 10):
        self.threshold = max(3, int(threshold))
        self.window_seconds = max(1, int(window_seconds))
        self._events: dict[str, deque[tuple[float, int, str]]] = defaultdict(deque)
        self._last_trigger: dict[str, float] = {}

    def inspect(self, packet: dict[str, Any]) -> dict[str, Any] | None:
        if packet.get("protocol") != "TCP" or packet.get("destination_port") is None:
            return None
        if packet.get("flags") and "S" not in packet["flags"]:
            return None
        source = packet["source"]
        now = time.monotonic()
        events = self._events[source]
        events.append((now, int(packet["destination_port"]), packet["destination"]))
        while events and now - events[0][0] > self.window_seconds:
            events.popleft()
        unique_ports = {event[1] for event in events}
        if len(unique_ports) < self.threshold or now - self._last_trigger.get(source, 0) < self.window_seconds:
            return None
        self._last_trigger[source] = now
        destinations = sorted({event[2] for event in events})
        return {
            "type": "TCP Port Scan",
            "severity": "High" if len(unique_ports) >= self.threshold * 2 else "Medium",
            "source": source,
            "destination": destinations[0] if len(destinations) == 1 else "Multiple",
            "description": f"Source contacted {len(unique_ports)} unique TCP destination ports within {self.window_seconds} seconds. This may indicate port scanning.",
            "evidence": {"unique_destination_ports": sorted(unique_ports), "window_seconds": self.window_seconds},
        }
