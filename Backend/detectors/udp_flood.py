from collections import defaultdict, deque
import time
from typing import Any


class UdpFloodDetector:
    def __init__(self, threshold: int = 100, window_seconds: int = 5, byte_threshold: int = 250_000):
        self.threshold = max(10, int(threshold))
        self.window_seconds = max(1, int(window_seconds))
        self.byte_threshold = max(10_000, int(byte_threshold))
        self._events: dict[tuple[str, str], deque[tuple[float, int]]] = defaultdict(deque)
        self._last_trigger: dict[tuple[str, str], float] = {}

    def inspect(self, packet: dict[str, Any]) -> dict[str, Any] | None:
        if packet.get("protocol") != "UDP":
            return None
        key = (packet["source"], packet["destination"])
        now = time.monotonic()
        events = self._events[key]
        events.append((now, max(0, int(packet.get("length", 0)))))
        while events and now - events[0][0] > self.window_seconds:
            events.popleft()

        packet_count = len(events)
        byte_count = sum(item[1] for item in events)
        if packet_count < self.threshold and byte_count < self.byte_threshold:
            return None
        if now - self._last_trigger.get(key, 0) < self.window_seconds:
            return None

        self._last_trigger[key] = now
        return {
            "alert_type": "Possible UDP Flood",
            "severity": "High" if packet_count >= self.threshold * 2 or byte_count >= self.byte_threshold * 2 else "Medium",
            "source": key[0],
            "destination": key[1],
            "description": f"Observed {packet_count} UDP packets ({byte_count} captured bytes) from one source to one destination within {self.window_seconds} seconds.",
            "evidence": {"udp_packets": packet_count, "bytes": byte_count, "window_seconds": self.window_seconds},
        }
