from collections import defaultdict, deque
import math
import time
from typing import Any


class DnsTunnelingDetector:
    def __init__(self, query_threshold: int = 40, window_seconds: int = 30, label_length_threshold: int = 45):
        self.query_threshold = max(5, int(query_threshold))
        self.window_seconds = max(5, int(window_seconds))
        self.label_length_threshold = max(20, int(label_length_threshold))
        self._queries: dict[str, deque[tuple[float, str]]] = defaultdict(deque)
        self._last_trigger: dict[str, float] = {}

    @staticmethod
    def _entropy(value: str) -> float:
        if not value:
            return 0.0
        frequencies = {char: value.count(char) / len(value) for char in set(value)}
        return -sum(p * math.log2(p) for p in frequencies.values())

    def inspect(self, packet: dict[str, Any]) -> dict[str, Any] | None:
        if packet.get("protocol") != "UDP" or packet.get("destination_port") != 53:
            return None
        if packet.get("dns_qr") not in (0, False, None):
            return None

        qname = (packet.get("dns_qname") or "").strip(".").lower()
        if not qname:
            return None

        source = packet["source"]
        now = time.monotonic()
        events = self._queries[source]
        events.append((now, qname))
        while events and now - events[0][0] > self.window_seconds:
            events.popleft()

        labels = qname.split(".")
        longest_label = max((len(label) for label in labels), default=0)
        first_label_entropy = self._entropy(labels[0] if labels else "")
        count = len(events)
        suspicious_lengths = longest_label >= self.label_length_threshold
        suspicious_rate = count >= self.query_threshold
        suspicious_encoding = len(labels[0]) >= 25 and first_label_entropy >= 3.5

        if not (suspicious_lengths or suspicious_rate or suspicious_encoding):
            return None
        if now - self._last_trigger.get(source, 0) < self.window_seconds:
            return None

        self._last_trigger[source] = now
        reasons = []
        if suspicious_lengths:
            reasons.append(f"label length {longest_label}")
        if suspicious_rate:
            reasons.append(f"{count} queries in {self.window_seconds}s")
        if suspicious_encoding:
            reasons.append(f"high-entropy label ({first_label_entropy:.2f} bits)")
        return {
            "alert_type": "Possible DNS Tunneling",
            "severity": "High" if suspicious_lengths or suspicious_encoding else "Medium",
            "source": source,
            "destination": packet.get("destination", "N/A"),
            "description": "DNS query pattern is unusual: " + ", ".join(reasons) + ". This is heuristic and requires investigation.",
            "evidence": {"query_name": qname, "query_count_in_window": count, "longest_label_length": longest_label, "first_label_entropy": round(first_label_entropy, 2), "window_seconds": self.window_seconds},
        }
