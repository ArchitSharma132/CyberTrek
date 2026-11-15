from collections import defaultdict, deque
import time
from typing import Any


class MalformedFragmentDetector:
    def __init__(self, state_ttl_seconds: int = 30, cooldown_seconds: int = 30):
        self.state_ttl_seconds = max(5, int(state_ttl_seconds))
        self.cooldown_seconds = max(1, int(cooldown_seconds))
        self._fragments: dict[tuple[str, str, int, int], list[tuple[int, int, float]]] = defaultdict(list)
        self._last_trigger: dict[tuple[str, str, int, int], float] = {}

    def inspect(self, packet: dict[str, Any]) -> dict[str, Any] | None:
        if packet.get("network_layer") != "IPv4":
            return None

        source = packet.get("source", "N/A")
        destination = packet.get("destination", "N/A")
        total_length = int(packet.get("ip_total_length") or 0)
        offset_units = int(packet.get("fragment_offset") or 0)
        more_fragments = bool(packet.get("more_fragments"))
        identification = packet.get("ip_id")
        ip_protocol = int(packet.get("ip_protocol") or 0)

        reason = None
        if total_length > 65535 or total_length < 20:
            reason = f"invalid IPv4 total length {total_length}"

        if not more_fragments and offset_units == 0:
            if reason:
                return self._alert(source, destination, reason, {"ip_total_length": total_length})
            return None

        if identification is None:
            return self._alert(source, destination, "fragment metadata is incomplete", {"ip_total_length": total_length})

        key = (source, destination, int(identification), ip_protocol)
        now = time.monotonic()
        fragments = self._fragments[key]
        fragments[:] = [item for item in fragments if now - item[2] <= self.state_ttl_seconds]

        payload_length = max(0, total_length - 20)
        start = offset_units * 8
        end = start + payload_length

        if end > 65535 - 20:
            reason = "fragment sequence implies an IPv4 datagram larger than the maximum legal size"

        for old_start, old_end, _ in fragments:
            if max(start, old_start) < min(end, old_end):
                reason = "overlapping IPv4 fragment ranges detected"
                break

        if reason:
            return self._alert(source, destination, reason, {
                "identification": identification,
                "fragment_offset": offset_units,
                "fragment_payload_length": payload_length,
                "more_fragments": more_fragments,
            }, key)

        fragments.append((start, end, now))
        if not more_fragments:
            self._fragments.pop(key, None)
        return None

    def _alert(self, source: str, destination: str, reason: str, evidence: dict[str, Any], key=None):
        now = time.monotonic()
        cooldown_key = key or (source, destination, reason, 0)
        if now - self._last_trigger.get(cooldown_key, 0) < self.cooldown_seconds:
            return None
        self._last_trigger[cooldown_key] = now
        return {
            "alert_type": "Malformed IP Fragment",
            "severity": "High",
            "source": source,
            "destination": destination,
            "description": f"Suspicious IPv4 fragmentation: {reason}. This may indicate a malformed-fragment attack or packet corruption.",
            "evidence": evidence,
        }
