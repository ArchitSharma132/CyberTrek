from collections import defaultdict
import time
from typing import Any


class ArpSpoofingDetector:
    def __init__(self, change_cooldown_seconds: int = 60):
        self.change_cooldown_seconds = max(1, int(change_cooldown_seconds))
        self._ip_to_mac: dict[str, set[str]] = defaultdict(set)
        self._last_trigger: dict[str, float] = {}

    def inspect(self, packet: dict[str, Any]) -> dict[str, Any] | None:
        if packet.get("protocol") != "ARP":
            return None
        sender_ip = packet.get("arp_sender_ip")
        sender_mac = (packet.get("arp_sender_mac") or "").lower()
        if not sender_ip or not sender_mac or sender_ip in {"0.0.0.0", "0.0.0.0/0"}:
            return None

        known_macs = self._ip_to_mac[sender_ip]
        now = time.monotonic()
        if not known_macs:
            known_macs.add(sender_mac)
            return None
        if sender_mac in known_macs:
            return None

        previous = sorted(known_macs)
        known_macs.add(sender_mac)
        if now - self._last_trigger.get(sender_ip, 0) < self.change_cooldown_seconds:
            return None
        self._last_trigger[sender_ip] = now

        return {
            "alert_type": "Possible ARP Spoofing",
            "severity": "High",
            "source": sender_mac,
            "destination": sender_ip,
            "description": f"An IP-to-MAC mapping changed or conflicted: {sender_ip} was previously associated with {', '.join(previous)} and is now advertised by {sender_mac}.",
            "evidence": {"claimed_ip": sender_ip, "previous_macs": previous, "new_mac": sender_mac, "arp_operation": packet.get("arp_operation")},
        }
