import threading
import time
from datetime import datetime
from typing import Any

from storage.database import insert_alert

class AlertManager:
    def __init__(self, cooldown_seconds: int = 30):
        self.cooldown_seconds = max(0, int(cooldown_seconds))
        self._last_alert: dict[tuple[str, str, str], float] = {}
        self._lock = threading.Lock()
        self._recent: list[dict[str, Any]] = []
        self.total_alerts = 0

    def create_alert(
        self,
        alert_type: str,
        severity: str,
        source: str,
        destination: str = "N/A",
        description: str = "Potential suspicious network activity detected.",
        evidence: dict[str, Any] | None = None,
    ) -> dict[str, Any] | None:
        now_mono = time.monotonic()
        key = (alert_type, source, destination)
        with self._lock:
            last_seen = self._last_alert.get(key)
            if last_seen is not None and now_mono - last_seen < self.cooldown_seconds:
                return None
            self._last_alert[key] = now_mono
            if len(self._last_alert) > 5000:
                cutoff = now_mono - max(self.cooldown_seconds * 2, 60)
                self._last_alert = {k: v for k, v in self._last_alert.items() if v >= cutoff}

        alert = {
            "timestamp": datetime.now().astimezone().isoformat(timespec="seconds"),
            "type": alert_type,
            "severity": severity.title(),
            "source": source,
            "destination": destination,
            "description": description,
            "evidence": evidence or {},
        }
        try:
            alert = insert_alert(alert)
        except Exception:
            with self._lock:
                self._last_alert.pop(key, None)
            raise
        with self._lock:
            self.total_alerts += 1
            self._recent.insert(0, alert)
            del self._recent[100:]
        return alert

    def recent_alerts(self, limit: int = 20) -> list[dict[str, Any]]:
        with self._lock:
            return [dict(alert) for alert in self._recent[:max(1, min(limit, 100))]]

alert_manager = AlertManager()
