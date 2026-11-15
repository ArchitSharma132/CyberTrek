from collections import Counter
from typing import Any

from storage.database import fetch_alerts, fetch_traffic, get_counts, query_all


def get_dashboard_statistics() -> dict[str, Any]:
    counts = get_counts()
    protocols = query_all("SELECT protocol, COUNT(*) AS count FROM traffic GROUP BY protocol ORDER BY count DESC")
    attack_types = query_all("SELECT type, COUNT(*) AS count FROM alerts GROUP BY type ORDER BY count DESC")
    top_sources = query_all("SELECT source, COUNT(*) AS count FROM traffic GROUP BY source ORDER BY count DESC LIMIT 10")
    severities = query_all("SELECT severity, COUNT(*) AS count FROM alerts GROUP BY severity ORDER BY count DESC")
    timeline = query_all(
        """SELECT substr(timestamp, 1, 16) AS minute, COUNT(*) AS count
           FROM alerts GROUP BY minute ORDER BY minute DESC LIMIT 30"""
    )
    return {
        **counts,
        "protocol_distribution": protocols,
        "attack_distribution": attack_types,
        "top_sources": top_sources,
        "severity_distribution": severities,
        "alert_timeline": list(reversed(timeline)),
    }


def get_summary() -> dict[str, Any]:
    counts = get_counts()
    return {
        **counts,
        "recent_alerts": fetch_alerts(20),
    }
