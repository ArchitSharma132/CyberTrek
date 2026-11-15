from detectors.icmp_flood import IcmpFloodDetector


def test_icmp_flood_triggers_at_threshold():
    detector = IcmpFloodDetector(threshold=5, window_seconds=5)
    finding = None
    for _ in range(5):
        finding = detector.inspect({
            "protocol": "ICMP", "source": "192.0.2.10", "destination": "192.0.2.20",
        }) or finding
    assert finding is not None
    assert finding["type"] == "Possible ICMP Flood"
