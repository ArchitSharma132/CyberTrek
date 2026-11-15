from detectors.syn_flood import SynFloodDetector


def test_syn_flood_triggers_at_threshold():
    detector = SynFloodDetector(threshold=5, window_seconds=5)
    finding = None
    for _ in range(5):
        finding = detector.inspect({
            "protocol": "TCP", "flags": "S", "source": "192.0.2.10",
            "destination": "192.0.2.20", "destination_port": 80,
        }) or finding
    assert finding is not None
    assert finding["type"] == "Possible SYN Flood"


def test_ack_packets_do_not_count_as_syn_only():
    detector = SynFloodDetector(threshold=5, window_seconds=5)
    assert detector.inspect({
        "protocol": "TCP", "flags": "SA", "source": "192.0.2.10",
        "destination": "192.0.2.20", "destination_port": 80,
    }) is None
