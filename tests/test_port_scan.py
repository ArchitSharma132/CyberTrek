from detectors.port_scan import PortScanDetector


def test_port_scan_triggers_after_unique_syn_ports():
    detector = PortScanDetector(threshold=3, window_seconds=10)
    finding = None
    for port in (22, 80, 443):
        finding = detector.inspect({
            "protocol": "TCP", "flags": "S", "source": "192.0.2.10",
            "destination": "192.0.2.20", "destination_port": port,
        }) or finding
    assert finding is not None
    assert finding["type"] == "TCP Port Scan"
    assert len(finding["evidence"]["unique_destination_ports"]) == 3
