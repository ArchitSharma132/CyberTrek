import unittest

from detectors.udp_flood import UdpFloodDetector
from detectors.ping_sweep import PingSweepDetector
from detectors.arp_spoofing import ArpSpoofingDetector
from detectors.dns_tunneling import DnsTunnelingDetector
from detectors.malformed_fragments import MalformedFragmentDetector


class TestNewDetectors(unittest.TestCase):
    def test_udp_flood_detected(self):
        detector = UdpFloodDetector(threshold=10, window_seconds=5, byte_threshold=1_000_000)
        finding = None
        for _ in range(10):
            finding = detector.inspect({
                "protocol": "UDP", "source": "192.0.2.10",
                "destination": "192.0.2.20", "length": 100
            }) or finding
        self.assertIsNotNone(finding)
        self.assertEqual(finding["alert_type"], "Possible UDP Flood")

    def test_normal_udp_not_flagged(self):
        detector = UdpFloodDetector(threshold=10, window_seconds=5)
        finding = detector.inspect({
            "protocol": "UDP", "source": "192.0.2.10",
            "destination": "192.0.2.20", "length": 100
        })
        self.assertIsNone(finding)

    def test_ping_sweep_detected(self):
        detector = PingSweepDetector(threshold=5, window_seconds=10)
        finding = None
        for index in range(5):
            finding = detector.inspect({
                "protocol": "ICMP", "icmp_type": 8,
                "source": "192.0.2.10",
                "destination": f"192.0.2.{index + 20}"
            }) or finding
        self.assertIsNotNone(finding)
        self.assertEqual(finding["alert_type"], "Possible ICMP Ping Sweep")

    def test_arp_mapping_conflict_detected(self):
        detector = ArpSpoofingDetector()
        detector.inspect({
            "protocol": "ARP", "arp_sender_ip": "192.0.2.1",
            "arp_sender_mac": "00:11:22:33:44:55", "arp_operation": 2
        })
        finding = detector.inspect({
            "protocol": "ARP", "arp_sender_ip": "192.0.2.1",
            "arp_sender_mac": "66:77:88:99:aa:bb", "arp_operation": 2
        })
        self.assertIsNotNone(finding)
        self.assertEqual(finding["alert_type"], "Possible ARP Spoofing")

    def test_dns_long_label_detected(self):
        detector = DnsTunnelingDetector(
            query_threshold=100, window_seconds=30, label_length_threshold=30
        )
        finding = detector.inspect({
            "protocol": "UDP", "destination_port": 53, "dns_qr": 0,
            "dns_qname": ("a" * 40) + ".example.test",
            "source": "192.0.2.10", "destination": "192.0.2.53"
        })
        self.assertIsNotNone(finding)
        self.assertEqual(finding["alert_type"], "Possible DNS Tunneling")

    def test_overlapping_fragments_detected(self):
        detector = MalformedFragmentDetector()
        common = {
            "network_layer": "IPv4", "protocol": "UDP",
            "source": "192.0.2.10", "destination": "192.0.2.20",
            "ip_total_length": 1500, "ip_id": 1234, "ip_protocol": 17
        }
        detector.inspect({
            **common, "fragment_offset": 0, "more_fragments": True
        })
        finding = detector.inspect({
            **common, "fragment_offset": 100, "more_fragments": False
        })
        self.assertIsNotNone(finding)
        self.assertEqual(finding["alert_type"], "Malformed IP Fragment")


if __name__ == "__main__":
    unittest.main(verbosity=2)
