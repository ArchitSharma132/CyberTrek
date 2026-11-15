import os
import threading
from datetime import datetime
from typing import Any

from scapy.all import sniff
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.l2 import ARP
from scapy.layers.dns import DNS, DNSQR

from core.alert_manager import alert_manager
from detectors.icmp_flood import IcmpFloodDetector
from detectors.port_scan import PortScanDetector
from detectors.syn_flood import SynFloodDetector
from detectors.udp_flood import UdpFloodDetector
from detectors.ping_sweep import PingSweepDetector
from detectors.arp_spoofing import ArpSpoofingDetector
from detectors.dns_tunneling import DnsTunnelingDetector
from detectors.malformed_fragments import MalformedFragmentDetector
from storage.database import insert_traffic

traffic: list[dict[str, Any]] = []
alerts: list[dict[str, Any]] = []
report_alerts: list[dict[str, Any]] = []
total_packets = 0
total_alerts = 0
_capture_lock = threading.Lock()
_state_lock = threading.RLock()
_capture_started = False
_capture_error: str | None = None

port_scan_detector = PortScanDetector(
    threshold=int(os.getenv("PORT_SCAN_THRESHOLD", "8")),
    window_seconds=int(os.getenv("PORT_SCAN_WINDOW_SECONDS", "10")),
)
syn_flood_detector = SynFloodDetector(
    threshold=int(os.getenv("SYN_FLOOD_THRESHOLD", "40")),
    window_seconds=int(os.getenv("SYN_FLOOD_WINDOW_SECONDS", "5")),
)
icmp_flood_detector = IcmpFloodDetector(
    threshold=int(os.getenv("ICMP_FLOOD_THRESHOLD", "50")),
    window_seconds=int(os.getenv("ICMP_FLOOD_WINDOW_SECONDS", "5")),
)
udp_flood_detector = UdpFloodDetector(
    threshold=int(os.getenv("UDP_FLOOD_THRESHOLD", "100")),
    window_seconds=int(os.getenv("UDP_FLOOD_WINDOW_SECONDS", "5")),
    byte_threshold=int(os.getenv("UDP_FLOOD_BYTE_THRESHOLD", "250000")),
)
ping_sweep_detector = PingSweepDetector(
    threshold=int(os.getenv("PING_SWEEP_THRESHOLD", "10")),
    window_seconds=int(os.getenv("PING_SWEEP_WINDOW_SECONDS", "10")),
)
arp_spoofing_detector = ArpSpoofingDetector(
    change_cooldown_seconds=int(os.getenv("ARP_SPOOF_COOLDOWN_SECONDS", "60")),
)
dns_tunneling_detector = DnsTunnelingDetector(
    query_threshold=int(os.getenv("DNS_TUNNEL_QUERY_THRESHOLD", "40")),
    window_seconds=int(os.getenv("DNS_TUNNEL_WINDOW_SECONDS", "30")),
    label_length_threshold=int(os.getenv("DNS_TUNNEL_LABEL_LENGTH", "45")),
)
malformed_fragment_detector = MalformedFragmentDetector(
    state_ttl_seconds=int(os.getenv("FRAGMENT_STATE_TTL_SECONDS", "30")),
    cooldown_seconds=int(os.getenv("FRAGMENT_ALERT_COOLDOWN_SECONDS", "30")),
)

DETECTORS = (
    port_scan_detector,
    syn_flood_detector,
    icmp_flood_detector,
    udp_flood_detector,
    ping_sweep_detector,
    arp_spoofing_detector,
    dns_tunneling_detector,
    malformed_fragment_detector,
)


def process_packet(packet: Any) -> None:
    global total_packets, total_alerts

    timestamp = datetime.now().astimezone().isoformat(timespec="seconds")
    record: dict[str, Any] | None = None

    if packet.haslayer(ARP):
        arp = packet[ARP]
        record = {
            "timestamp": timestamp,
            "source": str(arp.psrc),
            "destination": str(arp.pdst),
            "protocol": "ARP",
            "source_port": None,
            "destination_port": None,
            "port": "N/A",
            "length": len(packet),
            "flags": "",
            "arp_sender_ip": str(arp.psrc),
            "arp_sender_mac": str(arp.hwsrc),
            "arp_target_ip": str(arp.pdst),
            "arp_operation": int(arp.op),
        }

    elif packet.haslayer(IP):
        ip_layer = packet[IP]
        source = str(ip_layer.src)
        destination = str(ip_layer.dst)
        protocol = "IP"
        source_port = None
        destination_port = None
        flags = ""
        icmp_type = None
        dns_qname = None
        dns_qr = None
        dns_qtype = None

        if packet.haslayer(TCP):
            tcp = packet[TCP]
            protocol = "TCP"
            source_port = int(tcp.sport)
            destination_port = int(tcp.dport)
            flags = str(tcp.flags)
        elif packet.haslayer(UDP):
            udp = packet[UDP]
            protocol = "UDP"
            source_port = int(udp.sport)
            destination_port = int(udp.dport)
        elif packet.haslayer(ICMP):
            protocol = "ICMP"
            icmp_type = int(packet[ICMP].type)

        if packet.haslayer(DNS):
            dns = packet[DNS]
            dns_qr = int(dns.qr)
            if packet.haslayer(DNSQR):
                query = packet[DNSQR].qname
                dns_qname = query.decode("utf-8", errors="replace") if isinstance(query, bytes) else str(query)
                dns_qtype = int(packet[DNSQR].qtype)

        record = {
            "timestamp": timestamp,
            "source": source,
            "destination": destination,
            "protocol": protocol,
            "network_layer": "IPv4",
            "source_port": source_port,
            "destination_port": destination_port,
            "port": destination_port if destination_port is not None else "N/A",
            "length": len(packet),
            "flags": flags,
            "icmp_type": icmp_type,
            "dns_qname": dns_qname,
            "dns_qr": dns_qr,
            "dns_qtype": dns_qtype,
            "ip_total_length": int(ip_layer.len or 0),
            "fragment_offset": int(ip_layer.frag),
            "more_fragments": bool(int(ip_layer.flags) & 1),
            "ip_id": int(ip_layer.id),
            "ip_protocol": int(ip_layer.proto),
        }

    if record is None:
        return

    try:
        record["id"] = insert_traffic(record)
    except Exception as exc:
        _set_capture_error(f"Database write failed: {exc}")

    with _state_lock:
        total_packets += 1
        traffic.insert(0, record)
        del traffic[500:]

    for detector in DETECTORS:
        try:
            finding = detector.inspect(record)
            if finding:
                if "type" in finding and "alert_type" not in finding:
                    finding["alert_type"] = finding.pop("type")
                alert = alert_manager.create_alert(**finding)
                if alert:
                    with _state_lock:
                        total_alerts += 1
                        alerts.insert(0, alert)
                        del alerts[100:]
                        report_alerts.insert(0, alert)
                        del report_alerts[500:]
        except Exception as exc:
            _set_capture_error(f"Detector error ({detector.__class__.__name__}): {exc}")


def _set_capture_error(message: str | None) -> None:
    global _capture_error
    with _state_lock:
        _capture_error = message


def capture_status() -> dict[str, Any]:
    with _state_lock:
        return {
            "running": _capture_started,
            "error": _capture_error,
            "interface": os.getenv("CYBER_TREK_INTERFACE") or None,
        }


def start_capture() -> None:
    global _capture_started
    if not _capture_lock.acquire(blocking=False):
        return
    try:
        _capture_started = True
        interface = os.getenv("CYBER_TREK_INTERFACE", "").strip() or None
        try:
            sniff(iface=interface, prn=process_packet, store=False)
        except Exception as exc:
            _set_capture_error(str(exc))
        finally:
            _capture_started = False
    finally:
        _capture_lock.release()
