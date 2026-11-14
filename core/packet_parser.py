"""
Packet Parser Module for Basic Packet-Filtering Firewall.

Defines the PacketData structure and handles packet inspection,
Scapy packet parsing, and synthetic packet crafting.
"""

from dataclasses import dataclass
from datetime import datetime
from typing import Optional, Dict, Any, Tuple
import ipaddress

# Optional Scapy import with fallback
try:
    from scapy.all import IP, TCP, UDP, ICMP, Raw
    from scapy.packet import Packet as ScapyPacket
    SCAPY_AVAILABLE = True
except (ImportError, Exception):
    SCAPY_AVAILABLE = False
    ScapyPacket = Any


COMMON_PORTS: Dict[Tuple[str, int], str] = {
    ("TCP", 20): "FTP Data",
    ("TCP", 21): "FTP Control",
    ("TCP", 22): "SSH",
    ("TCP", 23): "Telnet",
    ("TCP", 25): "SMTP",
    ("TCP", 53): "DNS Zone Transfer",
    ("TCP", 80): "HTTP (Web)",
    ("TCP", 110): "POP3",
    ("TCP", 143): "IMAP",
    ("TCP", 443): "HTTPS (Secure Web)",
    ("TCP", 3306): "MySQL",
    ("TCP", 3389): "RDP",
    ("TCP", 8080): "HTTP Proxy/Alt",
    ("UDP", 53): "DNS Query",
    ("UDP", 67): "DHCP Server",
    ("UDP", 68): "DHCP Client",
    ("UDP", 69): "TFTP",
    ("UDP", 123): "NTP",
    ("UDP", 161): "SNMP",
    ("UDP", 500): "IKE (VPN)",
}


@dataclass
class PacketData:
    """Normalized packet representation for firewall evaluation."""
    src_ip: str
    dst_ip: str
    protocol: str  # TCP, UDP, ICMP, OTHER
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    flags: str = ""
    length: int = 0
    info: str = ""
    timestamp: Optional[datetime] = None
    scapy_pkt: Optional[Any] = None

    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.now()
        self.protocol = self.protocol.upper()

    @property
    def service_name(self) -> str:
        """Infer common service name from destination port and protocol."""
        if self.protocol == "ICMP":
            return "ICMP (Ping/Control)"
        if self.dst_port is not None:
            return COMMON_PORTS.get((self.protocol, self.dst_port), "Unknown Service")
        return "Unknown"

    def summary(self) -> str:
        """Formatted one-line summary of packet."""
        if self.protocol == "ICMP":
            return f"ICMP {self.src_ip} -> {self.dst_ip} ({self.info or 'Echo'})"
        return f"{self.protocol} {self.src_ip}:{self.src_port or 'ANY'} -> {self.dst_ip}:{self.dst_port or 'ANY'} [{self.service_name}]"


class PacketParser:
    """Parses network packets and crafts synthetic packets for simulation."""

    @staticmethod
    def is_scapy_available() -> bool:
        """Return True if Scapy is installed and imported."""
        return SCAPY_AVAILABLE

    @staticmethod
    def validate_packet_input(
        src_ip: str,
        dst_ip: str,
        protocol: str,
        src_port: any,
        dst_port: any
    ) -> Tuple[bool, str]:
        """Validate manual user input for packet simulation."""
        # 1. Validate IPs
        for label, ip in [("Source IP", src_ip), ("Destination IP", dst_ip)]:
            cleaned = str(ip).strip()
            if not cleaned:
                return False, f"{label} cannot be empty."
            try:
                ipaddress.ip_address(cleaned)
            except ValueError:
                return False, f"Invalid {label}: '{cleaned}'. Must be a valid IPv4 address (e.g., 192.168.1.1)."

        # 2. Validate Protocol
        proto_clean = str(protocol).strip().upper()
        if proto_clean not in {"TCP", "UDP", "ICMP"}:
            return False, f"Protocol must be TCP, UDP, or ICMP, got '{protocol}'."

        # 3. Validate Ports
        if proto_clean in {"TCP", "UDP"}:
            for label, p in [("Source Port", src_port), ("Destination Port", dst_port)]:
                try:
                    p_num = int(str(p).strip())
                    if not (0 <= p_num <= 65535):
                        return False, f"{label} must be between 0 and 65535, got {p_num}."
                except (ValueError, TypeError):
                    return False, f"{label} must be a valid integer port (0-65535), got '{p}'."

        return True, "Valid"

    @classmethod
    def create_simulated_packet(
        cls,
        src_ip: str,
        dst_ip: str,
        protocol: str,
        src_port: Optional[int] = None,
        dst_port: Optional[int] = None,
        info: str = "",
        craft_scapy: bool = True
    ) -> PacketData:
        """
        Create a PacketData instance from simulated parameters.
        Optionally generates an underlying Scapy packet object if Scapy is present.
        """
        proto_clean = str(protocol).strip().upper()
        src_p = int(src_port) if (src_port is not None and proto_clean != "ICMP") else None
        dst_p = int(dst_port) if (dst_port is not None and proto_clean != "ICMP") else None

        scapy_obj = None
        length = 64  # standard simulated frame size

        if craft_scapy and SCAPY_AVAILABLE:
            try:
                scapy_obj = cls.craft_scapy_packet(
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    protocol=proto_clean,
                    src_port=src_p or 50000,
                    dst_port=dst_p or 80,
                    payload=info
                )
                length = len(scapy_obj)
            except Exception as e:
                print(f"[PacketParser Warning] Scapy packet crafting failed: {e}")

        return PacketData(
            src_ip=src_ip.strip(),
            dst_ip=dst_ip.strip(),
            protocol=proto_clean,
            src_port=src_p,
            dst_port=dst_p,
            flags="SYN" if proto_clean == "TCP" else "",
            length=length,
            info=info or f"Simulated {proto_clean} packet",
            timestamp=datetime.now(),
            scapy_pkt=scapy_obj
        )

    @classmethod
    def craft_scapy_packet(
        cls,
        src_ip: str,
        dst_ip: str,
        protocol: str,
        src_port: int = 50000,
        dst_port: int = 80,
        payload: str = ""
    ) -> Any:
        """Construct a real Scapy packet object."""
        if not SCAPY_AVAILABLE:
            return None

        ip_layer = IP(src=src_ip, dst=dst_ip)
        payload_layer = Raw(load=payload.encode("utf-8")) if payload else None

        if protocol.upper() == "TCP":
            transport = TCP(sport=src_port, dport=dst_port, flags="S")
        elif protocol.upper() == "UDP":
            transport = UDP(sport=src_port, dport=dst_port)
        elif protocol.upper() == "ICMP":
            transport = ICMP(type=8, code=0)  # Echo request (ping)
        else:
            transport = None

        if transport and payload_layer:
            return ip_layer / transport / payload_layer
        elif transport:
            return ip_layer / transport
        return ip_layer

    @classmethod
    def parse_scapy_packet(cls, pkt: ScapyPacket) -> Optional[PacketData]:
        """
        Extract normalized PacketData from a live Scapy packet.
        Returns None if packet does not contain an IPv4 layer.
        """
        if not SCAPY_AVAILABLE or not pkt.haslayer(IP):
            return None

        ip_layer = pkt[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        length = len(pkt)
        flags = ""
        info = ""

        if pkt.haslayer(TCP):
            tcp_layer = pkt[TCP]
            proto = "TCP"
            src_port = tcp_layer.sport
            dst_port = tcp_layer.dport
            flags = str(tcp_layer.flags)
            info = f"TCP Flags: {flags}"
        elif pkt.haslayer(UDP):
            udp_layer = pkt[UDP]
            proto = "UDP"
            src_port = udp_layer.sport
            dst_port = udp_layer.dport
            info = "UDP Datagram"
        elif pkt.haslayer(ICMP):
            icmp_layer = pkt[ICMP]
            proto = "ICMP"
            src_port = None
            dst_port = None
            icmp_type = icmp_layer.type
            info = f"ICMP Type {icmp_type} (Echo Req)" if icmp_type == 8 else f"ICMP Type {icmp_type}"
        else:
            proto = "OTHER"
            src_port = None
            dst_port = None
            info = f"Protocol #{ip_layer.proto}"

        return PacketData(
            src_ip=src_ip,
            dst_ip=dst_ip,
            protocol=proto,
            src_port=src_port,
            dst_port=dst_port,
            flags=flags,
            length=length,
            info=info,
            timestamp=datetime.now(),
            scapy_pkt=pkt
        )
