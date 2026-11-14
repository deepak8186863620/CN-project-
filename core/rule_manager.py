"""
Rule Manager Module for Basic Packet-Filtering Firewall.

Handles rule creation, validation, persistent storage in JSON,
and matching logic for IP addresses, protocols, and port ranges.
"""

import os
import json
import ipaddress
from dataclasses import dataclass, asdict
from typing import List, Dict, Tuple, Optional, Any


VALID_PROTOCOLS = {"TCP", "UDP", "ICMP", "ANY", "*"}
VALID_ACTIONS = {"ALLOW", "BLOCK"}


@dataclass
class FirewallRule:
    """Represents a single packet filtering rule."""
    id: int
    name: str
    src_ip: str
    dst_ip: str
    protocol: str
    src_port: str
    dst_port: str
    action: str  # ALLOW or BLOCK
    enabled: bool = True

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "FirewallRule":
        return cls(
            id=int(data.get("id", 0)),
            name=str(data.get("name", "Unnamed Rule")),
            src_ip=str(data.get("src_ip", "ANY")).strip(),
            dst_ip=str(data.get("dst_ip", "ANY")).strip(),
            protocol=str(data.get("protocol", "ANY")).strip().upper(),
            src_port=str(data.get("src_port", "ANY")).strip(),
            dst_port=str(data.get("dst_port", "ANY")).strip(),
            action=str(data.get("action", "BLOCK")).strip().upper(),
            enabled=bool(data.get("enabled", True)),
        )

    def summary(self) -> str:
        """User-friendly summary of the rule."""
        p_str = self.protocol
        dst_p = f":{self.dst_port}" if self.dst_port not in ("ANY", "*") else ""
        return f"Rule {self.id} [{self.name}]: {p_str} {self.src_ip} -> {self.dst_ip}{dst_p} => {self.action}"


DEFAULT_RULES = [
    {
        "id": 1,
        "name": "Allow Web HTTP",
        "src_ip": "ANY",
        "dst_ip": "ANY",
        "protocol": "TCP",
        "src_port": "ANY",
        "dst_port": "80",
        "action": "ALLOW",
        "enabled": True,
    },
    {
        "id": 2,
        "name": "Allow Web HTTPS",
        "src_ip": "ANY",
        "dst_ip": "ANY",
        "protocol": "TCP",
        "src_port": "ANY",
        "dst_port": "443",
        "action": "ALLOW",
        "enabled": True,
    },
    {
        "id": 3,
        "name": "Block Insecure Telnet",
        "src_ip": "ANY",
        "dst_ip": "ANY",
        "protocol": "TCP",
        "src_port": "ANY",
        "dst_port": "23",
        "action": "BLOCK",
        "enabled": True,
    },
    {
        "id": 4,
        "name": "Allow DNS Queries",
        "src_ip": "ANY",
        "dst_ip": "ANY",
        "protocol": "UDP",
        "src_port": "ANY",
        "dst_port": "53",
        "action": "ALLOW",
        "enabled": True,
    },
    {
        "id": 5,
        "name": "Block ICMP Ping",
        "src_ip": "ANY",
        "dst_ip": "ANY",
        "protocol": "ICMP",
        "src_port": "ANY",
        "dst_port": "ANY",
        "action": "BLOCK",
        "enabled": True,
    },
]


class RuleManager:
    """Manages the rule set, validation, file persistence, and ordering."""

    def __init__(self, rules_file_path: str = "data/rules.json"):
        self.rules_file = os.path.abspath(rules_file_path)
        self.rules: List[FirewallRule] = []
        self.load_rules()

    @staticmethod
    def validate_ip(ip_str: str) -> Tuple[bool, str]:
        """Validate whether an IP string is ANY, *, valid IPv4, or valid CIDR."""
        cleaned = ip_str.strip().upper()
        if cleaned in ("", "ANY", "*"):
            return True, "ANY"
        try:
            # Check if CIDR or single IP
            if "/" in cleaned:
                network = ipaddress.ip_network(cleaned, strict=False)
                return True, str(network)
            else:
                addr = ipaddress.ip_address(cleaned)
                return True, str(addr)
        except ValueError as err:
            return False, f"Invalid IP address or CIDR notation: '{ip_str}' ({err})"

    @staticmethod
    def validate_port(port_str: str, protocol: str = "TCP") -> Tuple[bool, str]:
        """Validate whether a port string is ANY, *, or within 0-65535."""
        cleaned = str(port_str).strip().upper()
        proto_clean = str(protocol).strip().upper()

        if proto_clean == "ICMP":
            # ICMP does not have transport layer ports
            return True, "ANY"

        if cleaned in ("", "ANY", "*"):
            return True, "ANY"

        try:
            port_num = int(cleaned)
            if 0 <= port_num <= 65535:
                return True, str(port_num)
            return False, f"Port must be between 0 and 65535, got {port_num}"
        except ValueError:
            return False, f"Invalid port number: '{port_str}'"

    @staticmethod
    def validate_protocol(proto_str: str) -> Tuple[bool, str]:
        """Validate protocol against supported list."""
        cleaned = proto_str.strip().upper()
        if cleaned in VALID_PROTOCOLS:
            return True, cleaned
        return False, f"Protocol must be one of {sorted(VALID_PROTOCOLS)}, got '{proto_str}'"

    @staticmethod
    def validate_action(action_str: str) -> Tuple[bool, str]:
        """Validate firewall action (ALLOW or BLOCK)."""
        cleaned = action_str.strip().upper()
        if cleaned in VALID_ACTIONS:
            return True, cleaned
        return False, f"Action must be ALLOW or BLOCK, got '{action_str}'"

    def validate_rule_data(self, data: Dict[str, Any]) -> Tuple[bool, str]:
        """Validates all fields of a rule candidate."""
        name = str(data.get("name", "")).strip()
        if not name:
            return False, "Rule name cannot be empty."

        proto_ok, proto_val = self.validate_protocol(str(data.get("protocol", "TCP")))
        if not proto_ok:
            return False, proto_val

        src_ip_ok, src_ip_val = self.validate_ip(str(data.get("src_ip", "ANY")))
        if not src_ip_ok:
            return False, src_ip_val

        dst_ip_ok, dst_ip_val = self.validate_ip(str(data.get("dst_ip", "ANY")))
        if not dst_ip_ok:
            return False, dst_ip_val

        src_p_ok, src_p_val = self.validate_port(str(data.get("src_port", "ANY")), proto_val)
        if not src_p_ok:
            return False, src_p_val

        dst_p_ok, dst_p_val = self.validate_port(str(data.get("dst_port", "ANY")), proto_val)
        if not dst_p_ok:
            return False, dst_p_val

        act_ok, act_val = self.validate_action(str(data.get("action", "BLOCK")))
        if not act_ok:
            return False, act_val

        return True, "Valid"

    def load_rules(self) -> None:
        """Load rules from JSON file. Recovers gracefully if file is corrupted or absent."""
        if not os.path.exists(self.rules_file):
            self.reset_to_defaults()
            return

        try:
            with open(self.rules_file, "r", encoding="utf-8") as f:
                raw_data = json.load(f)

            if not isinstance(raw_data, list):
                raise ValueError("Rules file content is not a JSON list.")

            loaded = []
            for item in raw_data:
                rule = FirewallRule.from_dict(item)
                loaded.append(rule)

            self.rules = loaded
            # If empty, restore defaults
            if not self.rules:
                self.reset_to_defaults()
        except Exception as e:
            print(f"[RuleManager Warning] Failed to load '{self.rules_file}': {e}. Reverting to defaults.")
            self.reset_to_defaults()

    def save_rules(self) -> bool:
        """Save active rule list to JSON file."""
        try:
            parent_dir = os.path.dirname(self.rules_file)
            if parent_dir and not os.path.exists(parent_dir):
                os.makedirs(parent_dir, exist_ok=True)

            data = [r.to_dict() for r in self.rules]
            with open(self.rules_file, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
            return True
        except Exception as e:
            print(f"[RuleManager Error] Failed to save rules: {e}")
            return False

    def reset_to_defaults(self) -> None:
        """Reset rule database to standard initial educational rules."""
        self.rules = [FirewallRule.from_dict(d) for d in DEFAULT_RULES]
        self.save_rules()

    def get_rules(self) -> List[FirewallRule]:
        """Return all defined rules in priority order."""
        return list(self.rules)

    def get_active_rules(self) -> List[FirewallRule]:
        """Return only enabled rules."""
        return [r for r in self.rules if r.enabled]

    def _next_id(self) -> int:
        """Compute the next unique rule ID."""
        if not self.rules:
            return 1
        return max(r.id for r in self.rules) + 1

    def add_rule(self, rule_data: Dict[str, Any]) -> Tuple[bool, str, Optional[FirewallRule]]:
        """Validate and append a new rule."""
        ok, msg = self.validate_rule_data(rule_data)
        if not ok:
            return False, msg, None

        new_id = self._next_id()
        # Clean values
        _, proto = self.validate_protocol(str(rule_data.get("protocol", "TCP")))
        _, src_ip = self.validate_ip(str(rule_data.get("src_ip", "ANY")))
        _, dst_ip = self.validate_ip(str(rule_data.get("dst_ip", "ANY")))
        _, src_port = self.validate_port(str(rule_data.get("src_port", "ANY")), proto)
        _, dst_port = self.validate_port(str(rule_data.get("dst_port", "ANY")), proto)
        _, action = self.validate_action(str(rule_data.get("action", "BLOCK")))

        rule = FirewallRule(
            id=new_id,
            name=str(rule_data.get("name", f"Rule {new_id}")).strip(),
            src_ip=src_ip,
            dst_ip=dst_ip,
            protocol=proto,
            src_port=src_port,
            dst_port=dst_port,
            action=action,
            enabled=bool(rule_data.get("enabled", True)),
        )

        self.rules.append(rule)
        self.save_rules()
        return True, "Rule added successfully.", rule

    def update_rule(self, rule_id: int, rule_data: Dict[str, Any]) -> Tuple[bool, str]:
        """Update an existing rule by ID."""
        ok, msg = self.validate_rule_data(rule_data)
        if not ok:
            return False, msg

        for idx, r in enumerate(self.rules):
            if r.id == rule_id:
                _, proto = self.validate_protocol(str(rule_data.get("protocol", "TCP")))
                _, src_ip = self.validate_ip(str(rule_data.get("src_ip", "ANY")))
                _, dst_ip = self.validate_ip(str(rule_data.get("dst_ip", "ANY")))
                _, src_port = self.validate_port(str(rule_data.get("src_port", "ANY")), proto)
                _, dst_port = self.validate_port(str(rule_data.get("dst_port", "ANY")), proto)
                _, action = self.validate_action(str(rule_data.get("action", "BLOCK")))

                self.rules[idx] = FirewallRule(
                    id=rule_id,
                    name=str(rule_data.get("name", r.name)).strip(),
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    protocol=proto,
                    src_port=src_port,
                    dst_port=dst_port,
                    action=action,
                    enabled=bool(rule_data.get("enabled", r.enabled)),
                )
                self.save_rules()
                return True, "Rule updated successfully."

        return False, f"Rule with ID {rule_id} not found."

    def delete_rule(self, rule_id: int) -> bool:
        """Delete a rule by ID."""
        orig_len = len(self.rules)
        self.rules = [r for r in self.rules if r.id != rule_id]
        if len(self.rules) < orig_len:
            self.save_rules()
            return True
        return False

    def toggle_rule(self, rule_id: int, enabled: Optional[bool] = None) -> bool:
        """Toggle or explicitly set enabled status for a rule."""
        for r in self.rules:
            if r.id == rule_id:
                if enabled is None:
                    r.enabled = not r.enabled
                else:
                    r.enabled = bool(enabled)
                self.save_rules()
                return True
        return False

    def move_rule_up(self, rule_id: int) -> bool:
        """Move a rule up in priority (decreases index)."""
        for i, r in enumerate(self.rules):
            if r.id == rule_id and i > 0:
                self.rules[i], self.rules[i - 1] = self.rules[i - 1], self.rules[i]
                self.save_rules()
                return True
        return False

    def move_rule_down(self, rule_id: int) -> bool:
        """Move a rule down in priority (increases index)."""
        for i, r in enumerate(self.rules):
            if r.id == rule_id and i < len(self.rules) - 1:
                self.rules[i], self.rules[i + 1] = self.rules[i + 1], self.rules[i]
                self.save_rules()
                return True
        return False

    @staticmethod
    def match_ip(rule_ip: str, packet_ip: str) -> bool:
        """
        Check if packet_ip matches rule_ip.
        Supports 'ANY', '*', single IPv4 address, or CIDR network.
        """
        r_clean = rule_ip.strip().upper()
        if r_clean in ("ANY", "*", ""):
            return True

        p_clean = packet_ip.strip()
        if not p_clean:
            return False

        try:
            pkt_addr = ipaddress.ip_address(p_clean)
            if "/" in r_clean:
                net = ipaddress.ip_network(r_clean, strict=False)
                return pkt_addr in net
            else:
                rule_addr = ipaddress.ip_address(r_clean)
                return pkt_addr == rule_addr
        except ValueError:
            # Fallback to string match
            return r_clean.lower() == p_clean.lower()

    @staticmethod
    def match_port(rule_port: str, packet_port: Optional[int]) -> bool:
        """
        Check if packet_port matches rule_port.
        Supports 'ANY', '*', or specific integer port.
        """
        r_clean = str(rule_port).strip().upper()
        if r_clean in ("ANY", "*", ""):
            return True

        if packet_port is None:
            # Non-port protocols (like ICMP) match wildcard rule ports
            return False

        try:
            return int(r_clean) == int(packet_port)
        except ValueError:
            return False

    @staticmethod
    def match_protocol(rule_proto: str, packet_proto: str) -> bool:
        """Check if packet_proto matches rule_proto."""
        r_clean = rule_proto.strip().upper()
        if r_clean in ("ANY", "*", ""):
            return True
        return r_clean == packet_proto.strip().upper()
