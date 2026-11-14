"""
Automated Unit Tests for Firewall Engine.
Covers the 10 core requirements:
1. TCP port 80 -> ALLOW
2. TCP port 443 -> ALLOW
3. TCP port 23 -> BLOCK
4. UDP port 53 -> ALLOW
5. ICMP -> BLOCK
6. Unknown packet -> default policy
7. Wildcard IP matching
8. Invalid rule input handling
9. Rule ordering (first matching rule wins)
10. Logging verification
"""

import os
import sys
import tempfile
import types
import unittest

_TEST_DIR = os.path.dirname(os.path.abspath(__file__))
_PROJECT_ROOT = os.path.dirname(_TEST_DIR)
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

if "basic_firewall" not in sys.modules:
    try:
        import basic_firewall
    except ModuleNotFoundError:
        pkg = types.ModuleType("basic_firewall")
        pkg.__path__ = [_PROJECT_ROOT]
        sys.modules["basic_firewall"] = pkg

from basic_firewall.core.rule_manager import RuleManager
from basic_firewall.core.logger import FirewallLogger
from basic_firewall.core.packet_parser import PacketParser, PacketData
from basic_firewall.core.firewall_engine import FirewallEngine


class TestFirewallEngine(unittest.TestCase):

    def setUp(self):
        # Create temporary rules and log files
        self.temp_rules_file = tempfile.NamedTemporaryFile(delete=False, suffix=".json")
        self.temp_rules_file.close()

        self.temp_log_file = tempfile.NamedTemporaryFile(delete=False, suffix=".log")
        self.temp_log_file.close()

        self.rule_manager = RuleManager(rules_file_path=self.temp_rules_file.name)
        # Reset to standard 5 default rules
        self.rule_manager.reset_to_defaults()

        self.logger = FirewallLogger(log_path=self.temp_log_file.name)
        self.engine = FirewallEngine(
            rule_manager=self.rule_manager,
            logger=self.logger,
            default_policy="BLOCK"
        )

    def tearDown(self):
        for path in [self.temp_rules_file.name, self.temp_log_file.name]:
            if os.path.exists(path):
                os.remove(path)

    def test_01_tcp_port_80_allow(self):
        """Test Case 1: TCP port 80 (HTTP) -> ALLOW"""
        pkt = PacketParser.create_simulated_packet(
            src_ip="192.168.1.100",
            dst_ip="93.184.216.34",
            protocol="TCP",
            src_port=52345,
            dst_port=80,
            info="HTTP GET /"
        )
        res = self.engine.evaluate_packet(pkt)
        self.assertEqual(res.decision, "ALLOWED")
        self.assertIn("80", res.reason)

    def test_02_tcp_port_443_allow(self):
        """Test Case 2: TCP port 443 (HTTPS) -> ALLOW"""
        pkt = PacketParser.create_simulated_packet(
            src_ip="192.168.1.100",
            dst_ip="142.250.190.46",
            protocol="TCP",
            src_port=52346,
            dst_port=443,
            info="TLS Client Hello"
        )
        res = self.engine.evaluate_packet(pkt)
        self.assertEqual(res.decision, "ALLOWED")
        self.assertIn("443", res.reason)

    def test_03_tcp_port_23_block(self):
        """Test Case 3: TCP port 23 (Telnet) -> BLOCK"""
        pkt = PacketParser.create_simulated_packet(
            src_ip="192.168.1.10",
            dst_ip="192.168.1.20",
            protocol="TCP",
            src_port=5000,
            dst_port=23,
            info="Insecure Telnet Connection Request"
        )
        res = self.engine.evaluate_packet(pkt)
        self.assertEqual(res.decision, "BLOCKED")
        self.assertIn("23", res.reason)

    def test_04_udp_port_53_allow(self):
        """Test Case 4: UDP port 53 (DNS) -> ALLOW"""
        pkt = PacketParser.create_simulated_packet(
            src_ip="192.168.1.100",
            dst_ip="8.8.8.8",
            protocol="UDP",
            src_port=53535,
            dst_port=53,
            info="Standard DNS query A google.com"
        )
        res = self.engine.evaluate_packet(pkt)
        self.assertEqual(res.decision, "ALLOWED")
        self.assertIn("53", res.reason)

    def test_05_icmp_block(self):
        """Test Case 5: ICMP (Ping) -> BLOCK"""
        pkt = PacketParser.create_simulated_packet(
            src_ip="192.168.1.100",
            dst_ip="8.8.8.8",
            protocol="ICMP",
            info="Echo Request (Ping)"
        )
        res = self.engine.evaluate_packet(pkt)
        self.assertEqual(res.decision, "BLOCKED")
        self.assertIn("ICMP", res.reason)

    def test_06_unknown_packet_default_policy(self):
        """Test Case 6: Unknown traffic (e.g. TCP port 8088) -> Default Policy (BLOCK / ALLOW)"""
        # Testing default policy = BLOCK
        self.engine.set_default_policy("BLOCK")
        pkt = PacketParser.create_simulated_packet(
            src_ip="10.0.0.5",
            dst_ip="10.0.0.10",
            protocol="TCP",
            src_port=44444,
            dst_port=8088
        )
        res = self.engine.evaluate_packet(pkt)
        self.assertEqual(res.decision, "BLOCKED")
        self.assertEqual(res.applied_policy, "DEFAULT_POLICY")

        # Now test configuring default policy to ALLOW
        self.engine.set_default_policy("ALLOW")
        res2 = self.engine.evaluate_packet(pkt)
        self.assertEqual(res2.decision, "ALLOWED")
        self.assertEqual(res2.applied_policy, "DEFAULT_POLICY")

    def test_07_wildcard_ip_matching(self):
        """Test Case 7: Wildcard IP matching with ANY and CIDR"""
        # Add a specific subnet rule: Allow all TCP traffic from 192.168.50.0/24 to any port
        ok, _, rule = self.rule_manager.add_rule({
            "name": "Subnet Internal Trust",
            "src_ip": "192.168.50.0/24",
            "dst_ip": "ANY",
            "protocol": "TCP",
            "src_port": "ANY",
            "dst_port": "ANY",
            "action": "ALLOW",
            "enabled": True
        })
        self.assertTrue(ok)
        # Move rule to top priority
        self.rule_manager.move_rule_up(rule.id)
        while self.rule_manager.get_rules()[0].id != rule.id:
            self.rule_manager.move_rule_up(rule.id)

        # Packet within subnet: 192.168.50.15 -> should MATCH and ALLOW
        pkt_in = PacketParser.create_simulated_packet(
            src_ip="192.168.50.15",
            dst_ip="10.0.0.1",
            protocol="TCP",
            src_port=1234,
            dst_port=9999
        )
        res_in = self.engine.evaluate_packet(pkt_in)
        self.assertEqual(res_in.decision, "ALLOWED")
        self.assertEqual(res_in.matched_rule_id, rule.id)

        # Packet outside subnet: 192.168.51.15 -> should NOT match this rule
        pkt_out = PacketParser.create_simulated_packet(
            src_ip="192.168.51.15",
            dst_ip="10.0.0.1",
            protocol="TCP",
            src_port=1234,
            dst_port=9999
        )
        self.engine.set_default_policy("BLOCK")
        res_out = self.engine.evaluate_packet(pkt_out)
        self.assertEqual(res_out.decision, "BLOCKED")
        self.assertNotEqual(res_out.matched_rule_id, rule.id)

    def test_08_invalid_rule_input(self):
        """Test Case 8: Invalid rule input validation prevents malformed rules"""
        # Invalid IP
        ok, msg, _ = self.rule_manager.add_rule({
            "name": "Bad Rule",
            "src_ip": "300.400.500.600",
            "dst_ip": "ANY",
            "protocol": "TCP",
            "src_port": "ANY",
            "dst_port": "80",
            "action": "ALLOW"
        })
        self.assertFalse(ok)
        self.assertIn("Invalid IP", msg)

        # Invalid Port
        ok, msg, _ = self.rule_manager.add_rule({
            "name": "Bad Port",
            "src_ip": "ANY",
            "dst_ip": "ANY",
            "protocol": "TCP",
            "src_port": "ANY",
            "dst_port": "99999",
            "action": "ALLOW"
        })
        self.assertFalse(ok)
        self.assertIn("Port must be between 0 and 65535", msg)

        # Invalid Action
        ok, msg, _ = self.rule_manager.add_rule({
            "name": "Bad Action",
            "src_ip": "ANY",
            "dst_ip": "ANY",
            "protocol": "TCP",
            "src_port": "ANY",
            "dst_port": "80",
            "action": "INVALID_ACTION"
        })
        self.assertFalse(ok)

    def test_09_rule_ordering_first_match_wins(self):
        """Test Case 9: Rule ordering (First matching rule wins)"""
        # Clear rules and insert two conflicting rules for TCP :8080:
        # Rule A: ALLOW TCP :8080
        # Rule B: BLOCK TCP :8080
        self.rule_manager.rules = []
        ok1, _, rule_allow = self.rule_manager.add_rule({
            "name": "Allow 8080 First",
            "src_ip": "ANY",
            "dst_ip": "ANY",
            "protocol": "TCP",
            "src_port": "ANY",
            "dst_port": "8080",
            "action": "ALLOW",
            "enabled": True
        })
        ok2, _, rule_block = self.rule_manager.add_rule({
            "name": "Block 8080 Second",
            "src_ip": "ANY",
            "dst_ip": "ANY",
            "protocol": "TCP",
            "src_port": "ANY",
            "dst_port": "8080",
            "action": "BLOCK",
            "enabled": True
        })

        pkt = PacketParser.create_simulated_packet(
            src_ip="1.1.1.1", dst_ip="2.2.2.2", protocol="TCP", src_port=5000, dst_port=8080
        )

        # With ALLOW on top, decision should be ALLOWED
        res1 = self.engine.evaluate_packet(pkt)
        self.assertEqual(res1.decision, "ALLOWED")
        self.assertEqual(res1.matched_rule_id, rule_allow.id)

        # Now swap order (move BLOCK up above ALLOW)
        self.rule_manager.move_rule_up(rule_block.id)

        # Now with BLOCK on top, decision should be BLOCKED
        res2 = self.engine.evaluate_packet(pkt)
        self.assertEqual(res2.decision, "BLOCKED")
        self.assertEqual(res2.matched_rule_id, rule_block.id)

    def test_10_logging_verification(self):
        """Test Case 10: Logging correctly writes to file and parses back"""
        self.logger.clear_logs()
        pkt = PacketParser.create_simulated_packet(
            src_ip="192.168.1.10",
            dst_ip="192.168.1.20",
            protocol="TCP",
            src_port=5000,
            dst_port=23
        )
        self.engine.evaluate_packet(pkt)

        # Read logs back
        entries = self.logger.read_logs()
        self.assertEqual(len(entries), 1)
        entry = entries[0]
        self.assertEqual(entry["src_ip"], "192.168.1.10")
        self.assertEqual(entry["dst_ip"], "192.168.1.20")
        self.assertEqual(entry["protocol"], "TCP")
        self.assertEqual(entry["src_port"], "5000")
        self.assertEqual(entry["dst_port"], "23")
        self.assertEqual(entry["decision"], "BLOCKED")
        self.assertIn("Rule 3", entry["matched_rule"])

    def test_statistics_tracking(self):
        """Verify packet statistics (total, allowed, blocked, percentages)."""
        self.engine.reset_stats()
        # Process 1 allowed (port 80)
        pkt_allow = PacketParser.create_simulated_packet(
            src_ip="1.1.1.1", dst_ip="2.2.2.2", protocol="TCP", src_port=1000, dst_port=80
        )
        self.engine.evaluate_packet(pkt_allow)

        # Process 3 blocked (port 23)
        pkt_block = PacketParser.create_simulated_packet(
            src_ip="1.1.1.1", dst_ip="2.2.2.2", protocol="TCP", src_port=1000, dst_port=23
        )
        self.engine.evaluate_packet(pkt_block)
        self.engine.evaluate_packet(pkt_block)
        self.engine.evaluate_packet(pkt_block)

        stats = self.engine.get_stats()
        self.assertEqual(stats["total_processed"], 4)
        self.assertEqual(stats["total_allowed"], 1)
        self.assertEqual(stats["total_blocked"], 3)
        self.assertEqual(stats["allow_percentage"], 25.0)
        self.assertEqual(stats["block_percentage"], 75.0)


if __name__ == "__main__":
    unittest.main()
