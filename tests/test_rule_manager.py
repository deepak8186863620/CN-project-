"""
Unit Tests for RuleManager and Rule Validation.
"""

import os
import sys
import json
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

from basic_firewall.core.rule_manager import RuleManager, FirewallRule


class TestRuleManager(unittest.TestCase):

    def setUp(self):
        self.temp_file = tempfile.NamedTemporaryFile(delete=False, suffix=".json")
        self.temp_file.close()
        self.manager = RuleManager(rules_file_path=self.temp_file.name)

    def tearDown(self):
        if os.path.exists(self.temp_file.name):
            os.remove(self.temp_file.name)

    def test_default_rules_loaded(self):
        """Verify default educational rules are initialized."""
        rules = self.manager.get_rules()
        self.assertGreaterEqual(len(rules), 5)
        # Check that port 80 rule exists
        has_80 = any(r.dst_port == "80" and r.action == "ALLOW" for r in rules)
        self.assertTrue(has_80, "Default rules must include Allow TCP port 80")

    def test_validate_ip(self):
        """Test IP validation with single IP, CIDR subnet, wildcards, and invalid IPs."""
        # Valid
        ok, _ = RuleManager.validate_ip("ANY")
        self.assertTrue(ok)
        ok, _ = RuleManager.validate_ip("*")
        self.assertTrue(ok)
        ok, val = RuleManager.validate_ip("192.168.1.1")
        self.assertTrue(ok)
        self.assertEqual(val, "192.168.1.1")
        ok, val = RuleManager.validate_ip("10.0.0.0/24")
        self.assertTrue(ok)
        self.assertEqual(val, "10.0.0.0/24")

        # Invalid
        ok, _ = RuleManager.validate_ip("999.999.999.999")
        self.assertFalse(ok)
        ok, _ = RuleManager.validate_ip("not_an_ip")
        self.assertFalse(ok)
        ok, _ = RuleManager.validate_ip("192.168.1.1/40")
        self.assertFalse(ok)

    def test_validate_port(self):
        """Test port validation for valid ranges, wildcards, and out-of-bounds numbers."""
        ok, _ = RuleManager.validate_port("ANY", "TCP")
        self.assertTrue(ok)
        ok, val = RuleManager.validate_port("80", "TCP")
        self.assertTrue(ok)
        self.assertEqual(val, "80")
        ok, val = RuleManager.validate_port("65535", "UDP")
        self.assertTrue(ok)

        # ICMP always allows port to be ANY
        ok, val = RuleManager.validate_port("99999", "ICMP")
        self.assertTrue(ok)
        self.assertEqual(val, "ANY")

        # Invalid
        ok, _ = RuleManager.validate_port("70000", "TCP")
        self.assertFalse(ok)
        ok, _ = RuleManager.validate_port("-5", "UDP")
        self.assertFalse(ok)
        ok, _ = RuleManager.validate_port("abc", "TCP")
        self.assertFalse(ok)

    def test_validate_protocol_and_action(self):
        """Test protocol and action validation."""
        self.assertTrue(RuleManager.validate_protocol("TCP")[0])
        self.assertTrue(RuleManager.validate_protocol("udp")[0])
        self.assertTrue(RuleManager.validate_protocol("ICMP")[0])
        self.assertTrue(RuleManager.validate_protocol("ANY")[0])
        self.assertFalse(RuleManager.validate_protocol("HTTP")[0])

        self.assertTrue(RuleManager.validate_action("ALLOW")[0])
        self.assertTrue(RuleManager.validate_action("block")[0])
        self.assertFalse(RuleManager.validate_action("DROP")[0])

    def test_add_and_delete_rule(self):
        """Test adding a custom rule and deleting it."""
        rule_data = {
            "name": "Custom SSH Allow",
            "src_ip": "10.0.0.1",
            "dst_ip": "10.0.0.2",
            "protocol": "TCP",
            "src_port": "ANY",
            "dst_port": "22",
            "action": "ALLOW",
            "enabled": True
        }
        ok, msg, rule = self.manager.add_rule(rule_data)
        self.assertTrue(ok, msg)
        self.assertIsNotNone(rule)
        new_id = rule.id

        # Verify rule is in list
        rules = self.manager.get_rules()
        self.assertTrue(any(r.id == new_id for r in rules))

        # Delete rule
        deleted = self.manager.delete_rule(new_id)
        self.assertTrue(deleted)
        self.assertFalse(any(r.id == new_id for r in self.manager.get_rules()))

    def test_toggle_rule(self):
        """Test enabling and disabling a rule."""
        first_rule = self.manager.get_rules()[0]
        original_state = first_rule.enabled

        # Toggle
        self.manager.toggle_rule(first_rule.id)
        updated = next(r for r in self.manager.get_rules() if r.id == first_rule.id)
        self.assertEqual(updated.enabled, not original_state)

        # Toggle back explicitly
        self.manager.toggle_rule(first_rule.id, enabled=True)
        updated = next(r for r in self.manager.get_rules() if r.id == first_rule.id)
        self.assertTrue(updated.enabled)

    def test_rule_reordering(self):
        """Test moving rules up and down to change matching priority."""
        rules = self.manager.get_rules()
        first_id = rules[0].id
        second_id = rules[1].id

        # Move second rule UP
        moved = self.manager.move_rule_up(second_id)
        self.assertTrue(moved)
        new_rules = self.manager.get_rules()
        self.assertEqual(new_rules[0].id, second_id)
        self.assertEqual(new_rules[1].id, first_id)

        # Move it back DOWN
        moved = self.manager.move_rule_down(second_id)
        self.assertTrue(moved)
        new_rules = self.manager.get_rules()
        self.assertEqual(new_rules[0].id, first_id)
        self.assertEqual(new_rules[1].id, second_id)

    def test_persistence_and_corrupted_json_recovery(self):
        """Verify rules persist across instances and recover from corrupted JSON."""
        # Add a unique rule
        self.manager.add_rule({
            "name": "Persistence Test Rule",
            "src_ip": "1.2.3.4",
            "dst_ip": "5.6.7.8",
            "protocol": "UDP",
            "src_port": "ANY",
            "dst_port": "1234",
            "action": "ALLOW",
            "enabled": True
        })

        # New manager instance pointing to the same file
        manager2 = RuleManager(rules_file_path=self.temp_file.name)
        self.assertTrue(any(r.name == "Persistence Test Rule" for r in manager2.get_rules()))

        # Write corrupted JSON to the file
        with open(self.temp_file.name, "w", encoding="utf-8") as f:
            f.write("{ corrupt json file without closing bracket ...")

        # Manager should not crash, but recover to default rules
        manager3 = RuleManager(rules_file_path=self.temp_file.name)
        self.assertGreaterEqual(len(manager3.get_rules()), 5)

    def test_ip_matching_wildcard_exact_and_cidr(self):
        """Test RuleManager.match_ip with ANY, exact match, and CIDR subnet."""
        # ANY wildcard
        self.assertTrue(RuleManager.match_ip("ANY", "192.168.1.100"))
        self.assertTrue(RuleManager.match_ip("*", "10.0.0.1"))

        # Exact match
        self.assertTrue(RuleManager.match_ip("192.168.1.50", "192.168.1.50"))
        self.assertFalse(RuleManager.match_ip("192.168.1.50", "192.168.1.51"))

        # CIDR Subnet match
        self.assertTrue(RuleManager.match_ip("192.168.1.0/24", "192.168.1.45"))
        self.assertTrue(RuleManager.match_ip("192.168.1.0/24", "192.168.1.254"))
        self.assertFalse(RuleManager.match_ip("192.168.1.0/24", "192.168.2.1"))
        self.assertFalse(RuleManager.match_ip("10.0.0.0/8", "172.16.0.1"))


if __name__ == "__main__":
    unittest.main()
