"""
Automated Test for the Complete Final Viva Demonstration Walkthrough.
Verifies the exact 11-step sequence requested in the prompt:
1. Start the application / initialize engine.
2. Show dashboard status and initial state.
3. Show existing rules in priority order.
4. Create test packet for TCP port 443.
5. Verify decision is ALLOWED.
6. Create test packet for TCP port 23.
7. Verify decision is BLOCKED.
8. Open logs and verify both decisions recorded in order.
9. Delete or modify a rule (e.g., delete rule blocking port 23, or change its action).
10. Test the packet again and verify the changed result (now falls back to default policy or allowed).
11. Verify updated packet statistics.
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
from basic_firewall.core.packet_parser import PacketParser
from basic_firewall.core.firewall_engine import FirewallEngine


class TestVivaDemonstrationWalkthrough(unittest.TestCase):

    def setUp(self):
        self.tmp_rules = tempfile.NamedTemporaryFile(delete=False, suffix=".json")
        self.tmp_rules.close()
        self.tmp_log = tempfile.NamedTemporaryFile(delete=False, suffix=".log")
        self.tmp_log.close()

        self.rule_manager = RuleManager(rules_file_path=self.tmp_rules.name)
        self.rule_manager.reset_to_defaults()
        self.logger = FirewallLogger(log_path=self.tmp_log.name)
        self.engine = FirewallEngine(
            rule_manager=self.rule_manager,
            logger=self.logger,
            default_policy="BLOCK"
        )

    def tearDown(self):
        for path in [self.tmp_rules.name, self.tmp_log.name]:
            if os.path.exists(path):
                os.remove(path)

    def test_full_demonstration_scenario(self):
        # Step 1: Start engine
        self.assertTrue(self.engine.is_running)

        # Step 2: Dashboard metrics initially 0
        stats = self.engine.get_stats()
        self.assertEqual(stats["total_processed"], 0)
        self.assertEqual(stats["active_rules_count"], 5)

        # Step 3: Show existing rules
        rules = self.rule_manager.get_rules()
        self.assertEqual(len(rules), 5)
        # Verify port 443 rule exists and port 23 rule exists
        rule_443 = next(r for r in rules if r.dst_port == "443")
        rule_23 = next(r for r in rules if r.dst_port == "23")
        self.assertEqual(rule_443.action, "ALLOW")
        self.assertEqual(rule_23.action, "BLOCK")

        # Step 4: Create a test packet for TCP port 443
        pkt_https = PacketParser.create_simulated_packet(
            src_ip="192.168.1.100",
            dst_ip="142.250.190.46",
            protocol="TCP",
            src_port=52000,
            dst_port=443,
            info="HTTPS Test"
        )

        # Step 5: Show ALLOWED
        res_https = self.engine.evaluate_packet(pkt_https)
        self.assertEqual(res_https.decision, "ALLOWED")
        self.assertEqual(res_https.matched_rule_id, rule_443.id)

        # Step 6: Create a test packet for TCP port 23
        pkt_telnet = PacketParser.create_simulated_packet(
            src_ip="192.168.1.10",
            dst_ip="192.168.1.20",
            protocol="TCP",
            src_port=5000,
            dst_port=23,
            info="Telnet Test"
        )

        # Step 7: Show BLOCKED
        res_telnet = self.engine.evaluate_packet(pkt_telnet)
        self.assertEqual(res_telnet.decision, "BLOCKED")
        self.assertEqual(res_telnet.matched_rule_id, rule_23.id)

        # Step 8: Open logs and show both decisions
        logs = self.logger.read_logs()
        self.assertEqual(len(logs), 2)
        # Note: read_logs returns newest first
        self.assertEqual(logs[0]["decision"], "BLOCKED")  # Telnet was 2nd
        self.assertEqual(logs[1]["decision"], "ALLOWED")  # HTTPS was 1st

        # Step 9: Delete or modify a rule (e.g. modify Rule 3 to ALLOW or delete it)
        # Let's delete the rule blocking port 23
        self.rule_manager.delete_rule(rule_23.id)
        # And set default policy to ALLOW for this test to show the changed result
        self.engine.set_default_policy("ALLOW")

        # Step 10: Test the packet again and show the changed result
        res_telnet_again = self.engine.evaluate_packet(pkt_telnet)
        self.assertEqual(res_telnet_again.decision, "ALLOWED")
        self.assertEqual(res_telnet_again.applied_policy, "DEFAULT_POLICY")

        # Step 11: Show packet statistics
        final_stats = self.engine.get_stats()
        self.assertEqual(final_stats["total_processed"], 3)
        self.assertEqual(final_stats["total_allowed"], 2)
        self.assertEqual(final_stats["total_blocked"], 1)
        self.assertAlmostEqual(final_stats["allow_percentage"], 66.7, places=1)
        self.assertAlmostEqual(final_stats["block_percentage"], 33.3, places=1)


if __name__ == "__main__":
    unittest.main()
