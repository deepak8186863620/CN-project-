"""
Firewall Engine Module for Basic Packet-Filtering Firewall.

Implements the core decision engine:
- Evaluates packets sequentially against ordered rules (First Match Wins)
- Applies configurable default policy (BLOCK/ALLOW) when no rule matches
- Maintains live statistics (processed, allowed, blocked, percentages)
- Dispatches evaluation results to logger and UI callbacks
"""

from dataclasses import dataclass
from datetime import datetime
from typing import Optional, Callable, List, Dict, Any

from .packet_parser import PacketData
from .rule_manager import RuleManager, FirewallRule
from .logger import FirewallLogger


@dataclass
class EvaluationResult:
    """Encapsulates the firewall's decision and rationale for a given packet."""
    decision: str  # "ALLOWED" or "BLOCKED"
    packet: PacketData
    matched_rule: Optional[FirewallRule]
    matched_rule_id: Optional[int]
    matched_rule_name: str
    reason: str
    applied_policy: str  # "RULE", "DEFAULT_POLICY", or "BYPASS"
    timestamp: datetime


class FirewallEngine:
    """
    Core Packet-Filtering Firewall Engine.
    Executes rule matching, state management, statistics tracking, and logging.
    """

    def __init__(
        self,
        rule_manager: Optional[RuleManager] = None,
        logger: Optional[FirewallLogger] = None,
        default_policy: str = "BLOCK"
    ):
        self.rule_manager = rule_manager or RuleManager()
        self.logger = logger or FirewallLogger()
        self.default_policy = default_policy.upper() if default_policy.upper() in ("ALLOW", "BLOCK") else "BLOCK"
        self.is_running = True  # Status: RUNNING by default

        # Statistics
        self.packets_processed = 0
        self.packets_allowed = 0
        self.packets_blocked = 0

        # Optional listener callbacks: fn(EvaluationResult)
        self._callbacks: List[Callable[[EvaluationResult], None]] = []

    def register_callback(self, callback: Callable[[EvaluationResult], None]) -> None:
        """Register a GUI or listener callback triggered after each packet evaluation."""
        if callback not in self._callbacks:
            self._callbacks.append(callback)

    def unregister_callback(self, callback: Callable[[EvaluationResult], None]) -> None:
        """Remove a previously registered callback."""
        if callback in self._callbacks:
            self._callbacks.remove(callback)

    def set_running(self, running: bool) -> None:
        """Toggle firewall active status (RUNNING or STOPPED)."""
        self.is_running = running

    def set_default_policy(self, policy: str) -> None:
        """Set fallback policy when no rules match (ALLOW or BLOCK)."""
        clean = policy.strip().upper()
        if clean in ("ALLOW", "BLOCK"):
            self.default_policy = clean

    def reset_stats(self) -> None:
        """Reset traffic counters to zero."""
        self.packets_processed = 0
        self.packets_allowed = 0
        self.packets_blocked = 0

    def get_stats(self) -> Dict[str, Any]:
        """Return a dictionary of real-time firewall performance metrics."""
        total = self.packets_processed
        allow_pct = (self.packets_allowed / total * 100.0) if total > 0 else 0.0
        block_pct = (self.packets_blocked / total * 100.0) if total > 0 else 0.0

        return {
            "is_running": self.is_running,
            "status_text": "RUNNING" if self.is_running else "STOPPED",
            "default_policy": self.default_policy,
            "total_processed": total,
            "total_allowed": self.packets_allowed,
            "total_blocked": self.packets_blocked,
            "allow_percentage": round(allow_pct, 1),
            "block_percentage": round(block_pct, 1),
            "active_rules_count": len(self.rule_manager.get_active_rules()),
            "total_rules_count": len(self.rule_manager.get_rules()),
        }

    def evaluate_packet(self, packet: PacketData) -> EvaluationResult:
        """
        Evaluate a single packet through the firewall inspection engine.

        Matching Sequence (First Match Wins):
        1. If firewall is STOPPED, traffic is bypassed (ALLOWED).
        2. Iterate over enabled rules in order:
           a. Protocol match
           b. Source IP match
           c. Destination IP match
           d. Source Port match
           e. Destination Port match
           If ALL match -> Rule action taken, evaluation terminates.
        3. If no rules match -> Fallback to default_policy.
        4. Record decision to log file and notify listeners.
        """
        now = datetime.now()

        # Step 1: Check if firewall is STOPPED
        if not self.is_running:
            decision = "ALLOWED"
            reason = "Firewall is STOPPED. Packet bypassed without filtering."
            rule_id = None
            rule_name = "Bypass (Firewall Stopped)"
            applied_policy = "BYPASS"
            matched_rule = None

            result = EvaluationResult(
                decision=decision,
                packet=packet,
                matched_rule=matched_rule,
                matched_rule_id=rule_id,
                matched_rule_name=rule_name,
                reason=reason,
                applied_policy=applied_policy,
                timestamp=now,
            )
            self._record_result(result)
            return result

        # Step 2: Iterate through active rules in priority order
        active_rules = self.rule_manager.get_active_rules()
        matched_rule: Optional[FirewallRule] = None

        for rule in active_rules:
            # Check Protocol
            if not RuleManager.match_protocol(rule.protocol, packet.protocol):
                continue

            # Check Source IP
            if not RuleManager.match_ip(rule.src_ip, packet.src_ip):
                continue

            # Check Destination IP
            if not RuleManager.match_ip(rule.dst_ip, packet.dst_ip):
                continue

            # Check Ports (only applicable if transport protocol has ports)
            if packet.protocol in ("TCP", "UDP"):
                # Source port
                if not RuleManager.match_port(rule.src_port, packet.src_port):
                    continue
                # Destination port
                if not RuleManager.match_port(rule.dst_port, packet.dst_port):
                    continue
            elif packet.protocol == "ICMP":
                # For ICMP, port fields in rules are ignored unless explicitly set to non-ANY
                if rule.dst_port not in ("ANY", "*") and rule.dst_port != "":
                    continue

            # Found first match!
            matched_rule = rule
            break

        # Step 3: Determine decision
        raw_action = matched_rule.action.upper() if matched_rule else self.default_policy.upper()
        decision = "ALLOWED" if raw_action in ("ALLOW", "ALLOWED") else "BLOCKED"

        if matched_rule is not None:
            rule_id = matched_rule.id
            rule_name = matched_rule.name
            applied_policy = "RULE"
            reason = f"Matched Rule #{matched_rule.id} [{matched_rule.name}]: {matched_rule.protocol} {matched_rule.src_ip} -> {matched_rule.dst_ip}:{matched_rule.dst_port} => {matched_rule.action}"
        else:
            rule_id = None
            rule_name = f"Default Policy ({self.default_policy})"
            applied_policy = "DEFAULT_POLICY"
            reason = f"No rule matched packet criteria. Applied default policy: {self.default_policy} ({decision})"

        result = EvaluationResult(
            decision=decision,
            packet=packet,
            matched_rule=matched_rule,
            matched_rule_id=rule_id,
            matched_rule_name=rule_name,
            reason=reason,
            applied_policy=applied_policy,
            timestamp=now,
        )

        # Step 4: Record, update stats, and notify callbacks
        self._record_result(result)
        return result

    def _record_result(self, result: EvaluationResult) -> None:
        """Internal helper to update stats, write to log file, and trigger callbacks."""
        self.packets_processed += 1
        if result.decision == "ALLOWED":
            self.packets_allowed += 1
        else:
            self.packets_blocked += 1

        # Format matched rule description for logger
        if result.matched_rule is not None:
            rule_log = f"Rule {result.matched_rule.id}: {result.matched_rule.name}"
        elif result.applied_policy == "BYPASS":
            rule_log = "Bypass (Firewall Stopped)"
        else:
            rule_log = f"Default Policy ({self.default_policy})"

        # Write to firewall.log
        self.logger.log_decision(
            src_ip=result.packet.src_ip,
            dst_ip=result.packet.dst_ip,
            protocol=result.packet.protocol,
            src_port=result.packet.src_port,
            dst_port=result.packet.dst_port,
            decision=result.decision,
            matched_rule_desc=rule_log,
            timestamp=result.timestamp,
        )

        # Notify any subscribed listeners (e.g. GUI updates)
        for cb in self._callbacks:
            try:
                cb(result)
            except Exception as e:
                print(f"[FirewallEngine Callback Error]: {e}")
