"""
Logger Module for Basic Packet-Filtering Firewall.

Maintains an audit trail of packet filtering decisions in 'firewall.log'
Format:
YYYY-MM-DD HH:MM:SS | Source IP | Dest IP | Protocol | Src Port | Dst Port | Decision | Matched rule
"""

import os
import threading
from datetime import datetime
from typing import List, Dict, Optional


class FirewallLogger:
    """Handles thread-safe logging and retrieval of packet filtering events."""

    def __init__(self, log_path: str = "firewall.log"):
        self.log_path = os.path.abspath(log_path)
        self._lock = threading.Lock()
        self._ensure_log_file()

    def _ensure_log_file(self) -> None:
        """Create the log file if it does not already exist."""
        with self._lock:
            if not os.path.exists(self.log_path):
                # Ensure directory exists
                parent_dir = os.path.dirname(self.log_path)
                if parent_dir and not os.path.exists(parent_dir):
                    os.makedirs(parent_dir, exist_ok=True)
                with open(self.log_path, "w", encoding="utf-8") as f:
                    # Optional header comment
                    f.write("# Firewall Activity Log\n")
                    f.write("# Format: Timestamp | Source IP | Dest IP | Protocol | Src Port | Dst Port | Decision | Matched Rule\n")

    def log_decision(
        self,
        src_ip: str,
        dst_ip: str,
        protocol: str,
        src_port: any,
        dst_port: any,
        decision: str,
        matched_rule_desc: str,
        timestamp: Optional[datetime] = None,
    ) -> str:
        """
        Record a packet inspection decision into firewall.log.

        Returns the formatted log line.
        """
        if timestamp is None:
            timestamp = datetime.now()

        time_str = timestamp.strftime("%Y-%m-%d %H:%M:%S")
        src_p = str(src_port) if src_port is not None and str(src_port) != "" else "ANY"
        dst_p = str(dst_port) if dst_port is not None and str(dst_port) != "" else "ANY"
        rule_desc = str(matched_rule_desc).strip()

        log_line = f"{time_str} | {src_ip} | {dst_ip} | {protocol.upper()} | {src_p} | {dst_p} | {decision.upper()} | {rule_desc}\n"

        with self._lock:
            try:
                with open(self.log_path, "a", encoding="utf-8") as f:
                    f.write(log_line)
            except Exception as e:
                print(f"[FirewallLogger Error] Failed to write to log file: {e}")

        return log_line.strip()

    def read_logs(
        self,
        max_lines: int = 1000,
        filter_decision: Optional[str] = None,
        search_keyword: Optional[str] = None,
    ) -> List[Dict[str, str]]:
        """
        Read and parse log entries from the firewall log file.
        Returns parsed log dictionaries in reverse chronological order (newest first).
        """
        if not os.path.exists(self.log_path):
            return []

        parsed_entries = []
        with self._lock:
            try:
                with open(self.log_path, "r", encoding="utf-8") as f:
                    lines = f.readlines()
            except Exception as e:
                print(f"[FirewallLogger Error] Failed to read log file: {e}")
                return []

        # Iterate in reverse to show newest first
        for line in reversed(lines):
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            parts = [p.strip() for p in line.split("|")]
            if len(parts) >= 8:
                entry = {
                    "timestamp": parts[0],
                    "src_ip": parts[1],
                    "dst_ip": parts[2],
                    "protocol": parts[3],
                    "src_port": parts[4],
                    "dst_port": parts[5],
                    "decision": parts[6],
                    "matched_rule": "|".join(parts[7:]).strip(),
                    "raw": line,
                }

                # Apply decision filter if requested
                if filter_decision and filter_decision.upper() != "ALL":
                    if entry["decision"].upper() != filter_decision.upper():
                        continue

                # Apply keyword search
                if search_keyword:
                    kw = search_keyword.lower()
                    if kw not in line.lower():
                        continue

                parsed_entries.append(entry)
                if len(parsed_entries) >= max_lines:
                    break

        return parsed_entries

    def clear_logs(self) -> bool:
        """Clear all entries in firewall.log while preserving the header."""
        with self._lock:
            try:
                with open(self.log_path, "w", encoding="utf-8") as f:
                    f.write("# Firewall Activity Log\n")
                    f.write("# Format: Timestamp | Source IP | Dest IP | Protocol | Src Port | Dst Port | Decision | Matched Rule\n")
                return True
            except Exception as e:
                print(f"[FirewallLogger Error] Failed to clear log file: {e}")
                return False

    def export_logs(self, target_filepath: str) -> bool:
        """Export current log content to another file path."""
        with self._lock:
            try:
                with open(self.log_path, "r", encoding="utf-8") as src, open(
                    target_filepath, "w", encoding="utf-8"
                ) as dst:
                    dst.write(src.read())
                return True
            except Exception as e:
                print(f"[FirewallLogger Error] Failed to export log file: {e}")
                return False
