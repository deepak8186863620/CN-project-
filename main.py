"""
Basic Firewall Implementation using Python
Computer Networks Project - Main Entry Point

Launches the Tkinter GUI dashboard with packet filtering engine,
rule management, packet simulator, live capture, and audit logs.
"""

import os
import sys
import tkinter as tk
from tkinter import ttk, messagebox

# Reconfigure stdout/stderr encoding for Windows terminals if needed
if sys.stdout and hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# Ensure the parent directory is in sys.path so imports work regardless of launch location
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PARENT_DIR = os.path.dirname(CURRENT_DIR)
if CURRENT_DIR not in sys.path:
    sys.path.insert(0, CURRENT_DIR)
if PARENT_DIR not in sys.path:
    sys.path.insert(0, PARENT_DIR)

# Package alias support so both `from basic_firewall.core...` and root imports work
if "basic_firewall" not in sys.modules:
    try:
        import basic_firewall
    except ModuleNotFoundError:
        import types
        pkg = types.ModuleType("basic_firewall")
        pkg.__path__ = [CURRENT_DIR]
        sys.modules["basic_firewall"] = pkg

from basic_firewall.core.rule_manager import RuleManager
from basic_firewall.core.logger import FirewallLogger
from basic_firewall.core.firewall_engine import FirewallEngine
from basic_firewall.gui.dashboard import DashboardView
from basic_firewall.gui.rules_view import RulesView
from basic_firewall.gui.packet_simulator import PacketSimulatorView
from basic_firewall.gui.logs_view import LogsView
from basic_firewall.gui.live_capture_view import LiveCaptureView


class BasicFirewallApp(tk.Tk):
    """Main Application Window for Basic Firewall."""

    def __init__(self):
        super().__init__()

        self.title("Basic Firewall Implementation - Computer Networks Project")
        self.geometry("1060x720")
        self.minsize(940, 620)

        # Center on screen
        self._center_window()

        # Paths
        rules_path = os.path.join(CURRENT_DIR, "data", "rules.json")
        log_path = os.path.join(CURRENT_DIR, "firewall.log")

        # Initialize core components
        self.rule_manager = RuleManager(rules_file_path=rules_path)
        self.logger = FirewallLogger(log_path=log_path)
        self.engine = FirewallEngine(
            rule_manager=self.rule_manager,
            logger=self.logger,
            default_policy="BLOCK"
        )

        # Configure TTK Styles
        self._configure_styles()

        # Build Notebook Tabs
        self._build_tabs()

        # Build Status Bar
        self._build_status_bar()

        # Handle window close
        self.protocol("WM_DELETE_WINDOW", self._on_close)

    def _center_window(self) -> None:
        """Center the window on the primary display."""
        self.update_idletasks()
        w = 1060
        h = 720
        sw = self.winfo_screenwidth()
        sh = self.winfo_screenheight()
        x = max(0, (sw - w) // 2)
        y = max(0, (sh - h) // 2)
        self.geometry(f"{w}x{h}+{x}+{y}")

    def _configure_styles(self) -> None:
        """Apply modern font and widget styling."""
        style = ttk.Style(self)
        try:
            style.theme_use("clam")
        except Exception:
            pass

        # Global base style
        style.configure(".", font=("Segoe UI", 9))

        # Notebook tabs styling
        style.configure(
            "TNotebook.Tab",
            font=("Segoe UI", 10, "bold"),
            padding=[16, 8],
            background="#e2e8f0",
            foreground="#334155"
        )
        style.map(
            "TNotebook.Tab",
            background=[("selected", "#ffffff"), ("active", "#cbd5e1")],
            foreground=[("selected", "#1e40af"), ("active", "#0f172a")]
        )

        # Treeview styling
        style.configure(
            "Treeview.Heading",
            font=("Segoe UI", 9, "bold"),
            background="#f1f5f9",
            foreground="#1e293b",
            relief="flat"
        )
        style.configure("Treeview", rowheight=26, font=("Segoe UI", 9))
        style.map("Treeview", background=[("selected", "#dbeafe")], foreground=[("selected", "#1e40af")])

        # Buttons
        style.configure("TButton", font=("Segoe UI", 9), padding=5)

    def _build_tabs(self) -> None:
        """Initialize tabs and views."""
        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill="both", expand=True, padx=8, pady=(8, 0))

        # 1. Dashboard Tab
        self.view_dashboard = DashboardView(
            self.notebook,
            self.engine,
            on_navigate_rules=lambda: self.notebook.select(self.view_rules)
        )
        self.notebook.add(self.view_dashboard, text=" 📊 Dashboard ")

        # 2. Rule Management Tab
        self.view_rules = RulesView(
            self.notebook,
            self.rule_manager,
            on_rules_changed=self._on_rules_changed
        )
        self.notebook.add(self.view_rules, text=" 🛡️ Rule Management ")

        # 3. Packet Simulator Tab
        self.view_sim = PacketSimulatorView(self.notebook, self.engine)
        self.notebook.add(self.view_sim, text=" 🧪 Packet Simulator ")

        # 4. Live Capture Demonstration Tab
        self.view_capture = LiveCaptureView(self.notebook, self.engine)
        self.notebook.add(self.view_capture, text=" 📡 Live Capture / Demo ")

        # 5. Logs View Tab
        self.view_logs = LogsView(self.notebook, self.logger)
        self.notebook.add(self.view_logs, text=" 📜 Firewall Logs ")

        # Tab switch listener
        self.notebook.bind("<<NotebookTabChanged>>", self._on_tab_changed)

    def _build_status_bar(self) -> None:
        """Create bottom status footer."""
        self.status_bar = tk.Frame(self, bg="#f1f5f9", bd=1, relief="sunken", padx=10, pady=4)
        self.status_bar.pack(side="bottom", fill="x")

        self.lbl_status_engine = tk.Label(
            self.status_bar,
            text="Engine: RUNNING",
            font=("Segoe UI", 8, "bold"),
            bg="#f1f5f9",
            fg="#15803d"
        )
        self.lbl_status_engine.pack(side="left", padx=(0, 15))

        self.lbl_status_rules = tk.Label(
            self.status_bar,
            text=f"Active Rules: {len(self.rule_manager.get_active_rules())}",
            font=("Segoe UI", 8),
            bg="#f1f5f9",
            fg="#475569"
        )
        self.lbl_status_rules.pack(side="left", padx=(0, 15))

        self.lbl_status_policy = tk.Label(
            self.status_bar,
            text=f"Default Policy: {self.engine.default_policy}",
            font=("Segoe UI", 8),
            bg="#f1f5f9",
            fg="#475569"
        )
        self.lbl_status_policy.pack(side="left", padx=(0, 15))

        lbl_log_file = tk.Label(
            self.status_bar,
            text=f"Log: firewall.log",
            font=("Segoe UI", 8),
            bg="#f1f5f9",
            fg="#64748b"
        )
        lbl_log_file.pack(side="right")

    def _on_rules_changed(self) -> None:
        """Callback when rules are added, edited, toggled, or deleted."""
        self.view_dashboard.refresh()
        self.lbl_status_rules.config(text=f"Active Rules: {len(self.rule_manager.get_active_rules())}")

    def _on_tab_changed(self, event=None) -> None:
        """Refresh relevant view when switched to."""
        selected = self.notebook.select()
        if selected == str(self.view_dashboard):
            self.view_dashboard.refresh()
        elif selected == str(self.view_rules):
            self.view_rules.refresh()
        elif selected == str(self.view_logs):
            self.view_logs.refresh()

        # Update status bar
        state = "RUNNING" if self.engine.is_running else "STOPPED"
        color = "#15803d" if self.engine.is_running else "#d97706"
        self.lbl_status_engine.config(text=f"Engine: {state}", fg=color)
        self.lbl_status_rules.config(text=f"Active Rules: {len(self.rule_manager.get_active_rules())}")
        self.lbl_status_policy.config(text=f"Default Policy: {self.engine.default_policy}")

    def _on_close(self) -> None:
        """Clean shutdown handler."""
        # Stop live capture thread if running
        try:
            self.view_capture._stop_capture()
        except Exception:
            pass
        self.destroy()


def run_cli_demo() -> None:
    """Non-GUI demonstration mode for headless testing or quick terminal runs."""
    print("=" * 65)
    print(" BASIC FIREWALL IMPLEMENTATION - TERMINAL DEMONSTRATION")
    print("=" * 65)

    rules_path = os.path.join(CURRENT_DIR, "data", "rules.json")
    log_path = os.path.join(CURRENT_DIR, "firewall.log")

    mgr = RuleManager(rules_file_path=rules_path)
    logger = FirewallLogger(log_path=log_path)
    engine = FirewallEngine(rule_manager=mgr, logger=logger, default_policy="BLOCK")

    print(f"\n[+] Loaded {len(mgr.get_rules())} firewall rules from {rules_path}")
    for r in mgr.get_rules():
        status = "ENABLED" if r.enabled else "DISABLED"
        print(f"    - #{r.id} [{status}] {r.protocol} {r.src_ip} -> {r.dst_ip}:{r.dst_port} => {r.action} ({r.name})")

    demo_packets = [
        ("192.168.1.100", "93.184.216.34", "TCP", 54321, 80, "Web HTTP"),
        ("192.168.1.100", "142.250.190.46", "TCP", 54322, 443, "Web HTTPS"),
        ("192.168.1.10", "192.168.1.20", "TCP", 5000, 23, "Telnet Insecure"),
        ("192.168.1.100", "8.8.8.8", "UDP", 53535, 53, "DNS Request"),
        ("192.168.1.100", "8.8.8.8", "ICMP", None, None, "Ping Echo"),
        ("10.0.0.1", "10.0.0.2", "TCP", 1234, 8080, "Unknown Alternative Port"),
    ]

    print("\n[+] Evaluating Test Network Packets:")
    print("-" * 65)
    for src, dst, proto, s_p, d_p, info in demo_packets:
        from basic_firewall.core.packet_parser import PacketParser
        pkt = PacketParser.create_simulated_packet(src, dst, proto, s_p, d_p, info)
        res = engine.evaluate_packet(pkt)
        tag = "[ALLOWED]" if res.decision == "ALLOWED" else "[BLOCKED]"
        print(f"{tag:<10} | {proto:<4} {src}:{s_p or 'ANY'} -> {dst}:{d_p or 'ANY'} | {res.reason}")

    stats = engine.get_stats()
    print("-" * 65)
    print(f"Total: {stats['total_processed']} | Allowed: {stats['total_allowed']} ({stats['allow_percentage']}%) | Blocked: {stats['total_blocked']} ({stats['block_percentage']}%)")
    print(f"[+] Decisions logged to: {log_path}\n")


def main():
    if "--cli" in sys.argv or "--demo" in sys.argv:
        run_cli_demo()
        return

    # Start Tkinter GUI
    app = BasicFirewallApp()
    app.mainloop()


if __name__ == "__main__":
    main()
