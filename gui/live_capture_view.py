"""
Live Capture View for Basic Packet-Filtering Firewall.

Demonstrates packet inspection using Scapy where available.
Features:
- Live packet capture thread using Scapy's sniff()
- Graceful detection of privileges / Npcap on Windows
- Live Synthetic Stream Generator fallback (ensures flawless college demo without admin privileges)
- Live packet table showing header extraction and firewall decisions
"""

import time
import random
import threading
import tkinter as tk
from tkinter import ttk, messagebox
from typing import Optional

from basic_firewall.core.packet_parser import PacketParser, PacketData, SCAPY_AVAILABLE
from basic_firewall.core.firewall_engine import FirewallEngine, EvaluationResult

# Try importing sniff
try:
    from scapy.all import sniff, conf
    SNIFF_AVAILABLE = True
except Exception:
    SNIFF_AVAILABLE = False


class LiveCaptureView(ttk.Frame):
    """Network packet capture and live demonstration interface."""

    def __init__(self, parent: tk.Widget, engine: FirewallEngine):
        super().__init__(parent)
        self.engine = engine
        self._is_capturing = False
        self._capture_thread: Optional[threading.Thread] = None

        self._build_ui()

    def _build_ui(self) -> None:
        """Construct capture controls, information banner, and packet table."""
        self.columnconfigure(0, weight=1)
        self.rowconfigure(2, weight=1)

        # -------------------------------------------------------------
        # 1. EDUCATIONAL PRIVILEGE / STATUS BANNER
        # -------------------------------------------------------------
        banner = tk.Frame(self, bg="#f8fafc", bd=1, relief="groove", padx=12, pady=10)
        banner.grid(row=0, column=0, sticky="ew", padx=15, pady=(10, 6))

        tk.Label(
            banner,
            text="📡 PACKET CAPTURE & INSPECTION DEMONSTRATION",
            font=("Segoe UI", 10, "bold"),
            bg="#f8fafc",
            fg="#1e293b"
        ).pack(anchor="w")

        info_text = (
            "• Live Network Card sniffing uses Scapy to read packets in real-time.\n"
            "• Windows Note: Direct network card capture requires Administrator rights and Npcap.\n"
            "• Lab / No-Admin Note: The 'Live Traffic Generator' simulates continuous real-world traffic "
            "for demonstration without needing elevated privileges."
        )
        tk.Label(
            banner,
            text=info_text,
            font=("Segoe UI", 8),
            bg="#f8fafc",
            fg="#475569",
            justify="left"
        ).pack(anchor="w", pady=(4, 0))

        # -------------------------------------------------------------
        # 2. CONTROLS STRIP
        # -------------------------------------------------------------
        ctrl_frame = ttk.LabelFrame(self, text="Capture Mode & Controls", padding=10)
        ctrl_frame.grid(row=1, column=0, sticky="ew", padx=15, pady=6)
        ctrl_frame.columnconfigure(3, weight=1)

        ttk.Label(ctrl_frame, text="Capture Source:").grid(row=0, column=0, sticky="w", padx=(0, 6))
        self.combo_source = ttk.Combobox(
            ctrl_frame,
            values=["Live Synthetic Stream Generator (No Admin Needed)", "Live Network Card Sniffer (Scapy / Admin)"],
            state="readonly",
            width=48
        )
        self.combo_source.set("Live Synthetic Stream Generator (No Admin Needed)")
        self.combo_source.grid(row=0, column=1, sticky="w", padx=(0, 15))

        self.btn_start_stop = tk.Button(
            ctrl_frame,
            text="▶ Start Live Capture",
            command=self._toggle_capture,
            font=("Segoe UI", 9, "bold"),
            bg="#16a34a",
            fg="#ffffff",
            activebackground="#15803d",
            activeforeground="#ffffff",
            relief="flat",
            padx=12,
            pady=4,
            cursor="hand2"
        )
        self.btn_start_stop.grid(row=0, column=2, sticky="w", padx=5)

        self.btn_clear_captured = ttk.Button(ctrl_frame, text="Clear List", command=self._clear_table)
        self.btn_clear_captured.grid(row=0, column=4, sticky="e")

        # -------------------------------------------------------------
        # 3. CAPTURED PACKETS TABLE
        # -------------------------------------------------------------
        table_frame = ttk.Frame(self)
        table_frame.grid(row=2, column=0, sticky="nsew", padx=15, pady=(6, 12))
        table_frame.columnconfigure(0, weight=1)
        table_frame.rowconfigure(0, weight=1)

        cols = ("num", "time", "proto", "src", "dst", "service", "decision", "rule")
        self.tree_cap = ttk.Treeview(table_frame, columns=cols, show="headings", selectmode="browse")

        self.tree_cap.heading("num", text="#")
        self.tree_cap.heading("time", text="Timestamp")
        self.tree_cap.heading("proto", text="Protocol")
        self.tree_cap.heading("src", text="Source IP:Port")
        self.tree_cap.heading("dst", text="Destination IP:Port")
        self.tree_cap.heading("service", text="Service")
        self.tree_cap.heading("decision", text="Firewall Decision")
        self.tree_cap.heading("rule", text="Matching Rule")

        self.tree_cap.column("num", width=45, anchor="center")
        self.tree_cap.column("time", width=120, anchor="center")
        self.tree_cap.column("proto", width=65, anchor="center")
        self.tree_cap.column("src", width=150, anchor="w")
        self.tree_cap.column("dst", width=150, anchor="w")
        self.tree_cap.column("service", width=120, anchor="center")
        self.tree_cap.column("decision", width=110, anchor="center")
        self.tree_cap.column("rule", width=220, anchor="w")

        self.tree_cap.tag_configure("tag_allowed", foreground="#15803d", font=("Segoe UI", 9, "bold"))
        self.tree_cap.tag_configure("tag_blocked", foreground="#b91c1c", font=("Segoe UI", 9, "bold"))

        scroll_y = ttk.Scrollbar(table_frame, orient="vertical", command=self.tree_cap.yview)
        self.tree_cap.configure(yscrollcommand=scroll_y.set)

        self.tree_cap.grid(row=0, column=0, sticky="nsew")
        scroll_y.grid(row=0, column=1, sticky="ns")

        self.packet_counter = 0

    def _toggle_capture(self) -> None:
        """Start or stop the packet capture worker."""
        if not self._is_capturing:
            self._start_capture()
        else:
            self._stop_capture()

    def _start_capture(self) -> None:
        """Launch background worker for capturing / generating packets."""
        source = self.combo_source.get()

        if "Network Card" in source:
            if not SNIFF_AVAILABLE:
                messagebox.showerror(
                    "Capture Unavailable",
                    "Scapy sniffing is not functional on this system (requires Npcap and Administrator privileges).\n\n"
                    "Please select 'Live Synthetic Stream Generator' to demonstrate live packet evaluation."
                )
                return

        self._is_capturing = True
        self.btn_start_stop.config(text="⏹ Stop Live Capture", bg="#dc2626", activebackground="#b91c1c")
        self.combo_source.config(state="disabled")

        if "Network Card" in source:
            self._capture_thread = threading.Thread(target=self._sniff_worker, daemon=True)
        else:
            self._capture_thread = threading.Thread(target=self._synthetic_stream_worker, daemon=True)

        self._capture_thread.start()

    def _stop_capture(self) -> None:
        """Signal capture loop to stop."""
        self._is_capturing = False
        self.btn_start_stop.config(text="▶ Start Live Capture", bg="#16a34a", activebackground="#15803d")
        self.combo_source.config(state="readonly")

    def _clear_table(self) -> None:
        """Clear captured packets list."""
        for item in self.tree_cap.get_children():
            self.tree_cap.delete(item)
        self.packet_counter = 0

    def _synthetic_stream_worker(self) -> None:
        """Worker thread that continuously generates realistic packets at an educational pace."""
        sample_traffic = [
            ("192.168.1.102", "142.250.190.46", "TCP", 54321, 443, "Web HTTPS"),
            ("192.168.1.102", "93.184.216.34", "TCP", 54322, 80, "Web HTTP"),
            ("192.168.1.105", "192.168.1.20", "TCP", 5000, 23, "Insecure Telnet"),
            ("192.168.1.110", "8.8.8.8", "UDP", 53535, 53, "DNS Request"),
            ("192.168.1.115", "8.8.4.4", "ICMP", None, None, "Ping Echo"),
            ("192.168.1.120", "192.168.1.1", "TCP", 49152, 22, "SSH Admin"),
            ("10.0.0.50", "192.168.1.20", "TCP", 5111, 23, "Telnet Login Attempt"),
            ("192.168.1.102", "151.101.1.69", "TCP", 54326, 443, "CDN Secure Stream"),
            ("192.168.1.102", "172.217.16.206", "TCP", 54327, 80, "Unencrypted Web Page"),
            ("192.168.1.200", "1.1.1.1", "ICMP", None, None, "Ping Check"),
        ]

        while self._is_capturing:
            item = random.choice(sample_traffic)
            src_ip, dst_ip, proto, s_p, d_p, info = item

            # Generate synthetic packet
            pkt = PacketParser.create_simulated_packet(
                src_ip=src_ip,
                dst_ip=dst_ip,
                protocol=proto,
                src_port=s_p,
                dst_port=d_p,
                info=info,
                craft_scapy=True
            )

            res = self.engine.evaluate_packet(pkt)
            self.after(0, self._add_packet_row, res)

            # Sleep 1.2 seconds between packets so student can observe in real time
            for _ in range(12):
                if not self._is_capturing:
                    break
                time.sleep(0.1)

    def _sniff_worker(self) -> None:
        """Worker thread that executes Scapy sniff."""
        def handle_pkt(scapy_pkt):
            if not self._is_capturing:
                return
            parsed = PacketParser.parse_scapy_packet(scapy_pkt)
            if parsed is not None:
                res = self.engine.evaluate_packet(parsed)
                self.after(0, self._add_packet_row, res)

        try:
            # Sniff with stop_filter
            sniff(
                prn=handle_pkt,
                stop_filter=lambda p: not self._is_capturing,
                store=False,
                timeout=1
            )
            # Loop while capturing
            while self._is_capturing:
                sniff(
                    prn=handle_pkt,
                    stop_filter=lambda p: not self._is_capturing,
                    store=False,
                    timeout=1
                )
        except Exception as e:
            # Handle Npcap/admin error gracefully
            self.after(0, self._handle_sniff_error, str(e))

    def _handle_sniff_error(self, err_msg: str) -> None:
        """Alert user if real network card capture fails."""
        self._stop_capture()
        messagebox.showwarning(
            "Live Sniffing Note",
            f"Live network card capture could not proceed:\n{err_msg}\n\n"
            "This typically occurs on Windows when Npcap is missing or when running without Administrator privileges.\n\n"
            "Switching back to the 'Live Synthetic Stream Generator' allows you to demonstrate full packet capture without elevated rights."
        )
        self.combo_source.set("Live Synthetic Stream Generator (No Admin Needed)")

    def _add_packet_row(self, result: EvaluationResult) -> None:
        """Insert row into captured packets table."""
        self.packet_counter += 1
        p = result.packet
        time_str = result.timestamp.strftime("%H:%M:%S")
        src_str = f"{p.src_ip}:{p.src_port}" if p.src_port else p.src_ip
        dst_str = f"{p.dst_ip}:{p.dst_port}" if p.dst_port else p.dst_ip

        tag = "tag_allowed" if result.decision == "ALLOWED" else "tag_blocked"
        rule_desc = result.matched_rule_name if result.matched_rule_name else result.reason

        self.tree_cap.insert(
            "",
            0,  # Insert at top
            values=(
                self.packet_counter,
                time_str,
                p.protocol,
                src_str,
                dst_str,
                p.service_name,
                result.decision,
                rule_desc
            ),
            tags=(tag,)
        )

        # Cap rows at 100
        children = self.tree_cap.get_children()
        if len(children) > 100:
            self.tree_cap.delete(children[-1])
