"""
Packet Simulator View for Basic Packet-Filtering Firewall.

Allows manual input and generation of synthetic network packets:
- Validates user input
- Crafts PacketData and Scapy representations
- Evaluates against the firewall engine
- Displays prominent visual result banner (ALLOWED in Green, BLOCKED in Red)
- Explains matching criteria and rule evaluation step-by-step
"""

import random
import tkinter as tk
from tkinter import ttk, messagebox
from typing import Optional, Dict, Any

from basic_firewall.core.packet_parser import PacketParser, PacketData
from basic_firewall.core.firewall_engine import FirewallEngine, EvaluationResult


class PacketSimulatorView(ttk.Frame):
    """Interactive packet crafting and inspection testbed."""

    QUICK_PRESETS = [
        {"label": "🌐 HTTP Web (TCP :80)", "proto": "TCP", "src_ip": "192.168.1.100", "dst_ip": "93.184.216.34", "src_p": "51234", "dst_p": "80", "info": "GET /index.html HTTP/1.1"},
        {"label": "🔒 HTTPS Secure (TCP :443)", "proto": "TCP", "src_ip": "192.168.1.100", "dst_ip": "142.250.190.46", "src_p": "51235", "dst_p": "443", "info": "TLS Client Hello"},
        {"label": "⚠️ Telnet Insecure (TCP :23)", "proto": "TCP", "src_ip": "192.168.1.10", "dst_ip": "192.168.1.20", "src_p": "5000", "dst_p": "23", "info": "Telnet Terminal Connect"},
        {"label": "🔍 DNS Query (UDP :53)", "proto": "UDP", "src_ip": "192.168.1.100", "dst_ip": "8.8.8.8", "src_p": "53000", "dst_p": "53", "info": "DNS Query A example.com"},
        {"label": "📡 Ping Echo (ICMP)", "proto": "ICMP", "src_ip": "192.168.1.100", "dst_ip": "8.8.8.8", "src_p": "", "dst_p": "", "info": "Echo Request (Ping)"},
        {"label": "🔑 SSH Shell (TCP :22)", "proto": "TCP", "src_ip": "192.168.1.50", "dst_ip": "192.168.1.200", "src_p": "49152", "dst_p": "22", "info": "SSH-2.0-OpenSSH_8.9"},
    ]

    def __init__(self, parent: tk.Widget, engine: FirewallEngine):
        super().__init__(parent)
        self.engine = engine
        self._build_ui()

    def _build_ui(self) -> None:
        """Construct packet inputs and decision displays."""
        self.columnconfigure(0, weight=1)
        self.columnconfigure(1, weight=1)
        self.rowconfigure(1, weight=1)

        # -------------------------------------------------------------
        # 1. TOP QUICK PRESETS BAR
        # -------------------------------------------------------------
        presets_bar = ttk.LabelFrame(self, text="Quick Demonstration Presets", padding=8)
        presets_bar.grid(row=0, column=0, columnspan=2, sticky="ew", padx=15, pady=(10, 6))

        for idx, preset in enumerate(self.QUICK_PRESETS):
            btn = ttk.Button(
                presets_bar,
                text=preset["label"],
                command=lambda p=preset: self._apply_preset(p)
            )
            btn.pack(side="left", padx=4, pady=2)

        # -------------------------------------------------------------
        # 2. LEFT COLUMN: PACKET INPUT CRAFTING
        # -------------------------------------------------------------
        input_frame = ttk.LabelFrame(self, text="Packet Header Fields", padding=14)
        input_frame.grid(row=1, column=0, sticky="nsew", padx=(15, 8), pady=(6, 12))
        input_frame.columnconfigure(1, weight=1)

        pad_y = 6
        row = 0

        # Source IP
        ttk.Label(input_frame, text="Source IP Address:").grid(row=row, column=0, sticky="w", pady=pad_y)
        self.ent_src_ip = ttk.Entry(input_frame)
        self.ent_src_ip.insert(0, "192.168.1.10")
        self.ent_src_ip.grid(row=row, column=1, sticky="ew", pady=pad_y, padx=(8, 0))

        row += 1
        # Destination IP
        ttk.Label(input_frame, text="Destination IP Address:").grid(row=row, column=0, sticky="w", pady=pad_y)
        self.ent_dst_ip = ttk.Entry(input_frame)
        self.ent_dst_ip.insert(0, "192.168.1.20")
        self.ent_dst_ip.grid(row=row, column=1, sticky="ew", pady=pad_y, padx=(8, 0))

        row += 1
        # Protocol
        ttk.Label(input_frame, text="Transport Protocol:").grid(row=row, column=0, sticky="w", pady=pad_y)
        self.combo_proto = ttk.Combobox(input_frame, values=["TCP", "UDP", "ICMP"], state="readonly")
        self.combo_proto.set("TCP")
        self.combo_proto.bind("<<ComboboxSelected>>", self._on_proto_change)
        self.combo_proto.grid(row=row, column=1, sticky="w", pady=pad_y, padx=(8, 0))

        row += 1
        # Source Port
        ttk.Label(input_frame, text="Source Port (0-65535):").grid(row=row, column=0, sticky="w", pady=pad_y)
        self.ent_src_port = ttk.Entry(input_frame)
        self.ent_src_port.insert(0, "5000")
        self.ent_src_port.grid(row=row, column=1, sticky="ew", pady=pad_y, padx=(8, 0))

        row += 1
        # Destination Port
        ttk.Label(input_frame, text="Destination Port (0-65535):").grid(row=row, column=0, sticky="w", pady=pad_y)
        self.ent_dst_port = ttk.Entry(input_frame)
        self.ent_dst_port.insert(0, "23")
        self.ent_dst_port.grid(row=row, column=1, sticky="ew", pady=pad_y, padx=(8, 0))

        row += 1
        # Optional Payload / Info
        ttk.Label(input_frame, text="Payload Description:").grid(row=row, column=0, sticky="w", pady=pad_y)
        self.ent_info = ttk.Entry(input_frame)
        self.ent_info.insert(0, "Simulated Packet Payload")
        self.ent_info.grid(row=row, column=1, sticky="ew", pady=pad_y, padx=(8, 0))

        row += 1
        # Big Check Packet Button
        btn_box = tk.Frame(input_frame, bg="#ffffff", pady=10)
        btn_box.grid(row=row, column=0, columnspan=2, sticky="ew", pady=(10, 0))

        self.btn_check = tk.Button(
            btn_box,
            text="🔍 CHECK PACKET",
            command=self._check_packet,
            font=("Segoe UI", 11, "bold"),
            bg="#2563eb",
            fg="#ffffff",
            activebackground="#1d4ed8",
            activeforeground="#ffffff",
            relief="flat",
            padx=18,
            pady=8,
            cursor="hand2"
        )
        self.btn_check.pack(fill="x")

        # Burst traffic simulator
        burst_frame = ttk.Frame(input_frame)
        burst_frame.grid(row=row + 1, column=0, columnspan=2, sticky="ew", pady=(12, 0))

        ttk.Label(burst_frame, text="Demonstration Helper:", font=("Segoe UI", 8, "italic")).pack(side="left")
        self.btn_burst = ttk.Button(burst_frame, text="⚡ Send 15 Mixed Packets Burst", command=self._simulate_traffic_burst)
        self.btn_burst.pack(side="right")

        # -------------------------------------------------------------
        # 3. RIGHT COLUMN: FIREWALL DECISION & EXPLANATION
        # -------------------------------------------------------------
        decision_frame = ttk.LabelFrame(self, text="Inspection Result & Decision Analysis", padding=14)
        decision_frame.grid(row=1, column=1, sticky="nsew", padx=(8, 15), pady=(6, 12))
        decision_frame.columnconfigure(0, weight=1)

        # Big Visual Banner
        self.banner_decision = tk.Label(
            decision_frame,
            text="READY FOR PACKET",
            font=("Segoe UI", 16, "bold"),
            bg="#f1f5f9",
            fg="#64748b",
            relief="groove",
            bd=2,
            pady=16
        )
        self.banner_decision.grid(row=0, column=0, sticky="ew", pady=(0, 10))

        # Details Panel
        details_box = tk.Frame(decision_frame, bg="#ffffff", bd=1, relief="solid", padx=12, pady=10)
        details_box.grid(row=1, column=0, sticky="nsew", pady=6)
        decision_frame.rowconfigure(1, weight=1)
        details_box.columnconfigure(1, weight=1)

        self.lbl_reason_title = tk.Label(details_box, text="Evaluation Rationale:", font=("Segoe UI", 9, "bold"), bg="#ffffff", fg="#334155")
        self.lbl_reason_title.pack(anchor="w", pady=(0, 4))

        self.txt_reason = tk.Text(details_box, height=6, wrap="word", font=("Segoe UI", 9), bg="#f8fafc", relief="flat", padx=8, pady=8)
        self.txt_reason.pack(fill="x", pady=(0, 10))
        self.txt_reason.insert("1.0", "Click 'CHECK PACKET' to inspect the configured packet header against all active rules.")
        self.txt_reason.config(state="disabled")

        # Scapy packet representation preview
        tk.Label(details_box, text="Scapy Layer Representation:", font=("Segoe UI", 9, "bold"), bg="#ffffff", fg="#334155").pack(anchor="w", pady=(4, 2))
        self.lbl_scapy_inspect = tk.Label(details_box, text="[No packet generated yet]", font=("Consolas", 8), bg="#f8fafc", fg="#475569", anchor="w", justify="left", relief="flat", padx=6, pady=6)
        self.lbl_scapy_inspect.pack(fill="x")

        # Matching summary footer
        self.lbl_engine_state = tk.Label(
            details_box,
            text=f"Engine Mode: {self.engine.get_stats()['status_text']} | Fallback Policy: {self.engine.default_policy}",
            font=("Segoe UI", 8, "italic"),
            bg="#ffffff",
            fg="#94a3b8"
        )
        self.lbl_engine_state.pack(anchor="w", pady=(12, 0))

    def _on_proto_change(self, event=None) -> None:
        """Handle ICMP port field disabling."""
        proto = self.combo_proto.get().upper()
        if proto == "ICMP":
            self.ent_src_port.config(state="disabled")
            self.ent_dst_port.config(state="disabled")
        else:
            self.ent_src_port.config(state="normal")
            self.ent_dst_port.config(state="normal")

    def _apply_preset(self, preset: Dict[str, Any]) -> None:
        """Populate input fields with preset scenario."""
        self.ent_src_ip.delete(0, tk.END)
        self.ent_src_ip.insert(0, preset["src_ip"])

        self.ent_dst_ip.delete(0, tk.END)
        self.ent_dst_ip.insert(0, preset["dst_ip"])

        self.combo_proto.set(preset["proto"])
        self._on_proto_change()

        if preset["proto"] != "ICMP":
            self.ent_src_port.delete(0, tk.END)
            self.ent_src_port.insert(0, preset["src_p"])

            self.ent_dst_port.delete(0, tk.END)
            self.ent_dst_port.insert(0, preset["dst_p"])

        self.ent_info.delete(0, tk.END)
        self.ent_info.insert(0, preset.get("info", ""))

    def _check_packet(self) -> None:
        """Validate input, craft packet, evaluate, and display decision."""
        src_ip = self.ent_src_ip.get().strip()
        dst_ip = self.ent_dst_ip.get().strip()
        proto = self.combo_proto.get().strip().upper()
        src_port = self.ent_src_port.get().strip() if proto != "ICMP" else None
        dst_port = self.ent_dst_port.get().strip() if proto != "ICMP" else None
        info = self.ent_info.get().strip()

        # Validate inputs
        ok, err_msg = PacketParser.validate_packet_input(src_ip, dst_ip, proto, src_port, dst_port)
        if not ok:
            messagebox.showerror("Invalid Packet Input", err_msg)
            return

        # Create packet
        pkt = PacketParser.create_simulated_packet(
            src_ip=src_ip,
            dst_ip=dst_ip,
            protocol=proto,
            src_port=src_port,
            dst_port=dst_port,
            info=info,
            craft_scapy=True
        )

        # Evaluate through engine
        result = self.engine.evaluate_packet(pkt)
        self._display_result(result)

    def _display_result(self, result: EvaluationResult) -> None:
        """Update result banner and rationale."""
        decision = result.decision.upper()

        if decision == "ALLOWED":
            self.banner_decision.config(
                text="✔ ALLOWED",
                bg="#16a34a",
                fg="#ffffff"
            )
        else:
            self.banner_decision.config(
                text="✖ BLOCKED",
                bg="#dc2626",
                fg="#ffffff"
            )

        # Update rationale text
        self.txt_reason.config(state="normal")
        self.txt_reason.delete("1.0", tk.END)

        p = result.packet
        summary_text = (
            f"DECISION: {decision}\n\n"
            f"RATIONALE:\n{result.reason}\n\n"
            f"PACKET DETAILS:\n"
            f"  • Protocol: {p.protocol}\n"
            f"  • Source: {p.src_ip}" + (f":{p.src_port}" if p.src_port else "") + "\n"
            f"  • Destination: {p.dst_ip}" + (f":{p.dst_port}" if p.dst_port else "") + "\n"
            f"  • Service Inferred: {p.service_name}\n"
            f"  • Applied Policy Level: {result.applied_policy}"
        )
        self.txt_reason.insert("1.0", summary_text)
        self.txt_reason.config(state="disabled")

        # Update Scapy summary
        if p.scapy_pkt is not None:
            scapy_desc = p.scapy_pkt.summary()
        else:
            scapy_desc = f"{p.protocol} Packet ({p.src_ip} -> {p.dst_ip})"

        self.lbl_scapy_inspect.config(text=f"Scapy Summary: {scapy_desc}")
        self.lbl_engine_state.config(
            text=f"Engine Mode: {self.engine.get_stats()['status_text']} | Fallback Policy: {self.engine.default_policy}"
        )

    def _simulate_traffic_burst(self) -> None:
        """Simulate a burst of diverse network traffic to populate logs and graphs."""
        scenarios = [
            ("192.168.1.105", "142.250.190.46", "TCP", 54321, 443, "Web HTTPS browsing"),
            ("192.168.1.105", "93.184.216.34", "TCP", 54322, 80, "Web HTTP download"),
            ("192.168.1.120", "192.168.1.1", "UDP", 53535, 53, "DNS resolution query"),
            ("10.0.0.99", "192.168.1.20", "TCP", 4500, 23, "Telnet attempt from guest"),
            ("192.168.1.250", "8.8.8.8", "ICMP", None, None, "ICMP Echo Ping"),
            ("192.168.1.111", "1.1.1.1", "UDP", 53123, 53, "Cloudflare DNS query"),
            ("192.168.1.75", "10.0.0.1", "TCP", 33000, 8080, "Alternative Web Port"),
            ("172.16.5.10", "192.168.1.20", "TCP", 5210, 23, "Unauthorized Telnet scan"),
            ("192.168.1.105", "172.217.16.206", "TCP", 54329, 443, "Secure Web Session"),
            ("192.168.1.80", "192.168.1.1", "ICMP", None, None, "Gateway Ping"),
            ("192.168.1.90", "104.244.42.1", "TCP", 55443, 80, "HTTP news feed"),
            ("192.168.1.15", "192.168.1.25", "TCP", 22000, 22, "Internal SSH connection"),
            ("192.168.1.105", "204.79.197.200", "TCP", 54335, 443, "Bing search query"),
            ("10.10.10.5", "192.168.1.20", "TCP", 5005, 23, "Legacy Telnet connection"),
            ("192.168.1.100", "8.8.4.4", "UDP", 53999, 53, "Secondary DNS query"),
        ]

        last_res = None
        for s in scenarios:
            src_ip, dst_ip, proto, s_p, d_p, info = s
            pkt = PacketParser.create_simulated_packet(
                src_ip=src_ip,
                dst_ip=dst_ip,
                protocol=proto,
                src_port=s_p,
                dst_port=d_p,
                info=info,
                craft_scapy=True
            )
            last_res = self.engine.evaluate_packet(pkt)

        if last_res:
            self._display_result(last_res)

        messagebox.showinfo(
            "Burst Complete",
            f"Successfully generated and evaluated {len(scenarios)} network packets!\nCheck the Dashboard and Logs tab to view updated statistics."
        )
