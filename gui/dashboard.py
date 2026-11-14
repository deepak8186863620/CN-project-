"""
Dashboard View for Basic Packet-Filtering Firewall.

Displays:
- Real-time Firewall Status (RUNNING / STOPPED)
- Key Metrics: Processed, Allowed, Blocked, Active Rules
- Proportional Allowed vs Blocked Visual Chart (Tkinter Canvas)
- Live Recent Packet Event Stream
"""

import tkinter as tk
from tkinter import ttk, messagebox
from typing import Optional, Dict, Any

from basic_firewall.core.firewall_engine import FirewallEngine, EvaluationResult


class DashboardView(ttk.Frame):
    """Modern Dashboard with real-time statistics and packet activity feed."""

    def __init__(self, parent: tk.Widget, engine: FirewallEngine, on_navigate_rules: Optional[Any] = None):
        super().__init__(parent)
        self.engine = engine
        self.on_navigate_rules = on_navigate_rules

        # Register callback for automatic updates
        self.engine.register_callback(self._on_packet_evaluated)

        self._build_ui()
        self.refresh()

    def _build_ui(self) -> None:
        """Construct the dashboard widgets."""
        self.columnconfigure(0, weight=1)
        self.rowconfigure(2, weight=1)

        # -------------------------------------------------------------
        # 1. HEADER & CONTROL STRIP
        # -------------------------------------------------------------
        header_frame = ttk.LabelFrame(self, text="System Control & Status", padding=12)
        header_frame.grid(row=0, column=0, sticky="ew", padx=15, pady=(10, 8))
        header_frame.columnconfigure(1, weight=1)

        # Status Badge Frame
        status_box = tk.Frame(header_frame, bg="#ffffff", relief="groove", bd=1, padx=10, pady=6)
        status_box.grid(row=0, column=0, sticky="w", padx=(0, 15))

        tk.Label(status_box, text="Firewall State:", font=("Segoe UI", 9, "bold"), bg="#ffffff", fg="#64748b").pack(side="left", padx=(0, 5))
        self.lbl_status_badge = tk.Label(
            status_box,
            text=" RUNNING ",
            font=("Segoe UI", 10, "bold"),
            bg="#16a34a",
            fg="#ffffff",
            padx=8,
            pady=2
        )
        self.lbl_status_badge.pack(side="left")

        # Controls in header
        ctrl_frame = ttk.Frame(header_frame)
        ctrl_frame.grid(row=0, column=1, sticky="e")

        self.btn_toggle_engine = ttk.Button(
            ctrl_frame,
            text="⏸ Pause Firewall",
            command=self._toggle_firewall_status,
            width=18
        )
        self.btn_toggle_engine.pack(side="left", padx=5)

        ttk.Label(ctrl_frame, text="Default Fallback Policy:").pack(side="left", padx=(10, 4))
        self.combo_default_policy = ttk.Combobox(
            ctrl_frame,
            values=["BLOCK", "ALLOW"],
            state="readonly",
            width=8
        )
        self.combo_default_policy.set(self.engine.default_policy)
        self.combo_default_policy.bind("<<ComboboxSelected>>", self._on_change_default_policy)
        self.combo_default_policy.pack(side="left", padx=5)

        self.btn_reset_stats = ttk.Button(
            ctrl_frame,
            text="🔄 Reset Stats",
            command=self._reset_stats,
            width=14
        )
        self.btn_reset_stats.pack(side="left", padx=(10, 0))

        # -------------------------------------------------------------
        # 2. METRICS CARDS ROW
        # -------------------------------------------------------------
        metrics_frame = ttk.Frame(self)
        metrics_frame.grid(row=1, column=0, sticky="ew", padx=15, pady=6)
        for i in range(4):
            metrics_frame.columnconfigure(i, weight=1, uniform="metric_cards")

        # Card 1: Processed
        self.card_total, self.val_total = self._create_metric_card(
            metrics_frame, 0, "Packets Processed", "0", "#2563eb", "Total Traffic Evaluated"
        )
        # Card 2: Allowed
        self.card_allowed, self.val_allowed = self._create_metric_card(
            metrics_frame, 1, "Packets Allowed", "0 (0%)", "#16a34a", "Permitted through rules"
        )
        # Card 3: Blocked
        self.card_blocked, self.val_blocked = self._create_metric_card(
            metrics_frame, 2, "Packets Blocked", "0 (0%)", "#dc2626", "Filtered or dropped"
        )
        # Card 4: Active Rules
        self.card_rules, self.val_rules = self._create_metric_card(
            metrics_frame, 3, "Active Rules", "0", "#7c3aed", "Filtering criteria in engine"
        )

        # -------------------------------------------------------------
        # 3. LOWER SECTION (CHART & RECENT EVENTS STREAM)
        # -------------------------------------------------------------
        lower_frame = ttk.Frame(self)
        lower_frame.grid(row=2, column=0, sticky="nsew", padx=15, pady=(8, 12))
        lower_frame.columnconfigure(0, weight=1)
        lower_frame.columnconfigure(1, weight=2)
        lower_frame.rowconfigure(0, weight=1)

        # Chart Panel (Tkinter Canvas)
        chart_group = ttk.LabelFrame(lower_frame, text="Traffic Distribution Chart", padding=10)
        chart_group.grid(row=0, column=0, sticky="nsew", padx=(0, 10))
        chart_group.rowconfigure(0, weight=1)
        chart_group.columnconfigure(0, weight=1)

        self.canvas_chart = tk.Canvas(chart_group, bg="#ffffff", highlightthickness=1, highlightbackground="#e2e8f0", height=240)
        self.canvas_chart.grid(row=0, column=0, sticky="nsew")
        self.canvas_chart.bind("<Configure>", lambda e: self._draw_chart())

        # Recent Events Stream
        stream_group = ttk.LabelFrame(lower_frame, text="Live Packet Filtering Stream", padding=10)
        stream_group.grid(row=0, column=1, sticky="nsew")
        stream_group.rowconfigure(0, weight=1)
        stream_group.columnconfigure(0, weight=1)

        columns = ("time", "proto", "src", "dst", "decision", "rule")
        self.tree_stream = ttk.Treeview(stream_group, columns=columns, show="headings", height=8, selectmode="browse")

        self.tree_stream.heading("time", text="Timestamp")
        self.tree_stream.heading("proto", text="Proto")
        self.tree_stream.heading("src", text="Source IP:Port")
        self.tree_stream.heading("dst", text="Destination IP:Port")
        self.tree_stream.heading("decision", text="Decision")
        self.tree_stream.heading("rule", text="Matched Rule / Reason")

        self.tree_stream.column("time", width=125, anchor="center")
        self.tree_stream.column("proto", width=60, anchor="center")
        self.tree_stream.column("src", width=145, anchor="w")
        self.tree_stream.column("dst", width=145, anchor="w")
        self.tree_stream.column("decision", width=95, anchor="center")
        self.tree_stream.column("rule", width=220, anchor="w")

        # Color tags
        self.tree_stream.tag_configure("tag_allowed", foreground="#15803d", font=("Segoe UI", 9, "bold"))
        self.tree_stream.tag_configure("tag_blocked", foreground="#b91c1c", font=("Segoe UI", 9, "bold"))

        scroll = ttk.Scrollbar(stream_group, orient="vertical", command=self.tree_stream.xview)
        self.tree_stream.configure(yscrollcommand=scroll.set)

        self.tree_stream.grid(row=0, column=0, sticky="nsew")
        scroll.grid(row=0, column=1, sticky="ns")

    def _create_metric_card(
        self, parent: ttk.Frame, col: int, title: str, init_val: str, accent_color: str, subtitle: str
    ) -> Any:
        """Helper to build a clean KPI metric card."""
        card = tk.Frame(parent, bg="#ffffff", relief="groove", bd=1, padx=12, pady=10)
        card.grid(row=0, column=col, sticky="nsew", padx=4)

        tk.Label(card, text=title.upper(), font=("Segoe UI", 8, "bold"), fg="#64748b", bg="#ffffff").pack(anchor="w")
        lbl_val = tk.Label(card, text=init_val, font=("Segoe UI", 16, "bold"), fg=accent_color, bg="#ffffff", pady=3)
        lbl_val.pack(anchor="w")
        tk.Label(card, text=subtitle, font=("Segoe UI", 8), fg="#94a3b8", bg="#ffffff").pack(anchor="w")

        return card, lbl_val

    def _toggle_firewall_status(self) -> None:
        """Toggle RUNNING / STOPPED."""
        new_state = not self.engine.is_running
        self.engine.set_running(new_state)
        self.refresh()

    def _on_change_default_policy(self, event=None) -> None:
        """Update default policy when user selects from combobox."""
        policy = self.combo_default_policy.get()
        self.engine.set_default_policy(policy)

    def _reset_stats(self) -> None:
        """Reset counters and clear live stream."""
        if messagebox.askyesno("Confirm Reset", "Reset packet statistics counters?"):
            self.engine.reset_stats()
            # Clear stream rows
            for item in self.tree_stream.get_children():
                self.tree_stream.delete(item)
            self.refresh()

    def _on_packet_evaluated(self, result: EvaluationResult) -> None:
        """Thread-safe UI update when a packet is processed."""
        # Use after() to ensure execution on Tkinter main GUI thread
        self.after(0, self._append_packet_to_stream, result)

    def _append_packet_to_stream(self, result: EvaluationResult) -> None:
        """Append evaluated packet to live stream table."""
        p = result.packet
        time_str = result.timestamp.strftime("%H:%M:%S")
        src_str = f"{p.src_ip}:{p.src_port}" if p.src_port else p.src_ip
        dst_str = f"{p.dst_ip}:{p.dst_port}" if p.dst_port else p.dst_ip

        tag = "tag_allowed" if result.decision == "ALLOWED" else "tag_blocked"
        rule_label = result.matched_rule_name if result.matched_rule_name else result.reason

        item = self.tree_stream.insert(
            "",
            0,  # Insert at top
            values=(time_str, p.protocol, src_str, dst_str, result.decision, rule_label),
            tags=(tag,)
        )

        # Cap stream to 50 rows
        children = self.tree_stream.get_children()
        if len(children) > 50:
            self.tree_stream.delete(children[-1])

        self.refresh()

    def refresh(self) -> None:
        """Refresh statistics and status display."""
        stats = self.engine.get_stats()

        # 1. Update Status Badge
        if stats["is_running"]:
            self.lbl_status_badge.config(text=" RUNNING ", bg="#16a34a", fg="#ffffff")
            self.btn_toggle_engine.config(text="⏸ Pause Firewall")
        else:
            self.lbl_status_badge.config(text=" STOPPED ", bg="#d97706", fg="#ffffff")
            self.btn_toggle_engine.config(text="▶ Start Firewall")

        # 2. Update Metric values
        self.val_total.config(text=f"{stats['total_processed']}")
        self.val_allowed.config(text=f"{stats['total_allowed']} ({stats['allow_percentage']}%)")
        self.val_blocked.config(text=f"{stats['total_blocked']} ({stats['block_percentage']}%)")
        self.val_rules.config(text=f"{stats['active_rules_count']} of {stats['total_rules_count']}")

        # 3. Redraw chart
        self._draw_chart()

    def _draw_chart(self) -> None:
        """Render a comparative bar chart and metrics on the Tkinter canvas."""
        c = self.canvas_chart
        c.delete("all")

        w = c.winfo_width()
        h = c.winfo_height()
        if w < 50 or h < 50:
            return

        stats = self.engine.get_stats()
        total = stats["total_processed"]
        allowed = stats["total_allowed"]
        blocked = stats["total_blocked"]

        # Title
        c.create_text(w // 2, 22, text="ALLOW / BLOCK RATIO", font=("Segoe UI", 9, "bold"), fill="#475569")

        if total == 0:
            # Empty state
            c.create_text(
                w // 2, h // 2,
                text="No traffic evaluated yet.\nUse Packet Simulator or\nLive Capture to test.",
                font=("Segoe UI", 9),
                fill="#94a3b8",
                justify="center"
            )
            return

        # Comparative horizontal ratio bar
        bar_x1 = 25
        bar_x2 = w - 25
        bar_y1 = 55
        bar_y2 = 85
        bar_width = max(1, bar_x2 - bar_x1)

        allowed_width = int(bar_width * (allowed / total))
        blocked_width = bar_width - allowed_width

        # Background container
        c.create_rectangle(bar_x1, bar_y1, bar_x2, bar_y2, fill="#f1f5f9", outline="#cbd5e1", width=1)

        if allowed_width > 0:
            c.create_rectangle(bar_x1, bar_y1, bar_x1 + allowed_width, bar_y2, fill="#16a34a", outline="")
            if allowed_width > 35:
                c.create_text(bar_x1 + allowed_width // 2, (bar_y1 + bar_y2) // 2, text=f"{stats['allow_percentage']}%", font=("Segoe UI", 9, "bold"), fill="#ffffff")

        if blocked_width > 0:
            c.create_rectangle(bar_x1 + allowed_width, bar_y1, bar_x2, bar_y2, fill="#dc2626", outline="")
            if blocked_width > 35:
                c.create_text(bar_x1 + allowed_width + blocked_width // 2, (bar_y1 + bar_y2) // 2, text=f"{stats['block_percentage']}%", font=("Segoe UI", 9, "bold"), fill="#ffffff")

        # Vertical breakdown bars
        bottom_y = h - 35
        top_y = 120
        chart_h = bottom_y - top_y

        bar1_x = w * 0.3
        bar2_x = w * 0.7
        bw = min(50, w * 0.15)

        h_allow = chart_h * (allowed / total)
        h_block = chart_h * (blocked / total)

        # Baseline
        c.create_line(25, bottom_y, w - 25, bottom_y, fill="#cbd5e1", width=1)

        # Allowed Bar
        c.create_rectangle(bar1_x - bw // 2, bottom_y - h_allow, bar1_x + bw // 2, bottom_y, fill="#22c55e", outline="#16a34a")
        c.create_text(bar1_x, bottom_y - h_allow - 12, text=f"{allowed}\n({stats['allow_percentage']}%)", font=("Segoe UI", 8, "bold"), fill="#15803d", justify="center")
        c.create_text(bar1_x, bottom_y + 15, text="ALLOWED", font=("Segoe UI", 8, "bold"), fill="#15803d")

        # Blocked Bar
        c.create_rectangle(bar2_x - bw // 2, bottom_y - h_block, bar2_x + bw // 2, bottom_y, fill="#ef4444", outline="#dc2626")
        c.create_text(bar2_x, bottom_y - h_block - 12, text=f"{blocked}\n({stats['block_percentage']}%)", font=("Segoe UI", 8, "bold"), fill="#b91c1c", justify="center")
        c.create_text(bar2_x, bottom_y + 15, text="BLOCKED", font=("Segoe UI", 8, "bold"), fill="#b91c1c")
