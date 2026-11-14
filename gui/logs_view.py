"""
Firewall Logs View for Basic Packet-Filtering Firewall.

Provides an audit log browser for 'firewall.log' with:
- Keyword search and filtering by decision (ALL / ALLOWED / BLOCKED)
- Color-coded decision badges (Green ALLOWED / Red BLOCKED)
- Clear logs functionality
- Export logs to text file
"""

import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from typing import Optional

from basic_firewall.core.logger import FirewallLogger


class LogsView(ttk.Frame):
    """Log inspector and search interface."""

    def __init__(self, parent: tk.Widget, logger: FirewallLogger):
        super().__init__(parent)
        self.logger = logger

        self._build_ui()
        self.refresh()

    def _build_ui(self) -> None:
        """Construct search bar, table, and log control buttons."""
        self.columnconfigure(0, weight=1)
        self.rowconfigure(1, weight=1)

        # -------------------------------------------------------------
        # 1. FILTER & SEARCH BAR
        # -------------------------------------------------------------
        filter_bar = ttk.LabelFrame(self, text="Log Filtering & Search", padding=10)
        filter_bar.grid(row=0, column=0, sticky="ew", padx=15, pady=(10, 6))
        filter_bar.columnconfigure(1, weight=1)

        # Keyword search
        ttk.Label(filter_bar, text="Search Keyword:").grid(row=0, column=0, sticky="w", padx=(0, 5))
        self.ent_search = ttk.Entry(filter_bar)
        self.ent_search.grid(row=0, column=1, sticky="ew", padx=(0, 10))
        self.ent_search.bind("<Return>", lambda e: self.refresh())

        # Decision filter
        ttk.Label(filter_bar, text="Decision:").grid(row=0, column=2, sticky="w", padx=(0, 5))
        self.combo_filter_decision = ttk.Combobox(filter_bar, values=["ALL", "ALLOWED", "BLOCKED"], state="readonly", width=10)
        self.combo_filter_decision.set("ALL")
        self.combo_filter_decision.bind("<<ComboboxSelected>>", lambda e: self.refresh())
        self.combo_filter_decision.grid(row=0, column=3, sticky="w", padx=(0, 10))

        # Filter button
        self.btn_search = ttk.Button(filter_bar, text="Filter Logs", command=self.refresh)
        self.btn_search.grid(row=0, column=4, sticky="w", padx=(0, 10))

        self.btn_reset_filter = ttk.Button(filter_bar, text="Reset Filter", command=self._reset_filter)
        self.btn_reset_filter.grid(row=0, column=5, sticky="w")

        # -------------------------------------------------------------
        # 2. LOG ENTRIES TABLE
        # -------------------------------------------------------------
        table_frame = ttk.Frame(self)
        table_frame.grid(row=1, column=0, sticky="nsew", padx=15, pady=6)
        table_frame.columnconfigure(0, weight=1)
        table_frame.rowconfigure(0, weight=1)

        cols = ("time", "src_ip", "src_port", "dst_ip", "dst_port", "proto", "decision", "rule")
        self.tree_logs = ttk.Treeview(table_frame, columns=cols, show="headings", selectmode="browse")

        self.tree_logs.heading("time", text="Timestamp")
        self.tree_logs.heading("src_ip", text="Source IP")
        self.tree_logs.heading("src_port", text="Src Port")
        self.tree_logs.heading("dst_ip", text="Dest IP")
        self.tree_logs.heading("dst_port", text="Dst Port")
        self.tree_logs.heading("proto", text="Protocol")
        self.tree_logs.heading("decision", text="Decision")
        self.tree_logs.heading("rule", text="Matched Rule / Action Details")

        self.tree_logs.column("time", width=140, anchor="center")
        self.tree_logs.column("src_ip", width=130, anchor="center")
        self.tree_logs.column("src_port", width=70, anchor="center")
        self.tree_logs.column("dst_ip", width=130, anchor="center")
        self.tree_logs.column("dst_port", width=70, anchor="center")
        self.tree_logs.column("proto", width=70, anchor="center")
        self.tree_logs.column("decision", width=95, anchor="center")
        self.tree_logs.column("rule", width=250, anchor="w")

        # Styling tags
        self.tree_logs.tag_configure("tag_allowed", foreground="#15803d", font=("Segoe UI", 9, "bold"))
        self.tree_logs.tag_configure("tag_blocked", foreground="#b91c1c", font=("Segoe UI", 9, "bold"))

        scroll_y = ttk.Scrollbar(table_frame, orient="vertical", command=self.tree_logs.yview)
        scroll_x = ttk.Scrollbar(table_frame, orient="horizontal", command=self.tree_logs.xview)
        self.tree_logs.configure(yscrollcommand=scroll_y.set, xscrollcommand=scroll_x.set)

        self.tree_logs.grid(row=0, column=0, sticky="nsew")
        scroll_y.grid(row=0, column=1, sticky="ns")
        scroll_x.grid(row=1, column=0, sticky="ew")

        # -------------------------------------------------------------
        # 3. BOTTOM CONTROL BAR
        # -------------------------------------------------------------
        ctrl_bar = ttk.Frame(self)
        ctrl_bar.grid(row=2, column=0, sticky="ew", padx=15, pady=(8, 14))

        self.lbl_count = ttk.Label(ctrl_bar, text="Showing 0 log entries")
        self.lbl_count.pack(side="left")

        self.btn_clear = ttk.Button(ctrl_bar, text="🧹 Clear All Logs", command=self._clear_logs)
        self.btn_clear.pack(side="right", padx=(8, 0))

        self.btn_export = ttk.Button(ctrl_bar, text="💾 Export Logs...", command=self._export_logs)
        self.btn_export.pack(side="right", padx=(8, 0))

        self.btn_refresh = ttk.Button(ctrl_bar, text="🔄 Refresh Logs", command=self.refresh)
        self.btn_refresh.pack(side="right")

    def _reset_filter(self) -> None:
        """Reset search criteria."""
        self.ent_search.delete(0, tk.END)
        self.combo_filter_decision.set("ALL")
        self.refresh()

    def _clear_logs(self) -> None:
        """Truncate the log file."""
        if messagebox.askyesno("Confirm Clear Logs", "Are you sure you want to clear all firewall logs? This cannot be undone."):
            if self.logger.clear_logs():
                self.refresh()
                messagebox.showinfo("Logs Cleared", "firewall.log has been cleared successfully.")

    def _export_logs(self) -> None:
        """Export log file to a chosen location."""
        file_path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text Files", "*.txt"), ("Log Files", "*.log"), ("All Files", "*.*")],
            initialfile="firewall_export.txt"
        )
        if file_path:
            if self.logger.export_logs(file_path):
                messagebox.showinfo("Export Successful", f"Logs successfully exported to:\n{file_path}")

    def refresh(self) -> None:
        """Read log entries and display in treeview."""
        keyword = self.ent_search.get().strip() or None
        decision = self.combo_filter_decision.get()

        for item in self.tree_logs.get_children():
            self.tree_logs.delete(item)

        entries = self.logger.read_logs(max_lines=1000, filter_decision=decision, search_keyword=keyword)

        for entry in entries:
            tag = "tag_allowed" if entry["decision"] == "ALLOWED" else "tag_blocked"
            self.tree_logs.insert(
                "",
                "end",
                values=(
                    entry["timestamp"],
                    entry["src_ip"],
                    entry["src_port"],
                    entry["dst_ip"],
                    entry["dst_port"],
                    entry["protocol"],
                    entry["decision"],
                    entry["matched_rule"],
                ),
                tags=(tag,)
            )

        self.lbl_count.config(text=f"Showing {len(entries)} log entries (File: {self.logger.log_path})")
