"""
Rule Management View for Basic Packet-Filtering Firewall.

Provides interactive table of active/disabled firewall rules with features to:
- Add, Edit, Delete, Toggle rules
- Reorder rules (Move Up / Move Down) to demonstrate 'First Match Wins'
- Reset to educational sample defaults
- Input validation modal dialog with common network service presets
"""

import tkinter as tk
from tkinter import ttk, messagebox
from typing import Optional, Dict, Any

from basic_firewall.core.rule_manager import RuleManager, FirewallRule


class RuleEditDialog(tk.Toplevel):
    """Modal dialog for creating or updating a firewall rule."""

    PRESETS = {
        "Custom (Manual Input)": None,
        "HTTP Web (TCP :80) -> ALLOW": {
            "name": "Allow Web HTTP", "proto": "TCP", "src_ip": "ANY", "dst_ip": "ANY",
            "src_port": "ANY", "dst_port": "80", "action": "ALLOW"
        },
        "HTTPS Secure Web (TCP :443) -> ALLOW": {
            "name": "Allow Web HTTPS", "proto": "TCP", "src_ip": "ANY", "dst_ip": "ANY",
            "src_port": "ANY", "dst_port": "443", "action": "ALLOW"
        },
        "Telnet Insecure (TCP :23) -> BLOCK": {
            "name": "Block Insecure Telnet", "proto": "TCP", "src_ip": "ANY", "dst_ip": "ANY",
            "src_port": "ANY", "dst_port": "23", "action": "BLOCK"
        },
        "SSH Shell (TCP :22) -> ALLOW": {
            "name": "Allow SSH Management", "proto": "TCP", "src_ip": "ANY", "dst_ip": "ANY",
            "src_port": "ANY", "dst_port": "22", "action": "ALLOW"
        },
        "DNS Name Resolution (UDP :53) -> ALLOW": {
            "name": "Allow DNS Queries", "proto": "UDP", "src_ip": "ANY", "dst_ip": "ANY",
            "src_port": "ANY", "dst_port": "53", "action": "ALLOW"
        },
        "ICMP Ping Echo -> BLOCK": {
            "name": "Block ICMP Ping", "proto": "ICMP", "src_ip": "ANY", "dst_ip": "ANY",
            "src_port": "ANY", "dst_port": "ANY", "action": "BLOCK"
        },
        "Block Malicious Subnet (192.168.100.0/24)": {
            "name": "Block Untrusted Subnet", "proto": "ANY", "src_ip": "192.168.100.0/24", "dst_ip": "ANY",
            "src_port": "ANY", "dst_port": "ANY", "action": "BLOCK"
        },
    }

    def __init__(self, parent: tk.Widget, rule: Optional[FirewallRule] = None):
        super().__init__(parent)
        self.transient(parent)
        self.grab_set()

        self.rule = rule
        self.result: Optional[Dict[str, Any]] = None

        title = "Edit Firewall Rule" if rule else "Add New Firewall Rule"
        self.title(title)
        self.geometry("520x460")
        self.resizable(False, False)

        self._build_ui()
        self._populate_fields()

    def _build_ui(self) -> None:
        """Construct input form."""
        pad_x = 18
        pad_y = 6

        # Preset selector
        preset_frame = ttk.LabelFrame(self, text="Quick Service Preset", padding=10)
        preset_frame.pack(fill="x", padx=pad_x, pady=(12, 6))

        self.combo_preset = ttk.Combobox(
            preset_frame,
            values=list(self.PRESETS.keys()),
            state="readonly",
            width=45
        )
        self.combo_preset.set("Custom (Manual Input)")
        self.combo_preset.bind("<<ComboboxSelected>>", self._on_preset_selected)
        self.combo_preset.pack(fill="x")

        # Form fields frame
        form_frame = ttk.LabelFrame(self, text="Rule Attributes", padding=12)
        form_frame.pack(fill="both", expand=True, padx=pad_x, pady=6)
        form_frame.columnconfigure(1, weight=1)

        row = 0
        # Rule Name
        ttk.Label(form_frame, text="Rule Name:").grid(row=row, column=0, sticky="w", pady=pad_y)
        self.ent_name = ttk.Entry(form_frame)
        self.ent_name.grid(row=row, column=1, sticky="ew", pady=pad_y, padx=(5, 0))

        row += 1
        # Protocol
        ttk.Label(form_frame, text="Protocol:").grid(row=row, column=0, sticky="w", pady=pad_y)
        self.combo_proto = ttk.Combobox(form_frame, values=["TCP", "UDP", "ICMP", "ANY"], state="readonly")
        self.combo_proto.set("TCP")
        self.combo_proto.bind("<<ComboboxSelected>>", self._on_proto_change)
        self.combo_proto.grid(row=row, column=1, sticky="w", pady=pad_y, padx=(5, 0))

        row += 1
        # Source IP
        ttk.Label(form_frame, text="Source IP (or ANY):").grid(row=row, column=0, sticky="w", pady=pad_y)
        self.ent_src_ip = ttk.Entry(form_frame)
        self.ent_src_ip.grid(row=row, column=1, sticky="ew", pady=pad_y, padx=(5, 0))

        row += 1
        # Destination IP
        ttk.Label(form_frame, text="Destination IP (or ANY):").grid(row=row, column=0, sticky="w", pady=pad_y)
        self.ent_dst_ip = ttk.Entry(form_frame)
        self.ent_dst_ip.grid(row=row, column=1, sticky="ew", pady=pad_y, padx=(5, 0))

        row += 1
        # Source Port
        ttk.Label(form_frame, text="Source Port (or ANY):").grid(row=row, column=0, sticky="w", pady=pad_y)
        self.ent_src_port = ttk.Entry(form_frame)
        self.ent_src_port.grid(row=row, column=1, sticky="ew", pady=pad_y, padx=(5, 0))

        row += 1
        # Destination Port
        ttk.Label(form_frame, text="Destination Port (or ANY):").grid(row=row, column=0, sticky="w", pady=pad_y)
        self.ent_dst_port = ttk.Entry(form_frame)
        self.ent_dst_port.grid(row=row, column=1, sticky="ew", pady=pad_y, padx=(5, 0))

        row += 1
        # Action
        ttk.Label(form_frame, text="Action:").grid(row=row, column=0, sticky="w", pady=pad_y)
        self.combo_action = ttk.Combobox(form_frame, values=["ALLOW", "BLOCK"], state="readonly")
        self.combo_action.set("ALLOW")
        self.combo_action.grid(row=row, column=1, sticky="w", pady=pad_y, padx=(5, 0))

        row += 1
        # Enabled checkbox
        self.var_enabled = tk.BooleanVar(value=True)
        self.chk_enabled = ttk.Checkbutton(form_frame, text="Rule Enabled (Active in Engine)", variable=self.var_enabled)
        self.chk_enabled.grid(row=row, column=1, sticky="w", pady=pad_y, padx=(5, 0))

        # Action buttons
        btn_frame = ttk.Frame(self)
        btn_frame.pack(fill="x", padx=pad_x, pady=(6, 14))

        self.btn_save = ttk.Button(btn_frame, text="💾 Save Rule", command=self._save)
        self.btn_save.pack(side="right", padx=(8, 0))

        self.btn_cancel = ttk.Button(btn_frame, text="Cancel", command=self.destroy)
        self.btn_cancel.pack(side="right")

    def _populate_fields(self) -> None:
        """Pre-fill fields if editing existing rule."""
        if self.rule:
            self.ent_name.insert(0, self.rule.name)
            self.combo_proto.set(self.rule.protocol)
            self.ent_src_ip.insert(0, self.rule.src_ip)
            self.ent_dst_ip.insert(0, self.rule.dst_ip)
            self.ent_src_port.insert(0, self.rule.src_port)
            self.ent_dst_port.insert(0, self.rule.dst_port)
            self.combo_action.set(self.rule.action)
            self.var_enabled.set(self.rule.enabled)
        else:
            self.ent_name.insert(0, "New Rule")
            self.ent_src_ip.insert(0, "ANY")
            self.ent_dst_ip.insert(0, "ANY")
            self.ent_src_port.insert(0, "ANY")
            self.ent_dst_port.insert(0, "80")

    def _on_proto_change(self, event=None) -> None:
        """Handle ICMP port field disabling."""
        proto = self.combo_proto.get().upper()
        if proto == "ICMP":
            self.ent_src_port.delete(0, tk.END)
            self.ent_src_port.insert(0, "ANY")
            self.ent_dst_port.delete(0, tk.END)
            self.ent_dst_port.insert(0, "ANY")
            self.ent_src_port.config(state="disabled")
            self.ent_dst_port.config(state="disabled")
        else:
            self.ent_src_port.config(state="normal")
            self.ent_dst_port.config(state="normal")

    def _on_preset_selected(self, event=None) -> None:
        """Apply preset template values."""
        key = self.combo_preset.get()
        data = self.PRESETS.get(key)
        if not data:
            return

        self.ent_name.delete(0, tk.END)
        self.ent_name.insert(0, data["name"])

        self.combo_proto.set(data["proto"])
        self._on_proto_change()

        self.ent_src_ip.delete(0, tk.END)
        self.ent_src_ip.insert(0, data["src_ip"])

        self.ent_dst_ip.delete(0, tk.END)
        self.ent_dst_ip.insert(0, data["dst_ip"])

        if data["proto"] != "ICMP":
            self.ent_src_port.delete(0, tk.END)
            self.ent_src_port.insert(0, data["src_port"])

            self.ent_dst_port.delete(0, tk.END)
            self.ent_dst_port.insert(0, data["dst_port"])

        self.combo_action.set(data["action"])

    def _save(self) -> None:
        """Validate input and save result."""
        data = {
            "name": self.ent_name.get().strip(),
            "protocol": self.combo_proto.get().strip().upper(),
            "src_ip": self.ent_src_ip.get().strip() or "ANY",
            "dst_ip": self.ent_dst_ip.get().strip() or "ANY",
            "src_port": self.ent_src_port.get().strip() or "ANY",
            "dst_port": self.ent_dst_port.get().strip() or "ANY",
            "action": self.combo_action.get().strip().upper(),
            "enabled": self.var_enabled.get(),
        }

        # Validate with RuleManager helper
        dummy_mgr = RuleManager.__new__(RuleManager)
        ok, msg = dummy_mgr.validate_rule_data(data)
        if not ok:
            messagebox.showerror("Validation Error", msg, parent=self)
            return

        self.result = data
        self.destroy()


class RulesView(ttk.Frame):
    """Rule management table and controls."""

    def __init__(self, parent: tk.Widget, rule_manager: RuleManager, on_rules_changed: Optional[Any] = None):
        super().__init__(parent)
        self.rule_manager = rule_manager
        self.on_rules_changed = on_rules_changed

        self._build_ui()
        self.refresh()

    def _build_ui(self) -> None:
        """Construct table, toolbar, and ordering controls."""
        self.columnconfigure(0, weight=1)
        self.rowconfigure(1, weight=1)

        # 1. Top Information Banner
        info_frame = tk.Frame(self, bg="#eff6ff", bd=1, relief="solid")
        info_frame.grid(row=0, column=0, sticky="ew", padx=15, pady=(12, 6))

        tk.Label(
            info_frame,
            text="ℹ️ Rules are evaluated sequentially from top to bottom (Priority Order: First Matching Rule Wins).\n"
                 "Use the 'Move Up' and 'Move Down' buttons to adjust rule priority.",
            font=("Segoe UI", 9),
            bg="#eff6ff",
            fg="#1e40af",
            justify="left",
            padx=10,
            pady=8
        ).pack(anchor="w")

        # 2. Main Center Body: Treeview table + Priority Buttons on right
        center_frame = ttk.Frame(self)
        center_frame.grid(row=1, column=0, sticky="nsew", padx=15, pady=6)
        center_frame.columnconfigure(0, weight=1)
        center_frame.rowconfigure(0, weight=1)

        cols = ("id", "enabled", "name", "proto", "src_ip", "src_p", "dst_ip", "dst_p", "action")
        self.tree_rules = ttk.Treeview(center_frame, columns=cols, show="headings", selectmode="browse")

        self.tree_rules.heading("id", text="# ID")
        self.tree_rules.heading("enabled", text="Status")
        self.tree_rules.heading("name", text="Rule Description")
        self.tree_rules.heading("proto", text="Protocol")
        self.tree_rules.heading("src_ip", text="Source IP")
        self.tree_rules.heading("src_p", text="Src Port")
        self.tree_rules.heading("dst_ip", text="Dest IP")
        self.tree_rules.heading("dst_p", text="Dst Port")
        self.tree_rules.heading("action", text="Action")

        self.tree_rules.column("id", width=45, anchor="center")
        self.tree_rules.column("enabled", width=70, anchor="center")
        self.tree_rules.column("name", width=190, anchor="w")
        self.tree_rules.column("proto", width=65, anchor="center")
        self.tree_rules.column("src_ip", width=120, anchor="center")
        self.tree_rules.column("src_p", width=65, anchor="center")
        self.tree_rules.column("dst_ip", width=120, anchor="center")
        self.tree_rules.column("dst_p", width=65, anchor="center")
        self.tree_rules.column("action", width=85, anchor="center")

        # Tags styling
        self.tree_rules.tag_configure("tag_allow", foreground="#15803d", font=("Segoe UI", 9, "bold"))
        self.tree_rules.tag_configure("tag_block", foreground="#b91c1c", font=("Segoe UI", 9, "bold"))
        self.tree_rules.tag_configure("tag_disabled", foreground="#94a3b8")

        scroll_y = ttk.Scrollbar(center_frame, orient="vertical", command=self.tree_rules.yview)
        self.tree_rules.configure(yscrollcommand=scroll_y.set)

        self.tree_rules.grid(row=0, column=0, sticky="nsew")
        scroll_y.grid(row=0, column=1, sticky="ns")

        # Priority Reordering Strip on the right
        prio_frame = ttk.Frame(center_frame)
        prio_frame.grid(row=0, column=2, sticky="ns", padx=(8, 0))

        ttk.Label(prio_frame, text="Priority", font=("Segoe UI", 8, "bold"), foreground="#64748b").pack(pady=(5, 4))
        self.btn_up = ttk.Button(prio_frame, text="▲ Up", width=8, command=self._move_up)
        self.btn_up.pack(pady=3)
        self.btn_down = ttk.Button(prio_frame, text="▼ Down", width=8, command=self._move_down)
        self.btn_down.pack(pady=3)

        # Double click to edit
        self.tree_rules.bind("<Double-1>", lambda e: self._edit_selected_rule())

        # 3. Bottom Toolbar
        toolbar = ttk.Frame(self)
        toolbar.grid(row=2, column=0, sticky="ew", padx=15, pady=(8, 14))

        # Left action buttons
        self.btn_add = ttk.Button(toolbar, text="➕ Add Rule", command=self._add_rule)
        self.btn_add.pack(side="left", padx=(0, 6))

        self.btn_edit = ttk.Button(toolbar, text="✏️ Edit Rule", command=self._edit_selected_rule)
        self.btn_edit.pack(side="left", padx=6)

        self.btn_toggle = ttk.Button(toolbar, text="🔘 Toggle Enable/Disable", command=self._toggle_rule)
        self.btn_toggle.pack(side="left", padx=6)

        self.btn_delete = ttk.Button(toolbar, text="🗑️ Delete Rule", command=self._delete_rule)
        self.btn_delete.pack(side="left", padx=6)

        # Right action buttons
        self.btn_reset = ttk.Button(toolbar, text="🔄 Reset Defaults", command=self._reset_defaults)
        self.btn_reset.pack(side="right")

    def _get_selected_rule_id(self) -> Optional[int]:
        """Return rule ID of currently highlighted row, or None."""
        selected = self.tree_rules.selection()
        if not selected:
            return None
        item_vals = self.tree_rules.item(selected[0], "values")
        if item_vals:
            return int(item_vals[0])
        return None

    def _add_rule(self) -> None:
        """Open dialog to add a new rule."""
        dlg = RuleEditDialog(self)
        self.wait_window(dlg)
        if dlg.result:
            ok, msg, rule = self.rule_manager.add_rule(dlg.result)
            if ok:
                self.refresh()
                self._notify_change()
            else:
                messagebox.showerror("Error", msg)

    def _edit_selected_rule(self) -> None:
        """Open dialog to edit highlighted rule."""
        rule_id = self._get_selected_rule_id()
        if rule_id is None:
            messagebox.showinfo("Select Rule", "Please select a rule from the table to edit.")
            return

        rule = next((r for r in self.rule_manager.get_rules() if r.id == rule_id), None)
        if not rule:
            return

        dlg = RuleEditDialog(self, rule=rule)
        self.wait_window(dlg)
        if dlg.result:
            ok, msg = self.rule_manager.update_rule(rule_id, dlg.result)
            if ok:
                self.refresh()
                self._notify_change()
            else:
                messagebox.showerror("Error", msg)

    def _toggle_rule(self) -> None:
        """Toggle active status of selected rule."""
        rule_id = self._get_selected_rule_id()
        if rule_id is None:
            messagebox.showinfo("Select Rule", "Please select a rule to toggle.")
            return

        self.rule_manager.toggle_rule(rule_id)
        self.refresh()
        self._notify_change()

    def _delete_rule(self) -> None:
        """Delete selected rule after confirmation."""
        rule_id = self._get_selected_rule_id()
        if rule_id is None:
            messagebox.showinfo("Select Rule", "Please select a rule to delete.")
            return

        if messagebox.askyesno("Confirm Delete", f"Are you sure you want to delete Rule #{rule_id}?"):
            if self.rule_manager.delete_rule(rule_id):
                self.refresh()
                self._notify_change()

    def _move_up(self) -> None:
        """Shift selected rule higher in priority."""
        rule_id = self._get_selected_rule_id()
        if rule_id is not None:
            if self.rule_manager.move_rule_up(rule_id):
                self.refresh()
                self._reselect_id(rule_id)
                self._notify_change()

    def _move_down(self) -> None:
        """Shift selected rule lower in priority."""
        rule_id = self._get_selected_rule_id()
        if rule_id is not None:
            if self.rule_manager.move_rule_down(rule_id):
                self.refresh()
                self._reselect_id(rule_id)
                self._notify_change()

    def _reselect_id(self, rule_id: int) -> None:
        """Keep the moved item selected in Treeview."""
        for item in self.tree_rules.get_children():
            vals = self.tree_rules.item(item, "values")
            if vals and int(vals[0]) == rule_id:
                self.tree_rules.selection_set(item)
                self.tree_rules.focus(item)
                break

    def _reset_defaults(self) -> None:
        """Reset rule table to standard initial educational rules."""
        if messagebox.askyesno("Reset to Defaults", "Reset all firewall rules to standard default sample rules?"):
            self.rule_manager.reset_to_defaults()
            self.refresh()
            self._notify_change()

    def _notify_change(self) -> None:
        """Call external listener if registered."""
        if callable(self.on_rules_changed):
            self.on_rules_changed()

    def refresh(self) -> None:
        """Reload and repaint rules table."""
        # Save selection
        sel_id = self._get_selected_rule_id()

        for item in self.tree_rules.get_children():
            self.tree_rules.delete(item)

        rules = self.rule_manager.get_rules()
        for r in rules:
            status_text = "ENABLED" if r.enabled else "DISABLED"
            tag = "tag_disabled" if not r.enabled else ("tag_allow" if r.action == "ALLOW" else "tag_block")

            item = self.tree_rules.insert(
                "",
                "end",
                values=(r.id, status_text, r.name, r.protocol, r.src_ip, r.src_port, r.dst_ip, r.dst_port, r.action),
                tags=(tag,)
            )

            if sel_id is not None and r.id == sel_id:
                self.tree_rules.selection_set(item)
                self.tree_rules.focus(item)
