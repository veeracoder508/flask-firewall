# Copyright 2026 R A Veeraragavan

# Permission is hereby granted, free of charge, to any person obtaining a copy of this
# software and associated documentation files (the “Software”), to deal in the Software 
# without restriction, including without limitation the rights to use, copy, modify, merge, 
# publish, distribute, sublicense, and/or sell copies of the Software, and to permit 
# persons to whom the Software is furnished to do so, subject to the following conditions:

# The above copyright notice and this permission notice shall be included in all copies or
# substantial portions of the Software.

# THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING
# BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND 
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, 
# DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, 
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import threading
import os
import time
import json
from datetime import datetime

# --- Theme Constants ---
BG_DARK = "#0d1117"
BG_SURFACE = "#161b22"
ACCENT = "#58a6ff"
SUCCESS = "#3fb950"
DANGER = "#f85149"
WARNING = "#d29922"
TEXT_PRIMARY = "#c9d1d9"
BORDER = "#30363d"

class StatCard(tk.Frame):
    def __init__(self, parent, title, color):
        super().__init__(parent, bg=BG_SURFACE, highlightbackground=BORDER, highlightthickness=1, bd=0)
        self.title_label = tk.Label(self, text=title, bg=BG_SURFACE, fg=TEXT_PRIMARY, font=("Segoe UI", 9))
        self.title_label.pack(pady=(10, 0))
        self.value_label = tk.Label(self, text="0", bg=BG_SURFACE, fg=color, font=("Segoe UI", 20, "bold"))
        self.value_label.pack(pady=(0, 10))

    def update_value(self, value):
        self.value_label.config(text=str(value))

class SentinelMonitor(tk.Tk):
    def __init__(self, firewall_instance):
        super().__init__()
        self.fw = firewall_instance
        self.title(f"Sentinel SOC ({self.fw.server_name})")
        self.geometry("1100x750")
        self.configure(bg=BG_DARK)

        # 1. Initialize variables
        self.running = True
        self.allowed_count = 0
        self.dropped_count = 0
        self.log_file = f"{firewall_instance.server_name}_firewall.log"

        # 2. Setup UI
        self.setup_styles()
        self.init_ui()
        
        # 3. Start loops
        self.update_performance_stats()
        self.log_thread = threading.Thread(target=self.poll_logs, daemon=True)
        self.after(100, self.log_thread.start)
        
        self.protocol("WM_DELETE_WINDOW", self.on_close)

    def setup_styles(self):
        style = ttk.Style()
        style.theme_use('clam')
        style.configure("TNotebook", background=BG_DARK, borderwidth=0)
        style.configure("TNotebook.Tab", background=BG_SURFACE, foreground=TEXT_PRIMARY, padding=[20, 10])
        style.map("TNotebook.Tab", background=[("selected", ACCENT)], foreground=[("selected", BG_DARK)])
        style.configure("Treeview", background=BG_SURFACE, foreground=TEXT_PRIMARY, fieldbackground=BG_SURFACE)
        style.configure("Treeview.Heading", background=BG_SURFACE, foreground=TEXT_PRIMARY)

    def init_ui(self):
        header = tk.Frame(self, bg=BG_SURFACE, height=60)
        header.pack(fill="x", side="top")
        header.pack_propagate(False)
        tk.Label(header, text=f"SENTINEL SOC - {self.fw.server_name.upper()}", bg=BG_SURFACE, fg=ACCENT, font=("Segoe UI", 14, "bold")).pack(side="left", padx=20)

        self.tabs = ttk.Notebook(self)
        self.tabs.pack(fill="both", expand=True, padx=10, pady=10)

        self.logs_tab = tk.Frame(self.tabs, bg=BG_DARK)
        self.perf_tab = tk.Frame(self.tabs, bg=BG_DARK)
        self.assets_tab = tk.Frame(self.tabs, bg=BG_DARK)
        self.auto_tab = tk.Frame(self.tabs, bg=BG_DARK)

        self.tabs.add(self.logs_tab, text=" Live Traffic ")
        self.tabs.add(self.perf_tab, text=" Performance ")
        self.tabs.add(self.assets_tab, text=" Security Policy ")
        self.tabs.add(self.auto_tab, text=" Automation ")

        self.setup_logs_tab()
        self.setup_performance_tab()
        self.setup_assets_tab()
        self.setup_automation_tab()

    def setup_logs_tab(self):
        stats_frame = tk.Frame(self.logs_tab, bg=BG_DARK)
        stats_frame.pack(fill="x", pady=10)
        self.allowed_card = StatCard(stats_frame, "TOTAL ALLOWED", SUCCESS)
        self.allowed_card.pack(side="left", expand=True, fill="both", padx=5)
        self.dropped_card = StatCard(stats_frame, "TOTAL DROPPED", DANGER)
        self.dropped_card.pack(side="left", expand=True, fill="both", padx=5)

        self.log_display = scrolledtext.ScrolledText(self.logs_tab, bg=BG_SURFACE, fg=TEXT_PRIMARY, font=("Consolas", 11))
        self.log_display.pack(fill="both", expand=True, pady=10)
        self.log_display.tag_config("SUCCESS", foreground=SUCCESS)
        self.log_display.tag_config("DANGER", foreground=DANGER, font=("Consolas", 11, "bold"))
        self.log_display.tag_config("WARNING", foreground=WARNING)

    def setup_performance_tab(self):
        self.cpu_card = StatCard(self.perf_tab, "PROCESS CPU LOAD", ACCENT)
        self.cpu_card.pack(fill="x", pady=10, padx=20)
        self.mem_card = StatCard(self.perf_tab, "MEMORY USAGE (RAM)", ACCENT)
        self.mem_card.pack(fill="x", pady=10, padx=20)

    def update_performance_stats(self):
        """Fetches real data from the firewall instance."""
        if not self.running: return
        try:
            from .firewall import get_stats
            stats = get_stats(self.fw)
            self.cpu_card.update_value(f"{stats['cpu_percent']}%")
            self.mem_card.update_value(f"{stats['ram_mb']} MB")
        except Exception as e:
            print(f"Stats Error: {e}")
        self.after(2000, self.update_performance_stats)

    def setup_assets_tab(self):
        cols = ("ID", "Description", "Source CIDR", "Action")
        self.asset_table = ttk.Treeview(self.assets_tab, columns=cols, show="headings")
        for col in cols: 
            self.asset_table.heading(col, text=col)
            self.asset_table.column(col, width=150)
        self.asset_table.pack(fill="both", expand=True, padx=10, pady=10)
        self.refresh_rules()

    def refresh_rules(self):
        for item in self.asset_table.get_children(): self.asset_table.delete(item)
        for i, rule in enumerate(self.fw.engine.rules): 
            self.asset_table.insert("", "end", values=(i + 1, rule.desc, str(rule.src_net), rule.action))

    def setup_automation_tab(self):
        container = tk.Frame(self.auto_tab, bg=BG_SURFACE, highlightbackground=BORDER, highlightthickness=1, padx=30, pady=30)
        container.place(relx=0.5, rely=0.5, anchor="center")
        tk.Button(container, text="GENERATE AUDIT REPORT", bg=SUCCESS, fg="white", command=self.handle_report).pack(fill="x", pady=5)

    def handle_report(self):
        report = {"stats": self.fw.stats, "rules": len(self.fw.engine.rules)}
        with open("audit.json", "w") as f: json.dump(report, f)
        messagebox.showinfo("Success", "Report saved to audit.json")

    def poll_logs(self):
        if not os.path.exists(self.log_file):
            open(self.log_file, "a").close()
        
        with open(self.log_file, "r") as f:
            f.seek(0, 2) # Start at end of file
            while self.running:
                line = f.readline()
                if not line:
                    time.sleep(0.1)
                    continue
                self.after(0, self.process_log_line, line.strip())

    def process_log_line(self, line):
        tag = "SUCCESS" if "ALLOW" in line else "DANGER" if "DROP" in line else None
        if tag == "SUCCESS": self.allowed_count += 1
        if tag == "DANGER": self.dropped_count += 1
        
        self.allowed_card.update_value(self.allowed_count)
        self.dropped_card.update_value(self.dropped_count)
        self.log_display.insert("end", line + "\n", tag)
        self.log_display.see("end")

    def on_close(self):
        self.running = False
        self.destroy()