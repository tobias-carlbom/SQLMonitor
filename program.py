#!/usr/bin/env python3
"""
SQL Server Query Monitor - Unified Version
Supports both Extended Events (requires permissions) and DMV mode (legacy)
"""

import time
import csv
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from datetime import datetime
import threading
from pathlib import Path
import xml.etree.ElementTree as ET

try:
    import pyodbc
except ImportError as e:
    print(f"ERROR: Failed to import pyodbc: {e}")
    print("Install with: pip install pyodbc")
    exit(1)

POLL_INTERVAL = 0.5
POLL_INTERVAL_DMV = 1.0
MIN_DURATION_MS = 0
FADE_DURATION = 3.0
MAX_QUERY_PREVIEW = 200


class SQLMonitorGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("SQL Server Query Monitor")
        self.root.geometry("1200x800")

        self.conn = None
        self.monitoring = False
        self.monitor_thread = None
        self.session_name = "PythonQueryMonitor"
        self.monitor_session_id = None

        self.query_lookup = {}
        self.highlight_items = {}
        self.item_counter = 0
        self.query_data = []
        self.seen_queries = {}

        self.setup_gui()
        self.center_window()

        self.fade_thread = threading.Thread(target=self.fade_highlights_loop, daemon=True)
        self.fade_thread.start()

    def center_window(self):
        self.root.update_idletasks()
        width = self.root.winfo_width()
        height = self.root.winfo_height()
        x = (self.root.winfo_screenwidth() // 2) - (width // 2)
        y = (self.root.winfo_screenheight() // 2) - (height // 2)
        self.root.geometry(f"{width}x{height}+{x}+{y}")

    def setup_gui(self):
        self.create_config_frame()
        self.create_control_frame()
        self.create_output_frame()

        fade_colors = ["#ffff99", "#ffffaa", "#ffffbb", "#ffffcc", "#ffffdd", "#ffffee"]
        for i, color in enumerate(fade_colors):
            self.query_table.tag_configure(f"highlight_{i}", background=color)

    def create_config_frame(self):
        config_frame = ttk.LabelFrame(self.root, text="Configuration", padding="10")
        config_frame.pack(fill="x", padx=10, pady=5)

        ttk.Label(config_frame, text="SQL Server:").grid(row=0, column=0, sticky="w", padx=5, pady=2)
        self.config_vars = {}
        self.config_vars["server"] = tk.StringVar(value="localhost")
        ttk.Entry(config_frame, textvariable=self.config_vars["server"], width=25).grid(
            row=0, column=1, sticky="w", padx=5, pady=2
        )

        ttk.Label(config_frame, text="Database:").grid(row=0, column=2, sticky="w", padx=(20, 5), pady=2)
        self.config_vars["database"] = tk.StringVar(value="master")
        ttk.Entry(config_frame, textvariable=self.config_vars["database"], width=20).grid(
            row=0, column=3, sticky="w", padx=5, pady=2
        )

        ttk.Label(config_frame, text="Username:").grid(row=1, column=0, sticky="w", padx=5, pady=2)
        self.config_vars["username"] = tk.StringVar(value="")
        ttk.Entry(config_frame, textvariable=self.config_vars["username"], width=25).grid(
            row=1, column=1, sticky="w", padx=5, pady=2
        )

        ttk.Label(config_frame, text="Password:").grid(row=1, column=2, sticky="w", padx=(20, 5), pady=2)
        self.config_vars["password"] = tk.StringVar(value="")
        ttk.Entry(config_frame, textvariable=self.config_vars["password"], width=20, show="*").grid(
            row=1, column=3, sticky="w", padx=5, pady=2
        )

        self.use_windows_auth = tk.BooleanVar(value=True)
        ttk.Checkbutton(
            config_frame,
            text="Use Windows Authentication",
            variable=self.use_windows_auth,
        ).grid(row=2, column=0, columnspan=2, sticky="w", padx=5, pady=2)

        legacy_frame = ttk.Frame(config_frame)
        legacy_frame.grid(row=2, column=2, columnspan=2, sticky="w", padx=(20, 5), pady=2)

        self.use_legacy_mode = tk.BooleanVar(value=False)
        self.legacy_checkbox = ttk.Checkbutton(
            legacy_frame,
            text="Use Legacy Mode (DMV - no Extended Events)",
            variable=self.use_legacy_mode,
            command=self.on_legacy_mode_changed,
        )
        self.legacy_checkbox.pack(side="left")

        info_btn = ttk.Button(legacy_frame, text="?", width=3, command=self.show_mode_info)
        info_btn.pack(side="left", padx=5)

        self.show_system_queries = tk.BooleanVar(value=False)
        ttk.Checkbutton(
            config_frame,
            text="Show System Queries",
            variable=self.show_system_queries,
        ).grid(row=3, column=0, columnspan=2, sticky="w", padx=5, pady=2)

        self.mode_label = ttk.Label(config_frame, text="Mode: Extended Events", foreground="green")
        self.mode_label.grid(row=3, column=2, columnspan=2, sticky="w", padx=(20, 5), pady=2)

        ttk.Label(config_frame, text="Query Filter:").grid(row=4, column=0, sticky="w", padx=5, pady=2)
        self.query_filter_var = tk.StringVar()
        filter_entry = ttk.Entry(config_frame, textvariable=self.query_filter_var, width=60)
        filter_entry.grid(row=4, column=1, columnspan=3, padx=5, pady=2, sticky="ew")

        self.encrypt_connection = tk.BooleanVar(value=False)
        self.trust_server_cert = tk.BooleanVar(value=True)

        ttk.Checkbutton(
            config_frame,
            text="Encrypt connection (TLS)",
            variable=self.encrypt_connection,
        ).grid(row=5, column=0, columnspan=2, sticky="w", padx=5, pady=2)

        ttk.Checkbutton(
            config_frame,
            text="Trust server certificate (skip validation)",
            variable=self.trust_server_cert,
        ).grid(row=5, column=2, columnspan=2, sticky="w", padx=(20, 5), pady=2)

        config_frame.grid_columnconfigure(3, weight=1)

    def on_legacy_mode_changed(self):
        if self.use_legacy_mode.get():
            self.mode_label.config(text="Mode: Legacy (DMV)", foreground="blue")
        else:
            self.mode_label.config(text="Mode: Extended Events", foreground="green")

    def show_mode_info(self):
        info_text = """MONITORING MODES:

Extended Events Mode (Default):
• Captures ALL completed queries
• Provides most complete monitoring
• Requires ALTER ANY EVENT SESSION permission
• If you get permission errors, ask your DBA to run:
  GRANT ALTER ANY EVENT SESSION TO [your_username]

Legacy Mode (DMV):
• Uses Dynamic Management Views
• Captures only ACTIVE queries
• Works with standard VIEW SERVER STATE permission
• Good alternative if Extended Events permissions unavailable

Recommendation:
Try Extended Events first. If you get permission errors,
enable Legacy Mode to use DMV-based monitoring."""
        messagebox.showinfo("Monitoring Modes", info_text)

    def create_control_frame(self):
        button_frame = ttk.Frame(self.root)
        button_frame.pack(fill="x", padx=10, pady=5)

        self.start_button = ttk.Button(button_frame, text="Start Monitoring", command=self.start_monitoring)
        self.start_button.pack(side="left", padx=5)

        self.stop_button = ttk.Button(button_frame, text="Stop Monitoring", command=self.stop_monitoring, state="disabled")
        self.stop_button.pack(side="left", padx=5)

        ttk.Button(button_frame, text="Clear", command=self.clear_output).pack(side="left", padx=5)
        ttk.Button(button_frame, text="Export CSV", command=self.export_csv).pack(side="left", padx=5)

        self.status_var = tk.StringVar(value="Ready")
        ttk.Label(button_frame, textvariable=self.status_var, foreground="blue").pack(side="left", padx=20)

        self.query_count_var = tk.StringVar(value="Queries: 0")
        ttk.Label(button_frame, textvariable=self.query_count_var).pack(side="right", padx=5)

    def create_output_frame(self):
        output_frame = ttk.LabelFrame(self.root, text="Query Trace", padding="5")
        output_frame.pack(fill="both", expand=True, padx=10, pady=5)

        paned = ttk.PanedWindow(output_frame, orient=tk.VERTICAL)
        paned.pack(fill="both", expand=True)

        top_frame = ttk.Frame(paned)
        paned.add(top_frame, weight=3)

        columns = ("Time", "SID", "Database", "User", "Duration", "CPU", "Reads", "Query")
        self.query_table = ttk.Treeview(top_frame, columns=columns, show="headings", height=15)

        col_config = [
            ("Time", 180, "w"),
            ("SID", 50, "center"),
            ("Database", 120, "w"),
            ("User", 100, "w"),
            ("Duration", 100, "e"),
            ("CPU", 80, "e"),
            ("Reads", 80, "e"),
            ("Query", 500, "w"),
        ]

        for col, width, anchor in col_config:
            suffix = " (ms)" if col in ["Duration", "CPU"] else ""
            self.query_table.heading(col, text=col + suffix)
            self.query_table.column(col, width=width, anchor=anchor)

        v_scroll = ttk.Scrollbar(top_frame, orient="vertical", command=self.query_table.yview)
        h_scroll = ttk.Scrollbar(top_frame, orient="horizontal", command=self.query_table.xview)
        self.query_table.configure(yscrollcommand=v_scroll.set, xscrollcommand=h_scroll.set)

        self.query_table.grid(row=0, column=0, sticky="nsew")
        v_scroll.grid(row=0, column=1, sticky="ns")
        h_scroll.grid(row=1, column=0, sticky="ew")

        top_frame.grid_rowconfigure(0, weight=1)
        top_frame.grid_columnconfigure(0, weight=1)

        self.query_table.bind("<<TreeviewSelect>>", self.on_table_select)

        bottom_frame = ttk.LabelFrame(paned, text="Query Text", padding="5")
        paned.add(bottom_frame, weight=1)

        self.query_text = tk.Text(bottom_frame, wrap=tk.WORD, height=8, font=("Courier", 9), bg="#f5f5f5")
        query_scroll = ttk.Scrollbar(bottom_frame, orient="vertical", command=self.query_text.yview)
        self.query_text.configure(yscrollcommand=query_scroll.set)

        self.query_text.pack(side="left", fill="both", expand=True)
        query_scroll.pack(side="right", fill="y")

    def on_table_select(self, event=None):
        try:
            selection = self.query_table.selection()
            if selection and selection[0] in self.query_lookup:
                self.query_text.delete(1.0, tk.END)
                self.query_text.insert(1.0, self.query_lookup[selection[0]])
        except Exception:
            pass

    def fade_highlights_loop(self):
        fade_steps = 5
        while True:
            try:
                time.sleep(0.1)
                current_time = time.time()
                for item_id, timestamp in list(self.highlight_items.items()):
                    elapsed = current_time - timestamp
                    if elapsed >= FADE_DURATION:
                        self.root.after(0, lambda id=item_id: self.update_highlight(id, None))
                        del self.highlight_items[item_id]
                    else:
                        step = int((elapsed / FADE_DURATION) * fade_steps)
                        self.root.after(0, lambda id=item_id, s=step: self.update_highlight(id, s))
            except Exception:
                time.sleep(0.5)

    def update_highlight(self, item_id, step):
        try:
            if self.query_table.exists(item_id):
                tags = (f"highlight_{step}",) if step is not None else ()
                self.query_table.item(item_id, tags=tags)
        except Exception:
            pass

    def add_query_row(self, data):
        def insert():
            try:
                self.item_counter += 1
                item_id = f"item_{self.item_counter}"
                values = (
                    data["timestamp"],
                    data["session_id"],
                    data["database"],
                    data["username"],
                    f"{data['duration']:.1f}",
                    f"{data['cpu']:.1f}",
                    data["reads"],
                    data["preview"],
                )
                self.query_table.insert("", "end", iid=item_id, values=values, tags=("highlight_0",))
                self.highlight_items[item_id] = time.time()
                self.query_lookup[item_id] = data["full_query"]
                self.query_table.selection_set(item_id)
                self.query_table.see(item_id)
                self.query_text.delete(1.0, tk.END)
                self.query_text.insert(1.0, data["full_query"])
                self.query_count_var.set(f"Queries: {len(self.query_data)}")
            except Exception as e:
                print(f"Error adding row: {e}")

        self.root.after(0, insert)

    def log_message(self, message, msg_type="INFO"):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        if "[ERROR]" in message or msg_type == "ERROR":
            msg_type = "ERROR"
            clean_msg = message.replace("[ERROR] ", "")
        elif "[WARNING]" in message or msg_type == "WARNING":
            msg_type = "WARNING"
            clean_msg = message.replace("[WARNING] ", "")
        else:
            msg_type = "INFO"
            clean_msg = message.replace("[INFO] ", "")
        self.item_counter += 1
        item_id = f"info_{self.item_counter}"

        def insert():
            try:
                self.query_table.insert(
                    "",
                    "end",
                    iid=item_id,
                    values=(timestamp, "-", msg_type, "-", "-", "-", "-", clean_msg),
                )
            except Exception:
                pass

        self.root.after(0, insert)

    def clear_output(self):
        for item in self.query_table.get_children():
            self.query_table.delete(item)
        self.query_lookup.clear()
        self.highlight_items.clear()
        self.query_text.delete(1.0, tk.END)
        self.query_data.clear()
        self.seen_queries.clear()
        self.query_count_var.set("Queries: 0")

    def export_csv(self):
        if not self.query_data:
            messagebox.showinfo("Info", "No queries to export")
            return
        file_path = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")],
            initialfile=f"sql_queries_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
        )
        if file_path:
            try:
                with open(file_path, "w", newline="", encoding="utf-8") as f:
                    writer = csv.writer(f, delimiter=";")
                    writer.writerow(
                        [
                            "timestamp",
                            "session_id",
                            "database",
                            "username",
                            "duration_ms",
                            "cpu_ms",
                            "reads",
                            "writes",
                            "query",
                        ]
                    )
                    for row in self.query_data:
                        writer.writerow(
                            [
                                row["timestamp"],
                                row["session_id"],
                                row["database"],
                                row["username"],
                                row["duration"],
                                row["cpu"],
                                row["reads"],
                                row.get("writes", 0),
                                row["full_query"],
                            ]
                        )
                messagebox.showinfo("Success", f"Exported {len(self.query_data)} queries to {file_path}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to export: {str(e)}")

    def validate_config(self):
        if not self.config_vars["server"].get():
            messagebox.showerror("Error", "Server name is required")
            return False
        if not self.config_vars["database"].get():
            messagebox.showerror("Error", "Database name is required")
            return False
        if not self.use_windows_auth.get():
            if not self.config_vars["username"].get():
                messagebox.showerror("Error", "Username is required for SQL authentication")
                return False
        return True

    def detect_sql_server_driver(self):
        drivers = [d for d in pyodbc.drivers() if "SQL Server" in d]
        if not drivers:
            raise RuntimeError(
                "No SQL Server ODBC driver found. Install 'ODBC Driver 18 for SQL Server' or 'ODBC Driver 17 for SQL Server'."
            )
        preferred = ["ODBC Driver 18 for SQL Server", "ODBC Driver 17 for SQL Server", "SQL Server"]
        for name in preferred:
            if name in drivers:
                return name
        return drivers[-1]

    def get_connection_string(self):
        server = self.config_vars["server"].get()
        database = self.config_vars["database"].get()
        driver = self.detect_sql_server_driver()
        encrypt = "yes" if self.encrypt_connection.get() else "no"
        trust = "yes" if self.trust_server_cert.get() else "no"
        base = (
            f"DRIVER={{{driver}}};SERVER={server};DATABASE={database};"
            f"Encrypt={encrypt};TrustServerCertificate={trust};"
        )
        if self.use_windows_auth.get():
            return base + "Trusted_Connection=yes;"
        else:
            username = self.config_vars["username"].get()
            password = self.config_vars["password"].get()
            return base + f"UID={username};PWD={password};"

    def start_monitoring(self):
        if not self.validate_config():
            return
        self.monitoring = True
        self.start_button.config(state="disabled")
        self.stop_button.config(state="normal")
        self.status_var.set("Monitoring...")
        if self.use_legacy_mode.get():
            self.monitor_thread = threading.Thread(target=self.monitor_loop_dmv, daemon=True)
        else:
            self.monitor_thread = threading.Thread(target=self.monitor_loop_xe, daemon=True)
        self.monitor_thread.start()

    def stop_monitoring(self):
        self.monitoring = False
        self.start_button.config(state="normal")
        self.stop_button.config(state="disabled")
        self.status_var.set("Stopped")

    def setup_xe_session(self, cursor):
        try:
            cursor.execute("SELECT @@SPID as session_id")
            self.monitor_session_id = cursor.fetchone().session_id
            cursor.execute(
                f"IF EXISTS(SELECT * FROM sys.server_event_sessions WHERE name='{self.session_name}') "
                f"DROP EVENT SESSION [{self.session_name}] ON SERVER"
            )
            cursor.commit()
            create_sql = f"""
            CREATE EVENT SESSION [{self.session_name}] ON SERVER 
            ADD EVENT sqlserver.sql_batch_completed(
                ACTION(sqlserver.client_app_name,sqlserver.database_name,sqlserver.session_id,sqlserver.username)
                WHERE sqlserver.session_id != {self.monitor_session_id}
            ),
            ADD EVENT sqlserver.rpc_completed(
                ACTION(sqlserver.client_app_name,sqlserver.database_name,sqlserver.session_id,sqlserver.username)
                WHERE sqlserver.session_id != {self.monitor_session_id}
            )
            ADD TARGET package0.ring_buffer(SET max_memory=4096)
            WITH (MAX_MEMORY=4096 KB,EVENT_RETENTION_MODE=ALLOW_SINGLE_EVENT_LOSS,MAX_DISPATCH_LATENCY=1 SECONDS)
            """
            cursor.execute(create_sql)
            cursor.commit()
            cursor.execute(f"ALTER EVENT SESSION [{self.session_name}] ON SERVER STATE = START")
            cursor.commit()
            return True
        except pyodbc.Error as e:
            error_msg = str(e)
            if "42000" in error_msg:
                self.log_message(
                    "[ERROR] Extended Events requires ALTER ANY EVENT SESSION permission", "ERROR"
                )
                self.log_message(
                    "[ERROR] Ask your DBA to run: GRANT ALTER ANY EVENT SESSION TO [your_username]",
                    "ERROR",
                )
                self.log_message(
                    "[WARNING] Switch to Legacy Mode (DMV) to monitor without Extended Events",
                    "WARNING",
                )
                if messagebox.askyesno(
                    "Permission Error",
                    "Extended Events requires elevated permissions.\n\n"
                    "To fix this, ask your DBA to run:\n"
                    "GRANT ALTER ANY EVENT SESSION TO [your_username]\n\n"
                    "Would you like to switch to Legacy Mode (DMV) instead?",
                ):
                    self.use_legacy_mode.set(True)
                    self.on_legacy_mode_changed()
            else:
                self.log_message(f"[ERROR] Failed to create Extended Events: {error_msg}", "ERROR")
            return False

    def cleanup_xe_session(self, cursor):
        try:
            cursor.execute(
                f"IF EXISTS(SELECT * FROM sys.server_event_sessions WHERE name='{self.session_name}') "
                f"ALTER EVENT SESSION [{self.session_name}] ON SERVER STATE = STOP"
            )
            cursor.execute(
                f"IF EXISTS(SELECT * FROM sys.server_event_sessions WHERE name='{self.session_name}') "
                f"DROP EVENT SESSION [{self.session_name}] ON SERVER"
            )
            cursor.commit()
        except Exception:
            pass

    def monitor_loop_xe(self):
        show_system = self.show_system_queries.get()
        self.log_message(f"[INFO] Connecting to {self.config_vars['server'].get()} (Extended Events Mode)...")
        try:
            self.conn = pyodbc.connect(self.get_connection_string(), timeout=10, autocommit=True)
            cursor = self.conn.cursor()
            self.log_message("[INFO] Connected successfully")
            if not self.setup_xe_session(cursor):
                self.root.after(0, self.stop_monitoring)
                return
            self.log_message(
                f"[INFO] Extended Events monitoring started (Session ID: {self.monitor_session_id})"
            )
            processed_events = set()
            while self.monitoring:
                try:
                    cursor.execute(
                        f"""
                        SELECT CAST(target_data AS XML) as target_data
                        FROM sys.dm_xe_session_targets st
                        JOIN sys.dm_xe_sessions s ON s.address = st.event_session_address
                        WHERE s.name = '{self.session_name}' AND st.target_name = 'ring_buffer'
                        """
                    )
                    row = cursor.fetchone()
                    if row and row.target_data:
                        root = ET.fromstring(row.target_data)
                        for event in root.findall(".//event"):
                            if not self.monitoring:
                                break
                            event_timestamp = event.get("timestamp")
                            if event_timestamp in processed_events:
                                continue
                            processed_events.add(event_timestamp)
                            if len(processed_events) > 10000:
                                processed_events = set(list(processed_events)[-5000:])
                            data = {}
                            for item in event.findall(".//data"):
                                value = item.find("value")
                                if value is not None:
                                    data[item.get("name")] = value.text
                            actions = {}
                            for action in event.findall(".//action"):
                                value = action.find("value")
                                if value is not None:
                                    actions[action.get("name")] = value.text
                            statement = data.get("statement", data.get("batch_text", ""))
                            if not statement:
                                continue
                            query_filter = self.query_filter_var.get().strip()
                            if query_filter and query_filter.lower() not in statement.lower():
                                continue
                            duration_ms = int(data.get("duration", 0)) / 1000.0
                            if duration_ms < MIN_DURATION_MS:
                                continue
                            cpu_ms = int(data.get("cpu_time", 0)) / 1000.0
                            reads = int(data.get("physical_reads", 0)) + int(
                                data.get("logical_reads", 0)
                            )
                            writes = int(data.get("writes", 0))
                            session_id = actions.get("session_id", "N/A")
                            if not show_system:
                                try:
                                    if int(session_id) <= 50:
                                        continue
                                except Exception:
                                    pass
                            query_clean = " ".join(statement.split())
                            query_preview = (
                                query_clean[:80] + "..." if len(query_clean) > 80 else query_clean
                            )
                            query_info = {
                                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
                                "session_id": session_id,
                                "database": actions.get("database_name", "N/A"),
                                "username": actions.get("username", "N/A"),
                                "duration": duration_ms,
                                "cpu": cpu_ms,
                                "reads": reads,
                                "writes": writes,
                                "preview": query_preview,
                                "full_query": statement.strip(),
                            }
                            self.query_data.append(query_info)
                            self.add_query_row(query_info)
                except Exception as e:
                    if self.monitoring:
                        self.log_message(f"[ERROR] {str(e)}", "ERROR")
                time.sleep(POLL_INTERVAL)
        except Exception as e:
            self.log_message(f"[ERROR] Connection failed: {str(e)}", "ERROR")
            messagebox.showerror("Connection Error", str(e))
        finally:
            if self.conn:
                try:
                    cursor = self.conn.cursor()
                    self.log_message("[INFO] Cleaning up Extended Events session...")
                    self.cleanup_xe_session(cursor)
                    self.conn.close()
                except Exception:
                    pass
            self.root.after(0, self.stop_monitoring)

    def monitor_loop_dmv(self):
        show_system = self.show_system_queries.get()
        self.log_message(f"[INFO] Connecting to {self.config_vars['server'].get()} (Legacy DMV Mode)...")
        try:
            self.conn = pyodbc.connect(self.get_connection_string(), timeout=10)
            cursor = self.conn.cursor()
            cursor.execute("SELECT @@SPID as session_id")
            monitor_session_id = cursor.fetchone().session_id
            self.log_message(f"[INFO] Connected successfully (Monitor Session: {monitor_session_id})")
            self.log_message("[INFO] Legacy DMV monitoring started - captures ACTIVE queries only")
            query = """
            SELECT 
                r.session_id,
                r.start_time,
                r.status,
                r.command,
                r.database_id,
                DB_NAME(r.database_id) as database_name,
                r.blocking_session_id,
                r.wait_type,
                r.wait_time,
                r.cpu_time,
                r.total_elapsed_time,
                r.reads,
                r.writes,
                r.logical_reads,
                s.login_name,
                s.host_name,
                s.program_name,
                t.text as query_text,
                SUBSTRING(t.text, (r.statement_start_offset/2)+1,
                    ((CASE r.statement_end_offset
                        WHEN -1 THEN DATALENGTH(t.text)
                        ELSE r.statement_end_offset
                    END - r.statement_start_offset)/2) + 1) as current_statement
            FROM sys.dm_exec_requests r
            CROSS APPLY sys.dm_exec_sql_text(r.sql_handle) t
            LEFT JOIN sys.dm_exec_sessions s ON r.session_id = s.session_id
            WHERE r.session_id != ?
                AND r.session_id != @@SPID
            ORDER BY r.total_elapsed_time DESC
            """
            while self.monitoring:
                try:
                    cursor.execute(query, monitor_session_id)
                    rows = cursor.fetchall()
                    current_time = time.time()
                    for row in rows:
                        if not self.monitoring:
                            break
                        if not show_system and row.session_id <= 50:
                            continue
                        if row.total_elapsed_time < MIN_DURATION_MS:
                            continue
                        query_text = row.current_statement or row.query_text or ""
                        if not query_text or query_text.strip() == "":
                            continue
                        query_filter = self.query_filter_var.get().strip()
                        if query_filter and query_filter.lower() not in query_text.lower():
                            continue
                        query_key = f"{row.session_id}_{row.start_time}_{hash(query_text[:100])}"
                        if query_key in self.seen_queries:
                            if row.status == "running" and current_time - self.seen_queries[query_key] > 5:
                                self.seen_queries[query_key] = current_time
                            else:
                                continue
                        else:
                            self.seen_queries[query_key] = current_time
                        if len(self.seen_queries) > 1000:
                            sorted_keys = sorted(self.seen_queries.items(), key=lambda x: x[1])
                            for key, _ in sorted_keys[:200]:
                                del self.seen_queries[key]
                        query_clean = " ".join(query_text.split())
                        query_preview = (
                            query_clean[:100] + "..." if len(query_clean) > 100 else query_clean
                        )
                        query_info = {
                            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
                            "session_id": row.session_id,
                            "database": row.database_name or "N/A",
                            "username": row.login_name or "N/A",
                            "duration": row.total_elapsed_time,
                            "cpu": row.cpu_time,
                            "reads": row.reads + row.logical_reads,
                            "writes": row.writes,
                            "preview": query_preview,
                            "full_query": query_text.strip(),
                        }
                        self.query_data.append(query_info)
                        self.add_query_row(query_info)
                except pyodbc.Error as e:
                    if self.monitoring and "Timeout expired" not in str(e):
                        self.log_message(f"[ERROR] Query failed: {str(e)}", "ERROR")
                except Exception as e:
                    if self.monitoring:
                        self.log_message(f"[ERROR] {str(e)}", "ERROR")
                time.sleep(POLL_INTERVAL_DMV)
        except Exception as e:
            self.log_message(f"[ERROR] Connection failed: {str(e)}", "ERROR")
            messagebox.showerror("Connection Error", str(e))
        finally:
            if self.conn:
                try:
                    self.log_message("[INFO] Closing connection...")
                    self.conn.close()
                except Exception:
                    pass
            self.root.after(0, self.stop_monitoring)


def main():
    root = tk.Tk()
    app = SQLMonitorGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
