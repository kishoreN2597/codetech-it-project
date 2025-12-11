#!/usr/bin/env python3
"""
FIM GUI (Tkinter)
Features:
- Pick file or directory
- Initial store hashes
- One-shot check (compare hashes)
- Real-time monitor (requires watchdog)
- Select hash algorithm (sha256, sha1, md5)
- Log output inside GUI
"""
import os
import json
import hashlib
import threading
import time
from datetime import datetime
import traceback
import queue
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext

# Try to import watchdog; monitor features depend on it
try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler
    WATCHDOG_AVAILABLE = True
except Exception:
    WATCHDOG_AVAILABLE = False

DB_FILE_DEFAULT = "hash_database.json"
BUFFER_SIZE = 4096
SUPPORTED_ALGOS = ("sha256", "sha1", "md5")


# ---------- Utility functions ----------
def calculate_hash(path, algo="sha256"):
    """Return hex digest for file; return None if cannot read."""
    try:
        h = hashlib.new(algo)
    except Exception:
        h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            for block in iter(lambda: f.read(BUFFER_SIZE), b""):
                h.update(block)
        return h.hexdigest()
    except (FileNotFoundError, PermissionError, IsADirectoryError):
        return None
    except Exception:
        return None


def walk_files(path):
    """Yield file paths inside path (if file yields itself)."""
    if os.path.isfile(path):
        yield path
        return
    for root, _, files in os.walk(path):
        for name in files:
            yield os.path.join(root, name)


def load_db(db_path):
    if not os.path.exists(db_path):
        return {}
    try:
        with open(db_path, "r") as fh:
            return json.load(fh)
    except Exception:
        # backup corrupt DB and return empty
        try:
            bak = db_path + ".bak." + datetime.utcnow().strftime("%s")
            os.rename(db_path, bak)
        except Exception:
            pass
        return {}


def save_db(db, db_path):
    with open(db_path, "w") as fh:
        json.dump(db, fh, indent=4)


# ---------- Watchdog event handler ----------
class FIMEventHandler(FileSystemEventHandler):
    def __init__(self, algo, update_db, log_q, db_path):
        super().__init__()
        self.algo = algo
        self.update_db = update_db
        self.log_q = log_q
        # store absolute DB path so we can ignore it
        self.db_path = os.path.abspath(db_path)

    def handle_path(self, path, event_type):
        # ignore modifications to the DB file itself
        try:
            if os.path.abspath(path) == self.db_path:
                return
        except Exception:
            pass

        if os.path.isdir(path):
            return
        current_hash = calculate_hash(path, self.algo)
        db = load_db(self.db_path)

        if event_type == "deleted":
            if path in db:
                self.log_q.put(f"[DELETED] {path} removed from filesystem")
                if self.update_db:
                    del db[path]
                    save_db(db, self.db_path)
            else:
                self.log_q.put(f"[DELETED] {path} (not tracked)")
            return

        if current_hash is None:
            self.log_q.put(f"[SKIP] Cannot read: {path}")
            return

        entry = db.get(path)
        if entry is None:
            self.log_q.put(f"[NEW] {path} (hash: {current_hash})")
            if self.update_db:
                db[path] = {"hash": current_hash, "algo": self.algo, "last_checked": datetime.utcnow().isoformat()}
                save_db(db, self.db_path)
            return

        stored_hash = entry.get("hash")
        stored_algo = entry.get("algo", self.algo)
        if stored_algo != self.algo:
            # recompute using stored algo to compare accurately
            compare_hash = calculate_hash(path, stored_algo) or current_hash
        else:
            compare_hash = current_hash

        if compare_hash == stored_hash:
            self.log_q.put(f"[UNCHANGED] {path}")
        else:
            # log change (do not overwrite DB unless update_db True)
            self.log_q.put(f"[CHANGED] {path}\n    old: {stored_hash}\n    new: {compare_hash}")
            if self.update_db:
                # preserve previous hash for forensics
                db[path] = {
                    "hash": compare_hash,
                    "algo": stored_algo,
                    "last_checked": datetime.utcnow().isoformat(),
                    "previous_hash": stored_hash
                }
                save_db(db, self.db_path)

    def on_created(self, event):
        self.handle_path(event.src_path, "created")

    def on_modified(self, event):
        self.handle_path(event.src_path, "modified")

    def on_deleted(self, event):
        self.handle_path(event.src_path, "deleted")

    def on_moved(self, event):
        # handle dest path
        self.handle_path(event.dest_path, "moved")


# ---------- GUI Application ----------
class FIMGuiApp:
    def __init__(self, root):
        self.root = root
        root.title("File Integrity Monitoring - GUI")
        root.geometry("880x560")

        # Left frame for controls
        ctrl = tk.Frame(root)
        ctrl.pack(side=tk.TOP, fill=tk.X, padx=8, pady=6)

        tk.Label(ctrl, text="Path:").grid(row=0, column=0, sticky="w")
        self.path_var = tk.StringVar()
        self.entry_path = tk.Entry(ctrl, textvariable=self.path_var, width=70)
        self.entry_path.grid(row=0, column=1, columnspan=4, sticky="w", padx=4)

        tk.Button(ctrl, text="Browse File", command=self.browse_file).grid(row=0, column=5, padx=2)
        tk.Button(ctrl, text="Browse Dir", command=self.browse_dir).grid(row=0, column=6, padx=2)

        tk.Label(ctrl, text="DB file:").grid(row=1, column=0, sticky="w", pady=6)
        self.db_var = tk.StringVar(value=DB_FILE_DEFAULT)
        tk.Entry(ctrl, textvariable=self.db_var, width=40).grid(row=1, column=1, columnspan=2, sticky="w")
        tk.Button(ctrl, text="Browse DB", command=self.browse_db).grid(row=1, column=3, padx=2)

        tk.Label(ctrl, text="Algorithm:").grid(row=1, column=4, sticky="e")
        self.algo_var = tk.StringVar(value="sha256")
        tk.OptionMenu(ctrl, self.algo_var, *SUPPORTED_ALGOS).grid(row=1, column=5, sticky="w")

        self.update_db_var = tk.BooleanVar(value=False)
        tk.Checkbutton(ctrl, text="Update DB on new/modified", variable=self.update_db_var).grid(row=2, column=1, columnspan=3, sticky="w", pady=6)

        # Buttons
        btn_frame = tk.Frame(root)
        btn_frame.pack(side=tk.TOP, fill=tk.X, padx=8)
        tk.Button(btn_frame, text="Initial Store", width=14, command=self.initial_store).pack(side=tk.LEFT, padx=6)
        tk.Button(btn_frame, text="One-shot Check", width=14, command=self.one_shot_check).pack(side=tk.LEFT, padx=6)

        # Accept Changes button (new)
        tk.Button(btn_frame, text="Accept Changes", width=14, command=self.accept_changes).pack(side=tk.LEFT, padx=6)

        self.monitor_btn = tk.Button(btn_frame, text="Start Monitor", width=14, command=self.toggle_monitor)
        self.monitor_btn.pack(side=tk.LEFT, padx=6)

        tk.Button(btn_frame, text="Clear Log", width=10, command=self.clear_log).pack(side=tk.RIGHT, padx=6)
        tk.Button(btn_frame, text="Export Log", width=12, command=self.export_log).pack(side=tk.RIGHT, padx=6)

        # Log area
        self.log_box = scrolledtext.ScrolledText(root, state="normal", height=24)
        self.log_box.pack(fill=tk.BOTH, padx=8, pady=8, expand=True)

        # Internal state
        self.monitoring = False
        self.observer = None
        self.log_q = queue.Queue()
        self.monitor_thread = None

        # Start log queue pump
        self.root.after(200, self.pump_log_queue)

        # Warn if watchdog missing
        if not WATCHDOG_AVAILABLE:
            self.log("[WARN] watchdog not installed. Real-time monitoring disabled. Install with: pip install watchdog")

    def log(self, msg):
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.log_box.insert("end", f"[{ts}] {msg}\n")
        self.log_box.see("end")

    def pump_log_queue(self):
        try:
            while True:
                msg = self.log_q.get_nowait()
                self.log(msg)
        except queue.Empty:
            pass
        self.root.after(200, self.pump_log_queue)

    def browse_file(self):
        p = filedialog.askopenfilename()
        if p:
            self.path_var.set(p)

    def browse_dir(self):
        p = filedialog.askdirectory()
        if p:
            self.path_var.set(p)

    def browse_db(self):
        p = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON", "*.json")])
        if p:
            self.db_var.set(p)

    # ---------- Actions ----------
    def initial_store(self):
        p = self.path_var.get().strip()
        db_path = self.db_var.get().strip()
        algo = self.algo_var.get()
        if not p:
            messagebox.showerror("Error", "Please choose a path")
            return
        count = 0
        db = load_db(db_path)
        try:
            for fp in walk_files(p):
                h = calculate_hash(fp, algo)
                if h is None:
                    self.log_q.put(f"[SKIP] Cannot read: {fp}")
                    continue
                db[fp] = {"hash": h, "algo": algo, "last_checked": datetime.utcnow().isoformat()}
                count += 1
            save_db(db, db_path)
            self.log_q.put(f"[INFO] Stored initial hashes for {count} files into {db_path}")
        except Exception as e:
            self.log_q.put(f"[ERROR] initial_store failed: {e}\n{traceback.format_exc()}")

    def one_shot_check(self):
        p = self.path_var.get().strip()
        db_path = self.db_var.get().strip()
        algo = self.algo_var.get()
        update_db = self.update_db_var.get()
        if not p:
            messagebox.showerror("Error", "Please choose a path")
            return
        try:
            db = load_db(db_path)
            counts = {"ok": 0, "new": 0, "modified": 0, "skipped": 0}
            for fp in walk_files(p):
                current = calculate_hash(fp, algo)
                if current is None:
                    self.log_q.put(f"[SKIP] {fp}")
                    counts["skipped"] += 1
                    continue
                entry = db.get(fp)
                if entry is None:
                    self.log_q.put(f"[NEW] {fp} (hash: {current})")
                    counts["new"] += 1
                    if update_db:
                        db[fp] = {"hash": current, "algo": algo, "last_checked": datetime.utcnow().isoformat()}
                else:
                    stored_algo = entry.get("algo", algo)
                    stored_hash = entry.get("hash")
                    compare_hash = calculate_hash(fp, stored_algo) if stored_algo != algo else current
                    if compare_hash == stored_hash:
                        self.log_q.put(f"[OK] {fp}")
                        counts["ok"] += 1
                    else:
                        self.log_q.put(f"[MODIFIED] {fp}\n    old: {stored_hash}\n    new: {compare_hash}")
                        # save updated hash if requested
                        counts["modified"] += 1
                        if update_db:
                            db[fp] = {"hash": compare_hash, "algo": stored_algo, "last_checked": datetime.utcnow().isoformat()}
            if update_db:
                save_db(db, db_path)
            self.log_q.put(f"[SUMMARY] ok={counts['ok']} new={counts['new']} modified={counts['modified']} skipped={counts['skipped']}")
        except Exception as e:
            self.log_q.put(f"[ERROR] one_shot_check failed: {e}\n{traceback.format_exc()}")

    def accept_changes(self):
        """Update DB to current state for all files under chosen path but keep previous_hash for forensics."""
        p = self.path_var.get().strip()
        db_path = self.db_var.get().strip()
        algo = self.algo_var.get()
        if not p:
            messagebox.showerror("Error", "Please choose a path")
            return

        try:
            db = load_db(db_path)
            updated = 0
            for fp in walk_files(p):
                current = calculate_hash(fp, algo)
                if current is None:
                    self.log_q.put(f"[SKIP] Cannot read: {fp}")
                    continue
                old = db.get(fp, {}).get("hash")
                if old != current:
                    # store previous hash in history key for forensics
                    db[fp] = {
                        "hash": current,
                        "algo": algo,
                        "last_checked": datetime.utcnow().isoformat(),
                        "previous_hash": old
                    }
                    updated += 1
            save_db(db, db_path)
            self.log_q.put(f"[INFO] Accepted changes for {updated} files (DB updated).")
        except Exception as e:
            self.log_q.put(f"[ERROR] accept_changes failed: {e}\n{traceback.format_exc()}")

    def toggle_monitor(self):
        if not WATCHDOG_AVAILABLE:
            messagebox.showwarning("Watchdog missing", "watchdog is not installed. Install with: pip install watchdog")
            return

        if not self.monitoring:
            p = self.path_var.get().strip()
            db_path = self.db_var.get().strip()
            if not p:
                messagebox.showerror("Error", "Please choose a path")
                return
            self.start_monitor(p, db_path, self.algo_var.get(), self.update_db_var.get())
        else:
            self.stop_monitor()

    def start_monitor(self, path, db_path, algo, update_db):
        # Start watchdog observer in background
        try:
            handler = FIMEventHandler(algo=algo, update_db=update_db, log_q=self.log_q, db_path=db_path)
            self.observer = Observer()
            if os.path.isdir(path):
                self.observer.schedule(handler, path, recursive=True)
                self.log_q.put(f"[INFO] Monitoring directory: {path}")
            elif os.path.isfile(path):
                directory = os.path.dirname(path) or "."
                self.observer.schedule(handler, directory, recursive=False)
                self.log_q.put(f"[INFO] Monitoring file: {path}")
            else:
                self.log_q.put(f"[ERROR] Path not found: {path}")
                return
            self.observer.start()
            self.monitoring = True
            self.monitor_btn.config(text="Stop Monitor")
            # spawn a thread to watch for observer exceptions
            def watch():
                try:
                    while self.monitoring:
                        time.sleep(0.5)
                except Exception as e:
                    self.log_q.put(f"[ERROR] monitor thread: {e}")
            self.monitor_thread = threading.Thread(target=watch, daemon=True)
            self.monitor_thread.start()
        except Exception as e:
            self.log_q.put(f"[ERROR] start_monitor failed: {e}\n{traceback.format_exc()}")

    def stop_monitor(self):
        try:
            self.monitoring = False
            if self.observer:
                self.observer.stop()
                self.observer.join(timeout=2)
                self.observer = None
            self.monitor_btn.config(text="Start Monitor")
            self.log_q.put("[INFO] Monitor stopped")
        except Exception as e:
            self.log_q.put(f"[ERROR] stop_monitor failed: {e}\n{traceback.format_exc()}")

    def clear_log(self):
        self.log_box.delete("1.0", "end")

    def export_log(self):
        fpath = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text", "*.txt")])
        if not fpath:
            return
        try:
            with open(fpath, "w") as fh:
                fh.write(self.log_box.get("1.0", "end"))
            messagebox.showinfo("Exported", f"Log exported to {fpath}")
        except Exception as e:
            messagebox.showerror("Export error", str(e))


# ---------- Run ----------
def main():
    root = tk.Tk()
    app = FIMGuiApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()


