import tkinter as tk
from tkinter import ttk, messagebox
import json
import os

LEDGER_PATH = "C:/ProgramData/AGYVerifier/protected_ledger.jsonl"

def load_ledger():
    if not os.path.exists(LEDGER_PATH):
        return []
    records = []
    try:
        with open(LEDGER_PATH, "r", encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    records.append(json.loads(line))
    except Exception as e:
        messagebox.showerror("Error", f"Failed to load ledger (access denied?): {e}")
    return records

class VerifierGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Antigravity Protected Ledger Viewer")
        self.root.geometry("800x600")
        
        # Treeview for ledger records
        columns = ("timestamp", "certificate_id", "claim", "status")
        self.tree = ttk.Treeview(root, columns=columns, show="headings")
        self.tree.heading("timestamp", text="Timestamp")
        self.tree.heading("certificate_id", text="Certificate ID")
        self.tree.heading("claim", text="Claim")
        self.tree.heading("status", text="Status")
        
        self.tree.column("timestamp", width=150)
        self.tree.column("certificate_id", width=150)
        self.tree.column("claim", width=100)
        self.tree.column("status", width=80)
        
        self.tree.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        self.tree.bind("<<TreeviewSelect>>", self.on_select)
        
        # Text widget for details
        self.details = tk.Text(root, height=15, wrap=tk.WORD)
        self.details.pack(fill=tk.BOTH, expand=False, padx=10, pady=10)
        
        # Refresh button
        self.btn_refresh = tk.Button(root, text="Refresh Ledger", command=self.refresh)
        self.btn_refresh.pack(pady=5)
        
        self.records = []
        self.refresh()

    def refresh(self):
        for item in self.tree.get_children():
            self.tree.delete(item)
            
        self.records = load_ledger()
        for i, rec in enumerate(self.records):
            status = rec.get("status", "UNKNOWN")
            self.tree.insert("", tk.END, iid=str(i), values=(
                rec.get("timestamp", ""),
                rec.get("certificate_id", ""),
                rec.get("claim", ""),
                status
            ))
            
    def on_select(self, event):
        selection = self.tree.selection()
        if not selection:
            return
        idx = int(selection[0])
        record = self.records[idx]
        
        self.details.delete(1.0, tk.END)
        self.details.insert(tk.END, json.dumps(record, indent=2))

if __name__ == "__main__":
    root = tk.Tk()
    app = VerifierGUI(root)
    root.mainloop()
