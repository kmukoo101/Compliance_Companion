"""
CVEye Compliance Companion: Automated Cybersecurity Compliance Checker for SMEs

This tool comes with GUI support, custom control support, regex/list output matching, 
email report sending, scan progress updates, and enhanced in-GUI results display with 
download capability.

"""

import os
import platform
import subprocess
import json
import logging
from datetime import datetime
from pathlib import Path
import random
import re
import smtplib
from email.message import EmailMessage
import tkinter as tk
from tkinter import messagebox, scrolledtext, filedialog

# --- SETUP ---

TIMESTAMP = datetime.now().strftime('%Y%m%d_%H%M%S')
LOG_FILE = f"compliance_log_{TIMESTAMP}.log"
logging.basicConfig(
    filename=LOG_FILE,
    filemode='w',
    format='%(asctime)s [%(levelname)s] %(message)s',
    level=logging.INFO
)

# Global result container
compliance_results = {
    "organization": "",
    "scan_date": TIMESTAMP,
    "framework": "",
    "controls": {},
    "remediation_roadmap": []
}

# Standard framework mappings for known controls
COMPLIANCE_FRAMEWORKS = {
    "NIST": {
        "FirewallEnabled": "SC-7",
        "DiskEncryption": "SC-12"
    },
    "ISO 27001": {
        "FirewallEnabled": "A.13.1.1",
        "DiskEncryption": "A.10.1.1"
    },
    "HIPAA": {
        "FirewallEnabled": "164.312(c)(1)",
        "DiskEncryption": "164.312(a)(2)(iv)"
    }
}

# Descriptions that are end-user readable
CONTROL_DESCRIPTIONS = {
    "FirewallEnabled": "The system firewall should be enabled to block unauthorized access. This is critical to prevent untrusted network traffic.",
    "DiskEncryption": "Ensure full disk encryption (e.g., BitLocker, FileVault, or LUKS) is enabled to protect data at rest from physical theft or access."
}

# Fix suggestions for each control
FIX_COMMANDS = {
    "FirewallEnabled": "Enable the system firewall. Windows: 'netsh advfirewall set allprofiles state on'. Linux: 'ufw enable'. macOS: Use System Preferences > Security & Privacy > Firewall.",
    "DiskEncryption": "Enable full disk encryption. Windows: BitLocker via Control Panel. macOS: Turn on FileVault in Security settings. Linux: Use LUKS with cryptsetup."
}

# --- UTILITY FUNCTIONS ---

def run_cmd(command):
    """Execute a system command and return output as string. Handles errors safely."""
    try:
        return subprocess.check_output(command, shell=True).decode(errors='ignore')
    except Exception as e:
        logging.warning(f"Command failed: {command} | {e}")
        return ""

# --- CONTROL CHECK FUNCTIONS ---

def check_firewall_enabled():
    """Check whether the system firewall is active based on platform."""
    system = platform.system()
    if system == 'Windows':
        return 'State ON' in run_cmd("netsh advfirewall show allprofiles")
    elif system == 'Linux':
        return 'active' in run_cmd("ufw status")
    elif system == 'Darwin':
        return 'enabled' in run_cmd("/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate")
    return False

def check_disk_encryption():
    """Check whether full disk encryption is enabled based on OS."""
    system = platform.system()
    if system == 'Windows':
        return 'Percentage Encrypted : 100' in run_cmd("manage-bde -status")
    elif system == 'Darwin':
        return 'FileVault: On' in run_cmd("fdesetup status")
    elif system == 'Linux':
        return 'crypt' in run_cmd("lsblk -o NAME,TYPE")
    return False

# --- CUSTOM CONTROLS LOADER ---

def load_custom_controls():
    """Load user-defined controls from a custom_controls.json file, if present."""
    filepath = "custom_controls.json"
    if not os.path.exists(filepath):
        return {}
    with open(filepath, "r") as f:
        try:
            return json.load(f)
        except json.JSONDecodeError:
            logging.error("Invalid JSON in custom_controls.json")
            return {}

# --- OUTPUT MATCHING LOGIC ---

def match_output(output, expected):
    """Evaluate command output against expected values.
    - Supports string, list of strings, or regex match.
    """
    if isinstance(expected, str):
        return expected in output
    elif isinstance(expected, list):
        return any(item in output for item in expected)
    elif isinstance(expected, dict) and expected.get("regex"):
        return re.search(expected["regex"], output, re.IGNORECASE) is not None
    return False

# --- MAIN SCAN LOGIC ---

def perform_scan(simulate=False, update_callback=None):
    """Run system and custom compliance checks. Update UI on progress if callback provided."""
    logging.info("Performing compliance checks...")
    system = platform.system()
    check_map = {
        "FirewallEnabled": check_firewall_enabled,
        "DiskEncryption": check_disk_encryption
    }

    for control, func in check_map.items():
        if update_callback:
            update_callback(f"Scanning {control}...")
        passed = random.choice([True, False]) if simulate else func()
        compliance_results["controls"][control] = {
            "status": "PASS" if passed else "FAIL",
            "description": CONTROL_DESCRIPTIONS[control],
            "framework_refs": {fw: COMPLIANCE_FRAMEWORKS[fw][control] for fw in COMPLIANCE_FRAMEWORKS},
            "fix_cmd": FIX_COMMANDS.get(control, "Refer to documentation")
        }
        if not passed:
            compliance_results["remediation_roadmap"].append({
                "control": control,
                "recommendation": CONTROL_DESCRIPTIONS[control],
                "priority": "High",
                "due_date": "30 days"
            })
            logging.warning(f"Control failed: {control}")

    for name, cfg in load_custom_controls().items():
        if cfg.get("platform", "any") not in ["any", system]:
            continue
        if update_callback:
            update_callback(f"Running custom control: {name}...")
        output = run_cmd(cfg.get("command", ""))
        passed = match_output(output, cfg.get("expected_output")) if not simulate else random.choice([True, False])
        compliance_results["controls"][name] = {
            "status": "PASS" if passed else "FAIL",
            "description": cfg.get("description", "No description."),
            "framework_refs": cfg.get("framework_refs", {}),
            "fix_cmd": cfg.get("fix_cmd", "N/A")
        }
        if not passed:
            compliance_results["remediation_roadmap"].append({
                "control": name,
                "recommendation": cfg.get("description", ""),
                "priority": cfg.get("priority", "Medium"),
                "due_date": "30 days"
            })
            logging.warning(f"Custom control failed: {name}")

# --- EMAIL REPORT ---

def send_email_report(recipient, sender, password):
    """Email the full compliance report as a JSON string using Gmail SMTP."""
    try:
        msg = EmailMessage()
        msg['Subject'] = 'CVEye Compliance Report'
        msg['From'] = sender
        msg['To'] = recipient
        msg.set_content(json.dumps(compliance_results, indent=2))
        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as smtp:
            smtp.login(sender, password)
            smtp.send_message(msg)
        messagebox.showinfo("Success", "Report emailed successfully!")
    except Exception as e:
        messagebox.showerror("Email Error", f"Failed to send email: {e}")

# --- GUI ---

class ComplianceApp:
    def __init__(self, root):
        self.root = root
        root.title("CVEye Compliance Companion")
        root.geometry("600x500")

        tk.Label(root, text="Organization:").pack()
        self.org_entry = tk.Entry(root)
        self.org_entry.pack()

        tk.Label(root, text="Industry:").pack()
        self.industry_entry = tk.Entry(root)
        self.industry_entry.pack()

        tk.Label(root, text="Framework:").pack()
        self.framework_var = tk.StringVar(value="NIST")
        tk.OptionMenu(root, self.framework_var, "NIST", "ISO 27001", "HIPAA").pack()

        self.sim_var = tk.IntVar()
        tk.Checkbutton(root, text="Simulate scan (for demo/testing)", variable=self.sim_var).pack()

        tk.Button(root, text="Start Scan", command=self.start_scan).pack(pady=10)
        tk.Button(root, text="Email Report", command=self.email_prompt).pack(pady=5)
        tk.Button(root, text="Download Report", command=self.download_report).pack(pady=5)

        self.output_box = scrolledtext.ScrolledText(root, height=15, wrap='word')
        self.output_box.pack(padx=10, pady=10, fill='both', expand=True)

    def update_status(self, text):
        """Insert real-time feedback in the output window."""
        self.output_box.insert(tk.END, f"{text}\n")
        self.output_box.see(tk.END)
        self.root.update_idletasks()

    def start_scan(self):
        compliance_results["organization"] = self.org_entry.get()
        compliance_results["framework"] = self.framework_var.get()
        simulate = self.sim_var.get() == 1
        self.output_box.delete('1.0', tk.END)
        self.update_status("Starting compliance scan...")
        perform_scan(simulate, update_callback=self.update_status)
        self.show_results()

    def show_results(self):
        self.output_box.insert(tk.END, "\nScan Complete. Results:\n")
        for name, data in compliance_results["controls"].items():
            self.output_box.insert(tk.END, f"{name}: {data['status']} — {data['description']}\n")
        self.output_box.insert(tk.END, "\nRemediation Suggestions:\n")
        for item in compliance_results["remediation_roadmap"]:
            self.output_box.insert(tk.END, f"- {item['control']}: {item['recommendation']}\n")

    def download_report(self):
        path = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON files", "*.json")])
        if path:
            with open(path, "w") as f:
                json.dump(compliance_results, f, indent=2)
            messagebox.showinfo("Saved", f"Report saved to {path}")

    def email_prompt(self):
        win = tk.Toplevel(self.root)
        win.title("Send Email Report")
        tk.Label(win, text="Recipient Email:").pack()
        to_entry = tk.Entry(win)
        to_entry.pack()
        tk.Label(win, text="Sender Email:").pack()
        from_entry = tk.Entry(win)
        from_entry.pack()
        tk.Label(win, text="Sender Password:").pack()
        pass_entry = tk.Entry(win, show="*")
        pass_entry.pack()
        tk.Button(win, text="Send", command=lambda: send_email_report(to_entry.get(), from_entry.get(), pass_entry.get())).pack()

# --- MAIN ---

if __name__ == '__main__':
    root = tk.Tk()
    app = ComplianceApp(root)
    root.mainloop()
