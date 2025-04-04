## 🛡️ CVEye Compliance Companion

This is an open-source, GUI-based cybersecurity compliance checker for Windows, macOS, and Linux. Built for SMBs, IT admins, and privacy-conscious users, it scans for basic security controls, checks custom hardening rules, and generates actionable reports mapped to frameworks like NIST, ISO 27001, and HIPAA.

Most free compliance tools are overly complex, CLI-only, or locked behind subscriptions. CVEye is free, readable, modifiable, and gets the job done with clarity.

---

### Features
- Built-in system checks (firewall, disk encryption)
- Custom controls via `custom_controls.json`
- Smart output matching: text, list, and regex
- Live progress updates during scan
- In-app report viewer + save to JSON
- Optional email report sender
- Cross-platform GUI with **Tkinter**

---

### Requirements

- Python 3.7+
- Cross-platform (Windows/macOS/Linux)
- Internet connection (only for email feature)

---

### Get Started

```bash
git clone https://github.com/kmukoo101/CVEye
cd CVEye
python compliance_checker.py
```

---

### ⚙ Controls 

Create a `custom_controls.json` in the same folder:

```json
{
  "CheckVPN": {
    "description": "Verify VPN interface is active.",
    "platform": "Linux",
    "command": "ip route",
    "expected_output": { "regex": "tun0" },
    "framework_refs": {
      "NIST": "SC-12",
      "ISO 27001": "A.13.2.1"
    },
    "fix_cmd": "Start VPN and verify tun0 exists.",
    "priority": "High",
    "tags": ["network", "remote-access"]
  }
}
```

---

### Sending Reports via Email

You can optionally send reports from a Gmail address:

- Enable "less secure app access" (or use an app password)
- Enter recipient, sender, and password in the GUI

---

### Output

- JSON file with control status, descriptions, remediation roadmap, and framework references
- Logged to `compliance_log_<timestamp>.log`


