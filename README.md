<div align="center">

# 🔍 File Malware Scanner

### 7-Layer Malware Analysis Engine

![Python](https://img.shields.io/badge/Python-3.10+-blue?style=for-the-badge&logo=python)
![Flask](https://img.shields.io/badge/Flask-2.x-black?style=for-the-badge&logo=flask)
![YARA](https://img.shields.io/badge/YARA-Rules-red?style=for-the-badge)
![VirusTotal](https://img.shields.io/badge/VirusTotal-API%20v3-orange?style=for-the-badge)
![VMware](https://img.shields.io/badge/VMware-Sandbox-607078?style=for-the-badge&logo=vmware)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)

> Upload any suspicious `.exe` file — get a full threat report in under 2 minutes.

</div>

---

## 🎯 What is this?

A **malware analysis engine** that runs every `.exe` file through **7 independent analysis layers** and produces a single **Risk Score from 0 to 100** with a full PDF report.

Built as part of the **CyberGuard Sentinel** graduation project.

---

## 🔬 The 7 Layers

```
 .exe Uploaded
      │
      ▼
 ① SHA-256 Hashing
      Computes a unique 64-char fingerprint for the file.
      Used to identify the file and query VirusTotal.
      │
      ▼
 ② Static PE Analysis
      Parses the PE structure without executing the file.
      Checks: imports, section entropy, suspicious strings.
      │
      ▼
 ③ VirusTotal API
      Sends the hash to VirusTotal.
      Cross-checks against 70+ antivirus engines instantly.
      │
      ▼
 ④ YARA Scanning
      Matches file content against custom malware rules:
      Ransomware · Trojans · Evasion · Persistence
      │
      ▼
 ⑤ VMware Sandbox
      Executes the file in a fully isolated VM.
      Monitors: network, files, registry, processes.
      │
      ▼
 ⑥ Behavioral Analysis
      Detects attack patterns:
      Persistence · Evasion · Discovery · Download & Execute
      │
      ▼
 ⑦ Risk Score 0–100
      Weighted verdict across all 6 layers.
      Generates PDF + JSON report.
```

---

## ⚖️ Risk Score Weights

| Module | Weight | Reason |
|--------|--------|--------|
| 🌐 VirusTotal | **35%** | Consensus of 70+ independent AV engines |
| 🔎 YARA | **25%** | Purpose-built malware signature rules |
| 🧬 Static Analysis | **20%** | PE structural anomalies never lie |
| 🧠 Behavioral Analysis | **15%** | Runtime behavior patterns |
| 📦 Sandbox | **5%** | Dynamic execution evidence |

---

## 🎯 Threat Levels

| Score | Level | Recommended Action |
|-------|-------|--------------------|
| 0 | 🟢 **Safe** | No action needed |
| 1 – 19 | 🔵 **Low** | Monitor the file |
| 20 – 44 | 🟡 **Medium** | Investigate before allowing execution |
| 45 – 69 | 🟠 **High** | Isolate system and delete the file |
| 70 – 100 | 🔴 **Critical** | Quarantine immediately — do not execute |

---

## 🧬 YARA Rules

Three custom rule files covering the most common malware families:

| File | Detects |
|------|---------|
| `ransomware.yar` | Encryption APIs, ransom note keywords, shadow copy deletion |
| `trojans.yar` | RATs, keyloggers (SetWindowsHookEx), credential stealers, screen capture |
| `evasion_persistence.yar` | VM detection, debugger detection, process injection, registry Run keys |

---

## 🗂️ Project Structure

```
File-Malware-Scanner/
│
├── App.py                        # Flask server & API routes
│
├── modules/
│   ├── hashing.py                # SHA-256 chunked calculation
│   ├── static_analysis.py        # PE parsing (pefile)
│   ├── virustotal.py             # VirusTotal API v3 integration
│   ├── yara_scanner.py           # YARA rule engine
│   ├── sandbox.py                # VMware sandbox execution
│   ├── behavior_engine.py        # Behavioral pattern detection
│   ├── risk_score.py             # Weighted scoring system
│   └── report_generator.py       # PDF + JSON report generation
│
├── yara_rules/
│   ├── ransomware.yar
│   ├── trojans.yar
│   └── evasion_persistence.yar
│
├── static/
│   ├── css/style.css
│   └── js/script.js
│
├── templates/
│   └── index.html
│
├── uploads/                      # Generated reports go here
├── requirements.txt
└── README.md
```

---

## ⚙️ Installation

### Requirements
- Python 3.10+
- VMware Workstation *(for Sandbox — optional)*

```bash
# 1. Clone the repo
git clone https://github.com/YOUR_USERNAME/File-Malware-Scanner.git
cd File-Malware-Scanner

# 2. Create virtual environment
python -m venv venv
venv\Scripts\activate        # Windows
# source venv/bin/activate   # Linux / Mac

# 3. Install dependencies
pip install -r requirements.txt

# 4. Set your VirusTotal API Key
# Open modules/virustotal.py and replace:
API_KEY = 'your_api_key_here'

# 5. Run
python App.py
```

Visit: **http://127.0.0.1:5000**

---

## 📦 Dependencies

```
flask
requests
yara-python
pefile
reportlab
```

Install all at once:
```bash
pip install -r requirements.txt
```

---

## 🔑 VirusTotal API Key

1. Go to [virustotal.com](https://www.virustotal.com)
2. Create a free account
3. Profile → API Key → Copy
4. Paste into `modules/virustotal.py`

> ⚠️ Free tier limits: **4 requests/min · 500 requests/day**

---

## 🔧 Technical Notes

**Why chunked reading for SHA-256?**
> Files can be gigabytes. Reading in 8 KB chunks prevents RAM overload.

**Why `sources=` instead of `filepaths=` in YARA?**
> YARA's internal C file-open doesn't handle non-ASCII paths (e.g. Arabic folder names) on Windows.
> We read rule files with Python first, then pass the content as strings to YARA — completely bypassing the issue.

**Why threshold = 3 for VirusTotal verdict?**
> A single AV engine can produce false positives.
> If 4+ independent engines agree → real threat.

---

## 📊 Sample Output

```
File: malware_sample.exe
SHA-256: 414b24251fb4ed1652bc5502b1990b68...

VirusTotal:   46 / 76 engines flagged as MALWARE
YARA:         Ransomware_Generic matched (CRITICAL)
Static:       Packed binary · 3 suspicious imports
Sandbox:      12 network connections · registry persistence
Behavioral:   Persistence + Evasion detected

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Risk Score:   87 / 100
Threat Level: 🔴 CRITICAL
Action:       Quarantine immediately.
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

---

## ⚠️ Disclaimer

> This tool is intended **for authorized security research and educational purposes only**.
> Do not analyze files you do not have explicit permission to test.
> The author is not responsible for any misuse.

---

## 👨‍💻 Author

**[Youssef]**

[![LinkedIn](https://img.shields.io/badge/LinkedIn-Connect-blue?style=flat&logo=linkedin)](https://linkedin.com/in/YOUR_PROFILE)
[![GitHub](https://img.shields.io/badge/GitHub-Follow-black?style=flat&logo=github)](https://github.com/YOUR_USERNAME)

---

<div align="center">

⭐ **If this helped you, drop a star!** ⭐

</div>
