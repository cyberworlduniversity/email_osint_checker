# 📧 Email OSINT Checker — Breach Detection Tool


## Get this repository

Clone the current project (this repository's canonical GitHub URL), then follow the installation and usage steps below.

```bash
git clone https://github.com/cyberworlduniversity/email_osint_checker.git
cd email_osint_checker
```

> **Author:** [hemanathan115](https://github.com/hemanathan115)  
> **Category:** OSINT / Cybersecurity Toolkit  
> **Tool #10** in the OSINT Kit

---

## 🔍 What It Does

**Email OSINT Checker** is a Python-based command-line tool that checks whether an email address has appeared in known data breaches or leaked credential databases. It aggregates results from multiple public and semi-public sources to give a comprehensive breach overview.

---

## ✨ Features

| Feature | Description |
|---|---|
| 🔎 **Multi-Source Check** | Queries EmailRep.io, HIBP, DeHashed, LeakCheck.io |
| 🧠 **Local Heuristic Analysis** | Detects disposable emails, suspicious patterns — no API needed |
| #️⃣ **Hash Generation** | Produces MD5 & SHA-1 hashes of the email for cross-referencing |
| 📋 **Batch Mode** | Check hundreds of emails from a `.txt` file |
| 💾 **JSON Reports** | Auto-saves detailed scan reports per email |
| 🎨 **Colorized Terminal UI** | Clear, color-coded results in the terminal |
| 🐍 **Zero Dependencies** | Runs with Python 3.6+ standard library only |

---

## 🚀 Quick Start

### Requirements
- Python 3.6 or higher
- No external packages required for basic usage

### Installation

```bash
# Clone the repo
git clone https://github.com/cyberworlduniversity/email_osint_checker.git
cd email_osint_checker

# Make executable (Linux/macOS)
chmod +x email_osint_checker.py
```

---

## 🛠️ Usage

### Single Email (Interactive)
```bash
python email_osint_checker.py
# Then enter: target@example.com
```

### Single Email (Direct)
```bash
python email_osint_checker.py target@example.com
```

### With API Keys (Recommended)
```bash
python email_osint_checker.py target@example.com \
  --hibp-key YOUR_HIBP_KEY \
  --leakcheck-key YOUR_LEAKCHECK_KEY
```

### Batch Mode (Multiple Emails)
```bash
# emails.txt — one email per line
python email_osint_checker.py --batch emails.txt
```

### Save Report to Custom File
```bash
python email_osint_checker.py target@example.com --output report.json
```

### Full Options
```
usage: email_osint_checker.py [-h] [--hibp-key KEY] [--dehashed-key KEY]
                               [--dehashed-user EMAIL] [--leakcheck-key KEY]
                               [--output FILE] [--no-banner] [--batch FILE]
                               [email]

positional arguments:
  email                 Target email address to check

optional arguments:
  -h, --help            Show this help message
  --hibp-key KEY        HaveIBeenPwned v3 API key
  --dehashed-key KEY    DeHashed API key
  --dehashed-user EMAIL Your DeHashed account email
  --leakcheck-key KEY   LeakCheck.io API key
  --output FILE         Save JSON report to this file
  --no-banner           Suppress ASCII banner
  --batch FILE          Check multiple emails from a text file
```

---

## 🔑 API Keys

| Source | Free? | How to Get |
|---|---|---|
| **EmailRep.io** | ✅ Free (rate limited) | No key needed / [emailrep.io](https://emailrep.io) |
| **HaveIBeenPwned** | 💰 Paid | [haveibeenpwned.com/API/Key](https://haveibeenpwned.com/API/Key) |
| **DeHashed** | 💰 Paid | [dehashed.com](https://dehashed.com) |
| **LeakCheck.io** | ✅ Free tier | [leakcheck.io](https://leakcheck.io) |

> 💡 **Tip:** Even without API keys, the tool performs local heuristic analysis and EmailRep.io checks for free.

---

## 📤 Sample Output

```
══════════════════════════════════════════════════════════════
  TARGET: example@gmail.com
══════════════════════════════════════════════════════════════

  🔍 Local Heuristic Analysis
  Email:     example@gmail.com
  Domain:    gmail.com
  Risk:      LOW
  Flags:
    ✅ No suspicious patterns detected
  Hashes:
    MD5 : 23463b99b62a72f26ed677cc556c44e8
    SHA1: 567159D422A9E610727F52A3E05EB3D70059879E

  🔍 EmailRep.io — Reputation & Breach Check
  ✅ Clean — No breaches found.
  • Reputation: medium
  • Data Breach: False
  • Credentials Leaked: False
```

---

## 📄 JSON Report Sample

```json
{
  "tool": "Email OSINT Checker",
  "author": "hemanathan115",
  "github": "https://github.com/hemanathan115",
  "timestamp": "2025-01-01T12:00:00",
  "target_email": "target@example.com",
  "local_analysis": {
    "risk_level": "LOW",
    "flags": ["✅ No suspicious patterns detected"],
    "hashes": { "md5": "...", "sha1": "..." }
  },
  "api_results": [...]
}
```

---

## ⚙️ How It Works

```
Email Input
    │
    ▼
┌─────────────────────────────┐
│  1. Validate Email Format   │
└────────────┬────────────────┘
             │
    ┌────────▼─────────┐
    │  Local Analysis  │  ← No API (instant)
    │  - Disposable?   │
    │  - Suspicious?   │
    │  - Hash it       │
    └────────┬─────────┘
             │
    ┌────────▼──────────────┐
    │  EmailRep.io          │  ← Free API
    │  (reputation + breach)│
    └────────┬──────────────┘
             │
    ┌────────▼──────────────┐
    │  HIBP / DeHashed /    │  ← Paid APIs (optional)
    │  LeakCheck.io         │
    └────────┬──────────────┘
             │
    ┌────────▼──────────────┐
    │  Save JSON Report     │
    └───────────────────────┘
```

---

## ⚠️ Legal Disclaimer

> This tool is intended for **educational and ethical security research only**.  
> Only check email addresses you own or have explicit written permission to audit.  
> The author is **not responsible** for any misuse of this tool.  
> Always comply with the Terms of Service of any API you use.

---

## 📁 File Structure

```
10-email-osint-checker/
├── email_osint_checker.py   # Main tool
├── requirements.txt         # Dependencies (stdlib only)
└── README.md                # This file
```

---

## 🤝 Contributing

Pull requests are welcome! For major changes, please open an issue first.

1. Fork the repo
2. Create your branch: `git checkout -b feature/new-source`
3. Commit: `git commit -m "Add new breach source"`
4. Push: `git push origin feature/new-source`
5. Open a Pull Request

---

## 📜 License

MIT License — see [LICENSE](LICENSE) for details.

---

<div align="center">

**Made with ❤️ by [hemanathan115](https://github.com/hemanathan115)**  
⭐ Star this repo if it helped you!

</div>
