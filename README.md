# 📧 MailTraceX

### Email Header & URL Forensic Analyzer

MailTraceX is a Python-based email forensics and phishing detection tool designed to analyze raw email headers and embedded URLs. It helps identify spoofed and malicious emails by extracting routing information, validating authentication mechanisms (SPF, DKIM, DMARC), detecting suspicious links, and scanning URLs using the VirusTotal API.

This tool is ideal for **SOC analysts, DFIR professionals, cybersecurity students, and blue team operations**.

---

## 🚀 Features

* 📩 Email header parsing and analysis
* 🌐 Mail routing path (Received headers) inspection
* 🧾 Sender IP extraction and hop count analysis
* 🔐 SPF, DKIM, and DMARC validation
* 🔗 URL extraction from email headers
* 🚨 Detection of suspicious links (IP-based, shortened URLs)
* 🧪 VirusTotal URL reputation scanning
* 📊 Risk-based phishing scoring system
* 🖥️ Command-line interface (CLI)
* 📁 Single-file, easy-to-run Python tool

---

## 🛠️ Tech Stack

* **Python 3**
* **VirusTotal API**
* `email`, `re`, `requests`, `datetime`
* Email forensics & phishing detection techniques

---

## 📂 Project Structure

```
MailTraceX/
├── email_header_analyzer_vt.py
└── README.md
```

---

## 🔧 Installation

### 1️⃣ Clone the Repository

```bash
git clone https://github.com/your-username/MailTraceX.git
cd MailTraceX
```

### 2️⃣ Install Dependencies

```bash
pip install requests
```

---

## 🔑 VirusTotal API Setup

1. Create a free account at [https://www.virustotal.com](https://www.virustotal.com)
2. Generate your API key
3. Open `email_header_analyzer_vt.py` and add your key:

```python
VT_API_KEY = "PASTE_YOUR_VIRUSTOTAL_API_KEY_HERE"
```

> ⚠️ **Note:** Free VirusTotal API has rate limits.

---

## ▶️ Usage

Run the tool from the terminal:

```bash
python email_header_analyzer_vt.py
```

* Paste the **full email header** (e.g., Gmail → *Show original*)
* Press:

  * **CTRL + D** (Linux / macOS)
  * **CTRL + Z + Enter** (Windows)

---

## 📊 Sample Output

```
[+] BASIC HEADER FIELDS
From: attacker@example.com
To: victim@example.com
Subject: Urgent Action Required

[+] AUTHENTICATION RESULTS
SPF: FAIL
DKIM: FAIL
DMARC: FAIL

[+] EXTRACTED LINKS
- https://bit.ly/3xyzAbc

[+] VIRUSTOTAL URL SCAN
Malicious: 3 | Suspicious: 2

[+] FINAL RISK ASSESSMENT
Risk Score: 85/100
Verdict: HIGH RISK (Likely Phishing)
```

---

## 🎯 Use Cases

* Phishing email investigation
* SOC alert triage
* Digital Forensics & Incident Response (DFIR)
* Cybersecurity education and demonstrations
* Blue team threat analysis

---

## 🧠 Risk Scoring Logic (Overview)

The risk score is calculated based on:

* SPF / DKIM / DMARC failures
* Number of mail relay hops
* Presence of suspicious URLs
* VirusTotal malicious detections
* Timestamp inconsistencies

**Score Interpretation:**

* `0–39` → Low Risk
* `40–69` → Medium Risk
* `70+` → High Risk (Likely Phishing)

---

## 🧑‍💼 Resume Description

> Developed **MailTraceX**, a Python-based email forensics tool that analyzes email headers, extracts routing paths, validates SPF/DKIM/DMARC, detects suspicious URLs, integrates VirusTotal scanning, and assigns risk scores for phishing detection.

---

## 🚀 Future Enhancements

* Web-based dashboard (Flask / FastAPI)
* PDF forensic report generation
* WHOIS & domain age analysis
* Bulk email header analysis
* SIEM-compatible JSON output
* Machine learning–based phishing classification

---

## ⚠️ Disclaimer

This tool is intended for **educational and defensive security purposes only**.
Do not use it for unauthorized scanning or malicious activities.

---

## ⭐ Support

If you find this project useful:

* ⭐ Star the repository
* 🍴 Fork it
* 🛠️ Contribute enhancements

---
