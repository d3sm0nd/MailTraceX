import re
import sys
import time
import base64
import requests
from email import message_from_string
from datetime import datetime

# ===============================
# CONFIG
# ===============================

VT_API_KEY = "PASTE_YOUR_VIRUSTOTAL_API_KEY_HERE"
VT_URL_SCAN = "https://www.virustotal.com/api/v3/urls"

# ===============================
# UTILITY FUNCTIONS
# ===============================

def extract_ips(text):
    pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    return list(set(re.findall(pattern, text)))

def extract_links(text):
    pattern = r'(https?://[^\s<>"]+|www\.[^\s<>"]+)'
    return list(set(re.findall(pattern, text)))

def parse_auth_results(header_text):
    results = {"SPF": "Not Found", "DKIM": "Not Found", "DMARC": "Not Found"}
    text = header_text.lower()

    if "spf=pass" in text:
        results["SPF"] = "PASS"
    elif "spf=fail" in text:
        results["SPF"] = "FAIL"

    if "dkim=pass" in text:
        results["DKIM"] = "PASS"
    elif "dkim=fail" in text:
        results["DKIM"] = "FAIL"

    if "dmarc=pass" in text:
        results["DMARC"] = "PASS"
    elif "dmarc=fail" in text:
        results["DMARC"] = "FAIL"

    return results

def analyze_links(links):
    suspicious = []
    shorteners = ["bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly"]

    for link in links:
        if re.search(r'https?://\d+\.\d+\.\d+\.\d+', link):
            suspicious.append((link, "IP-based URL"))

        for s in shorteners:
            if s in link:
                suspicious.append((link, "Shortened URL"))

    return suspicious

def parse_received_headers(msg):
    return msg.get_all("Received", [])

def parse_timestamps(received_headers):
    timestamps = []
    for r in received_headers:
        match = re.search(r';\s*(.*)', r)
        if match:
            try:
                timestamps.append(datetime.strptime(match.group(1)[:31], "%a, %d %b %Y %H:%M:%S"))
            except:
                pass
    return timestamps

# ===============================
# VIRUSTOTAL FUNCTIONS
# ===============================

def vt_scan_url(url):
    headers = {
        "x-apikey": VT_API_KEY
    }

    data = {
        "url": url
    }

    response = requests.post(VT_URL_SCAN, headers=headers, data=data)
    if response.status_code != 200:
        return None

    scan_id = response.json()["data"]["id"]
    return vt_get_report(scan_id)

def vt_get_report(scan_id):
    headers = {
        "x-apikey": VT_API_KEY
    }

    report_url = f"{VT_URL_SCAN}/{scan_id}"

    # Wait for analysis
    time.sleep(3)

    response = requests.get(report_url, headers=headers)
    if response.status_code != 200:
        return None

    stats = response.json()["data"]["attributes"]["last_analysis_stats"]
    return stats

# ===============================
# RISK SCORING
# ===============================

def calculate_risk(auth, ip_count, timestamps, suspicious_links, vt_malicious):
    score = 0
    reasons = []

    if auth["SPF"] != "PASS":
        score += 40
        reasons.append("SPF failed or missing")

    if auth["DKIM"] != "PASS":
        score += 30
        reasons.append("DKIM failed or missing")

    if auth["DMARC"] != "PASS":
        score += 20
        reasons.append("DMARC failed or missing")

    if ip_count > 5:
        score += 10
        reasons.append("Excessive mail relay hops")

    if suspicious_links:
        score += 20
        reasons.append("Suspicious URLs detected")

    if vt_malicious > 0:
        score += 40
        reasons.append("VirusTotal flagged malicious URL")

    if not timestamps:
        score += 10
        reasons.append("Timestamp parsing failed")

    verdict = "LOW RISK"
    if score >= 70:
        verdict = "HIGH RISK (Likely Phishing)"
    elif score >= 40:
        verdict = "MEDIUM RISK"

    return score, verdict, reasons

# ===============================
# MAIN ANALYZER
# ===============================

def analyze_email_header(raw_header):
    msg = message_from_string(raw_header)

    print("\n" + "="*65)
    print(" EMAIL HEADER FORENSIC ANALYSIS REPORT ")
    print("="*65)

    # Basic Fields
    print("\n[+] BASIC HEADER FIELDS")
    for field in ["From", "To", "Subject", "Date", "Message-ID", "Return-Path"]:
        print(f"{field}: {msg.get(field)}")

    # Received Headers
    received = parse_received_headers(msg)
    print("\n[+] MAIL ROUTING (RECEIVED HEADERS)")
    for i, r in enumerate(received, 1):
        print(f"Hop {i}: {r}")

    # IP Analysis
    ips = extract_ips(raw_header)
    print("\n[+] EXTRACTED IP ADDRESSES")
    for ip in ips:
        print(f"- {ip}")

    # Authentication
    auth = parse_auth_results(raw_header)
    print("\n[+] AUTHENTICATION RESULTS")
    for k, v in auth.items():
        print(f"{k}: {v}")

    # Timestamp Analysis
    timestamps = parse_timestamps(received)
    print("\n[+] TIMESTAMPS")
    if timestamps:
        for t in timestamps:
            print(f"- {t}")
    else:
        print("No valid timestamps found")

    # Link Extraction
    links = extract_links(raw_header)
    suspicious_links = analyze_links(links)

    print("\n[+] EXTRACTED LINKS")
    if links:
        for link in links:
            print(f"- {link}")
    else:
        print("No links found")

    print("\n[+] SUSPICIOUS LINKS")
    for link, reason in suspicious_links:
        print(f"- {link} ({reason})")

    # VirusTotal Scan
    vt_malicious = 0
    if links:
        print("\n[+] VIRUSTOTAL URL SCAN")
        for link in links:
            print(f"Scanning: {link}")
            result = vt_scan_url(link)
            if result:
                malicious = result.get("malicious", 0)
                suspicious = result.get("suspicious", 0)
                vt_malicious += malicious
                print(f"  Malicious: {malicious}, Suspicious: {suspicious}")
            else:
                print("  VT scan failed or rate-limited")

    # Risk Assessment
    score, verdict, reasons = calculate_risk(
        auth,
        len(ips),
        timestamps,
        suspicious_links,
        vt_malicious
    )

    print("\n[+] FINAL RISK ASSESSMENT")
    print(f"Risk Score: {score}/100")
    print(f"Verdict: {verdict}")

    if reasons:
        print("\nReasons:")
        for r in reasons:
            print(f"- {r}")

    print("\n" + "="*65)
    print(" ANALYSIS COMPLETE ")
    print("="*65)

# ===============================
# ENTRY POINT
# ===============================

if __name__ == "__main__":
    print("\nPaste FULL email header below.")
    print("Press CTRL+D (Linux/Mac) or CTRL+Z + Enter (Windows)\n")

    raw_header = sys.stdin.read()
    analyze_email_header(raw_header)
