# 🛡️ Security Log Analyzer

<img width="769" height="621" alt="image" src="https://github.com/user-attachments/assets/6fadb44e-d97b-4957-9476-adf6297a880b" />

A Python-based security log analyzer with a graphical interface that detects suspicious activities such as SSH brute force attempts, SQL injection, XSS attacks, and directory scans from log files.

---

## 🚀 Features

* 📂 Load and analyze log files
* 🔍 Detects:

  * SSH brute force attempts
  * SQL injection patterns
  * Cross-site scripting (XSS) attempts
  * Directory and file probing scans
* 📊 Generates detailed security reports
* 🧮 Tracks:

  * Top attacker IPs
  * Most targeted usernames
  * Attack type distribution
* 💾 Export reports to:

  * JSON
  * CSV
* 🖥️ User-friendly GUI built with Tkinter

---

## 🧠 How It Works

The analyzer scans log files using pattern matching (regex) to identify known attack signatures.

It extracts useful data such as:

* Source IP addresses
* Targeted usernames
* Attack types

Then it generates a structured report with statistics and a calculated threat level.

---

## 📸 Interface Overview

* Load log file
* Analyze security events
* View detailed report
* Export results (JSON / CSV)

---

## 🛠️ Installation

### 1. Clone the repository

```bash
git clone https://github.com/yourusername/Security-Log-Analyzer.git
cd Security-Log-Analyzer
```

### 2. Run the program

```bash
python main.py
```

---

## ⚠️ Requirements

* Python 3.x
* No external dependencies (uses standard library only)

---

## 🧪 Testing Tips

Try analyzing:

* Linux authentication logs (`auth.log`)
* Web server logs (Apache/Nginx)
* Any text-based log file

### Example detections:

* Multiple failed SSH logins → 🚨 Brute force detected
* Suspicious SQL keywords → 🚨 SQL injection detected
* `<script>` tags → 🚨 XSS attempt detected

---

## ⚙️ Detection Logic

The tool uses regex patterns such as:

```python
SSH: Failed password for user from IP
SQL: SELECT, UNION, DROP in HTTP requests
XSS: <script> tags or encoded variants
Scan: wp-admin, .env, /etc/passwd
```

---

## 📊 Output Example

The generated report includes:

* Total suspicious events
* Attack type breakdown
* Top attacker IPs
* Most targeted users
* Threat level (LOW → CRITICAL)

---

## 🔒 Disclaimer

This tool is intended for **educational and defensive cybersecurity purposes only**.
Do not use it to analyze logs without proper authorization.


