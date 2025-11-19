# 🔐 Smart Web Application Attack Replay Generator

A Python-based security research tool that parses web server logs, automatically detects attack payloads, and generates executable replay scripts for security testing and ethical hacking purposes.

## 📋 Table of Contents

- [Features](#features)
- [Project Structure](#project-structure)
- [Installation](#installation)
- [Usage](#usage)
- [Supported Attack Types](#supported-attack-types)
- [Output Examples](#output-examples)
- [Educational Purpose](#educational-purpose)
- [License](#license)

## ✨ Features

### Core Capabilities

- **Log Parsing**: Supports Apache and Nginx web server log formats
- **Attack Detection**: Uses regex pattern matching to identify common web attacks
- **Automatic Extraction**: Captures IP addresses, timestamps, User-Agent, URLs, HTTP methods, and payloads
- **Script Generation**: Creates both Python (requests) and cURL replay scripts
- **Interactive Dashboard**: Streamlit-based web UI for easy analysis
- **Comprehensive Reports**: JSON-formatted summary reports with detailed statistics

### Attack Detection Engine

The tool can detect the following attack types:

- **SQL Injection** - UNION SELECT, OR 1=1, database manipulation
- **Cross-Site Scripting (XSS)** - Script injections, event handlers, iframe attacks
- **Directory Traversal** - Path traversal attempts, /etc/passwd access
- **Command Injection** - Shell command execution, pipe operators
- **File Inclusion** - LFI/RFI attempts, php:// wrappers, data:// URIs

## 📁 Project Structure

```
smart-web-attack-replay-generator/
│
├── app.py                      # Main Streamlit application
├── sample.log                  # Sample log file with attack patterns
├── README.md                   # This file
├── pyproject.toml             # Python dependencies
│
├── parser/
│   └── log_parser.py          # Log parsing module (LogParser class)
│
├── detector/
│   └── attack_detector.py     # Attack detection module (AttackDetector class)
│
├── generator/
│   └── replay_generator.py    # Script generation module (ReplayGenerator class)
│
└── generated_attacks/          # Output directory for generated scripts
    ├── attack_1_SQL_Injection.py
    ├── attack_1_SQL_Injection.sh
    ├── attack_2_XSS.py
    ├── attack_2_XSS.sh
    └── attack_summary.json
```

## 🚀 Installation

### Prerequisites

- Python 3.11 or higher
- pip package manager

### Setup Instructions

1. **Clone or download the project**

2. **Install dependencies**

```bash
pip install streamlit pandas requests
```

Or using the project file:

```bash
pip install -e .
```

3. **Verify installation**

```bash
streamlit --version
python --version
```

## 💻 Usage

### Running the Application

Start the Streamlit web interface:

```bash
streamlit run app.py --server.port 5000
```

The application will open in your default browser at `http://localhost:5000`

### Step-by-Step Workflow

#### Step 1: Load Log File

- Click **"Load Sample Log"** in the sidebar to use the provided sample, or
- Upload your own Apache/Nginx log file using the file uploader

#### Step 2: Analyze Logs

- Review the log preview
- Click **"🔍 Analyze Log File"** button
- Wait for parsing and attack detection to complete

#### Step 3: Review Detected Attacks

- Navigate to the **"📊 Attack Dashboard"** tab
- Filter attacks by type
- Expand each attack to view detailed information:
  - Attack type and matched pattern
  - Source IP and timestamp
  - HTTP method and status code
  - Full URL and payload
  - User-Agent string

#### Step 4: Generate Replay Scripts

- Go to the **"💾 Generate Scripts"** tab
- Click **"🚀 Generate All Replay Scripts"**
- Download the ZIP file containing:
  - Python scripts (executable with `requests` library)
  - cURL commands (for manual testing)
  - JSON summary report

#### Step 5: Analyze Statistics

- Visit the **"📈 Statistics"** tab for:
  - Attack type distribution charts
  - Top attacking IP addresses
  - Exportable JSON reports

### Using Generated Scripts

#### Python Replay Script

```bash
# Make executable
chmod +x generated_attacks/attack_1_SQL_Injection.py

# Run the script
python3 generated_attacks/attack_1_SQL_Injection.py
```

#### cURL Replay Script

```bash
# Make executable
chmod +x generated_attacks/attack_1_SQL_Injection.sh

# Run the script
bash generated_attacks/attack_1_SQL_Injection.sh
```

## 🎯 Supported Attack Types

### 1. SQL Injection

**Patterns Detected:**
- `UNION SELECT` statements
- `OR 1=1` / `AND 1=1` conditions
- SQL comments (`--`, `#`, `/* */`)
- Database manipulation (`DROP TABLE`, `INSERT INTO`, `DELETE FROM`)
- Database functions (`@@version`, `user()`, `database()`)

**Example:**
```
/products.php?id=5 UNION SELECT username,password FROM users--
```

### 2. Cross-Site Scripting (XSS)

**Patterns Detected:**
- `<script>` tags and variants
- JavaScript event handlers (`onerror`, `onload`, `onclick`)
- `<iframe>` injections
- JavaScript functions (`alert()`, `eval()`, `document.cookie`)

**Example:**
```
/search.php?q=<script>alert('XSS')</script>
```

### 3. Directory Traversal

**Patterns Detected:**
- Path traversal sequences (`../`, `..\\`)
- URL-encoded variants (`%2e%2e/`)
- Attempts to access `/etc/passwd`, `/etc/shadow`
- Windows path attempts (`c:\windows\`)

**Example:**
```
/download.php?file=../../../../etc/passwd
```

### 4. Command Injection

**Patterns Detected:**
- Shell commands (`ls`, `cat`, `wget`, `curl`)
- Command chaining (`;`, `&&`, `||`, `|`)
- Command substitution (`` ` ` ``, `$()`)
- Shell references (`/bin/bash`, `cmd.exe`)

**Example:**
```
/api/exec?cmd=ls;cat /etc/shadow
```

### 5. File Inclusion (LFI/RFI)

**Patterns Detected:**
- PHP wrappers (`php://filter`, `php://input`)
- File protocol handlers (`file://`, `expect://`)
- Data URIs (`data://text/plain`)
- Remote file inclusion attempts

**Example:**
```
/view.php?page=php://filter/convert.base64-encode/resource=config
```

## 📤 Output Examples

### Python Replay Script

```python
#!/usr/bin/env python3
import requests
from datetime import datetime

attack_info = {
    "attack_type": "SQL Injection",
    "original_ip": "198.51.100.78",
    "timestamp": "19/Nov/2025:10:17:12 +0000",
    "method": "GET",
    "status_code": "500"
}

print(f"[*] Replaying SQL Injection attack")
print(f"[*] Original IP: {attack_info['original_ip']}")
# ... (continues with request execution)
```

### cURL Command

```bash
#!/bin/bash

# Attack Type: SQL Injection
# Original IP: 198.51.100.78
# Timestamp: 19/Nov/2025:10:17:12 +0000

curl -X GET \
  -H "User-Agent: sqlmap/1.0" \
  -i \
  "/products.php?id=5 UNION SELECT username,password FROM users--"
```

### JSON Summary Report

```json
{
  "total_attacks_detected": 24,
  "unique_ips": 15,
  "attack_breakdown": {
    "SQL Injection": 8,
    "XSS": 7,
    "Directory Traversal": 4,
    "Command Injection": 3,
    "File Inclusion": 2
  },
  "attacks": [...]
}
```

## 🎓 Educational Purpose

This tool is designed for:

- **Security Research**: Understand attack patterns and techniques
- **Penetration Testing**: Generate test cases for authorized security assessments
- **Educational Projects**: Learn about web application vulnerabilities
- **Log Analysis Training**: Practice analyzing real-world attack logs

### ⚠️ Important Legal Notice

This tool is **ONLY** for:
- Authorized security testing
- Educational and research purposes
- Systems you own or have explicit permission to test

**Unauthorized use against systems you do not own is illegal and unethical.**

## 🛠️ Technical Details

### Technologies Used

- **Python 3.11+**: Core programming language
- **Streamlit**: Interactive web UI framework
- **Pandas**: Data processing and analysis
- **Requests**: HTTP library for replay scripts
- **Regular Expressions**: Pattern matching for attack detection
- **urllib.parse**: URL parsing and query string handling

### Module Architecture

#### LogParser Class (`parser/log_parser.py`)

- Parses Apache and Nginx log formats
- Extracts structured data (IP, timestamp, method, URL, etc.)
- Handles URL decoding and query parameter parsing

#### AttackDetector Class (`detector/attack_detector.py`)

- Maintains regex patterns for each attack type
- Performs pattern matching on log entries
- Generates analysis reports with statistics

#### ReplayGenerator Class (`generator/replay_generator.py`)

- Creates executable Python scripts
- Generates cURL commands
- Produces JSON summary reports
- Manages output directory structure

## 📝 Sample Log Format

The tool supports standard Apache/Nginx combined log format:

```
IP - - [Timestamp] "Method URL HTTP/Version" Status Size "Referrer" "User-Agent"
```

Example:
```
192.168.1.100 - - [19/Nov/2025:10:15:23 +0000] "GET /index.php HTTP/1.1" 200 1234 "-" "Mozilla/5.0"
```

## 🔧 Customization

### Adding New Attack Patterns

Edit `detector/attack_detector.py` and add patterns to the `attack_patterns` dictionary:

```python
self.attack_patterns = {
    'Your Attack Type': [
        r"(your_regex_pattern_here)",
        r"(another_pattern)",
    ],
    # ... existing patterns
}
```

### Modifying Script Templates

Edit the `generate_python_script()` and `generate_curl_command()` methods in `generator/replay_generator.py`

## 📊 Features Summary

| Feature | Status |
|---------|--------|
| Apache Log Parsing | ✅ |
| Nginx Log Parsing | ✅ |
| SQL Injection Detection | ✅ |
| XSS Detection | ✅ |
| Directory Traversal Detection | ✅ |
| Command Injection Detection | ✅ |
| File Inclusion Detection | ✅ |
| Python Script Generation | ✅ |
| cURL Command Generation | ✅ |
| JSON Report Export | ✅ |
| Interactive Web UI | ✅ |
| ZIP Download | ✅ |
| Attack Statistics | ✅ |

## 🤝 Contributing

This is an educational project. Feel free to:
- Add new attack patterns
- Improve detection accuracy
- Enhance the UI/UX
- Add support for other log formats

## 📄 License

MIT License - Free for educational and research purposes

## 👨‍💻 Author

Created as a final year project for ethical hacking education.

## 📞 Support

For questions or issues:
- Review the code comments in each module
- Check the sample.log for example attack patterns
- Examine generated scripts for output format

---

**Remember: Use this tool responsibly and only on systems you are authorized to test!**
