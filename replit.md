# Overview

Smart Web Application Attack Replay Generator is a Python-based security research tool designed to parse web server logs (Apache, Nginx, WAF), detect malicious attack patterns, and automatically generate executable replay scripts. The tool provides both a CLI interface and an interactive Streamlit dashboard for analyzing attack traffic and creating Python/cURL scripts for security testing and ethical hacking purposes.

The application focuses on detecting five primary attack vectors: SQL Injection, Cross-Site Scripting (XSS), Directory Traversal, Command Injection, and File Inclusion (LFI/RFI). It extracts critical metadata (IP addresses, timestamps, User-Agent, URLs, payloads) and generates comprehensive reports in JSON format.

# User Preferences

Preferred communication style: Simple, everyday language.

# System Architecture

## Application Structure

The project follows a modular three-tier architecture:

1. **Parser Layer** (`parser/log_parser.py`)
   - Handles log file parsing for Apache and Nginx formats
   - Uses regex pattern matching to extract structured data from unstructured log entries
   - Performs URL decoding and query parameter extraction
   - Returns normalized dictionaries with IP, timestamp, HTTP method, URL, status code, User-Agent, and referrer

2. **Detection Layer** (`detector/attack_detector.py`)
   - Implements rule-based attack detection engine
   - Maintains dictionary of regex patterns for each attack category
   - Scans URLs, query parameters, and request bodies for malicious payloads
   - Returns attack type classification and matched patterns

3. **Generation Layer** (`generator/replay_generator.py`)
   - Creates executable Python scripts using the `requests` library
   - Generates equivalent cURL commands for CLI-based replay
   - Preserves original attack metadata (IP, timestamp, User-Agent)
   - Outputs scripts to `generated_attacks/` directory

## Frontend Architecture

The application uses **Streamlit** as the web framework, providing:

- Multi-tab interface for different workflow stages
- File upload handling for custom log files
- Sample log file loading for demonstration
- Real-time analysis dashboard with attack statistics
- Interactive data visualization using pandas DataFrames
- Script download and export functionality via ZIP files

**Design rationale**: Streamlit was chosen for rapid prototyping of data-driven interfaces without requiring separate frontend/backend development. It provides reactive UI updates and built-in file handling.

## Pattern Matching Strategy

Attack detection relies on **compiled regular expressions** rather than machine learning:

**Pros**:
- Deterministic, explainable results
- No training data required
- Low computational overhead
- Easy to extend with new patterns

**Cons**:
- Requires manual pattern curation
- May produce false positives/negatives
- Cannot detect novel attack variations

**Alternatives considered**: Machine learning-based anomaly detection was considered but rejected due to complexity and lack of labeled training data.

## Data Flow

1. User uploads log file or loads sample → `app.py`
2. Log content passed to `LogParser.parse_log_file()` → structured entries
3. Each entry analyzed by `AttackDetector` → attack classifications
4. Detected attacks passed to `ReplayGenerator` → Python/cURL scripts
5. Results displayed in Streamlit dashboard + downloadable artifacts

## File Organization

```
/parser          - Log parsing module
/detector        - Attack detection engine
/generator       - Script generation utilities
app.py           - Streamlit web application
main.py          - CLI entry point (minimal)
sample.log       - Demo attack log file
pyproject.toml   - Python dependencies
```

# External Dependencies

## Core Python Libraries

- **streamlit** - Web application framework for interactive dashboard
- **pandas** - Data manipulation and tabular display
- **requests** - HTTP library (used in generated replay scripts)
- **re** (stdlib) - Regular expression pattern matching
- **json** (stdlib) - Report generation and data serialization
- **urllib.parse** (stdlib) - URL parsing and query string handling
- **zipfile** (stdlib) - Bundling generated scripts for download
- **io.BytesIO** (stdlib) - In-memory file handling for downloads

## No External Services

This application operates entirely locally with no external API calls, databases, or cloud services. All processing happens in-memory or through local file system operations.

## Future Integration Points

The architecture supports potential additions:

- **Database integration** - Could add SQLite/PostgreSQL for persistent storage of analysis results
- **SIEM integration** - Export capability to Splunk, ELK Stack, or other security platforms
- **Threat intelligence feeds** - Enrichment with IP reputation, CVE data
- **Sandboxed replay environment** - Docker-based isolated testing infrastructure