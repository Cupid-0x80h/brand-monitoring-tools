# Domain TLD Checker

## Description

**Domain TLD Checker** is a Python-based tool designed to check domain variants across a large set of TLDs (Top-Level Domains). It takes a list of base domain names and checks for the existence and status of these domains under multiple TLDs using WHOIS and DNS queries.

This tool is ideal for tasks like domain reconnaissance, brand protection, and hunting potential lookalike domains in phishing or fraud investigations.

## Features

- 🔍 **Base Domain Extraction**: Uses `tldextract` to derive the meaningful base of a domain for flexible variant generation.
- 🌐 **Multi-TLD Expansion**: Automatically appends over 60 common TLDs to the base domain for scanning.
- 🧠 **WHOIS Intelligence**: Retrieves:
  - Registrar name
  - Domain creation, update, and expiration dates
  - Domain status and registrant organization (if available)
- 🧾 **DNS Queries**:
  - A and AAAA records (IP addresses)
  - NS (Name Servers)
  - MX (Mail Servers)
- ✅ **Error-Resilient**: Handles exceptions and logs WHOIS/DNS issues gracefully.
- 💾 **CSV Export**: Results are saved in a structured CSV format with rich detail.
- 🕒 **Politeness Delay**: Includes a delay between requests to avoid overloading public services.

## Requirements

- Python 3.x
- Libraries:
  - `python-whois`
  - `dnspython`
  - `tldextract`

Install the dependencies:

```bash
pip install python-whois dnspython tldextract
```

## How to Use

1. Prepare a text file with one domain name per line. Example (`input.txt`):
   ```
   example.com
   mybrand.io
   ```

2. Run the script:
   ```bash
   python domain_tld_checker.py
   ```

3. When prompted:
   - Provide the input file path (e.g., `input.txt`)
   - Provide the desired output CSV file path (e.g., `output.csv`)

4. Review the `output.csv` file for the results.

## Output Format

Each row in the CSV file will include:

- Original Input Domain
- Extracted Base Name
- TLD Variant Checked
- Full Domain Queried
- A/AAAA DNS resolution
- IP Addresses
- Name Servers
- Mail Servers
- WHOIS creation, update, expiration dates
- WHOIS registrar, status, and registrant organization
- Any errors or notes from the process

## Notes

- WHOIS data availability and accuracy depend on registrar policies and privacy protection services.
- DNS records show configuration and **do not imply legitimacy** or maliciousness.
- A default 0.8s delay is used between queries to be polite to external services.

## Legal Disclaimer

This tool is for **informational and investigative purposes only**. It does **not determine phishing** or malicious intent. Use the results as indicators for further manual investigation by trained professionals.

---

**License**: *Due to NDA, licensing is restricted. Not intended for public distribution.*
