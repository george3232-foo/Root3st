# Root3st -- Comprehensive OSINT Reconnaissance Tool

Root3st is a modular, CLI-based Open Source Intelligence (OSINT) tool that performs both passive and active reconnaissance on a variety of target types including IP addresses, domains, email addresses, usernames, phone numbers, names, and social media profiles.

## Features

- **IP Reconnaissance** -- Geolocation, WHOIS, reverse DNS, port scanning, Shodan & VirusTotal enrichment
- **Domain Reconnaissance** -- DNS enumeration, WHOIS, SSL certificate analysis, subdomain discovery (crt.sh), HTTP header fingerprinting, technology detection, robots.txt & security.txt
- **Email Reconnaissance** -- MX record validation, SPF/DMARC analysis, Gravatar profile lookup, HIBP breach check, Hunter.io verification
- **Username Search** -- Concurrent existence checks across 30+ platforms (GitHub, Reddit, Twitter/X, Instagram, LinkedIn, TikTok, Steam, and more)
- **Phone Number Analysis** -- Format parsing, country identification, carrier lookup (NumVerify)
- **Name / Person Search** -- Targeted Google dork generation for LinkedIn, Facebook, Twitter, GitHub, Reddit, and news
- **Social Media Profiling** -- Public API queries for GitHub, Reddit, GitLab profiles plus search dork generation
- **Report Generation** -- JSON and styled HTML reports saved automatically
- **Optional API Enrichment** -- Supports Shodan, VirusTotal, Hunter.io, HIBP, and NumVerify API keys for deeper results

## Installation

### Prerequisites

- Python 3.10 or later
- pip

### Install from source

```bash
git clone https://github.com/george3232-foo/Root3st.git
cd Root3st
pip install -e ".[dev]"
```

## Quick Start

```bash
# IP reconnaissance
root3st ip 8.8.8.8

# Domain reconnaissance
root3st domain example.com

# Email reconnaissance
root3st email user@example.com

# Username search across 30+ platforms
root3st username johndoe

# Phone number analysis
root3st phone "+15551234567"

# Person name search (generates dorks)
root3st name "John Doe"

# Social media profile lookup
root3st social johndoe
```

### Options

```
--config, -c PATH    Path to a YAML config file (default: ~/.root3st/config.yaml)
--output, -o DIR     Output directory for reports (default: ./reports)
--json-only          Output raw JSON to stdout instead of Rich formatting
--version            Show version
--help               Show help
```

## Configuration

Create `~/.root3st/config.yaml` to configure API keys and behaviour:

```yaml
# Optional API keys for enriched results
shodan_api_key: "your-shodan-key"
virustotal_api_key: "your-vt-key"
hunter_api_key: "your-hunter-key"
haveibeenpwned_api_key: "your-hibp-key"

# Behaviour
timeout: 15
max_concurrent: 20
port_scan_timeout: 1.5

# Custom port list (defaults to common 24 ports)
# ports: [22, 80, 443, 8080]

# Output
output_dir: "./reports"
```

API keys can also be set via environment variables: `SHODAN_API_KEY`, `VIRUSTOTAL_API_KEY`, `HUNTER_API_KEY`, `HAVEIBEENPWNED_API_KEY`, `NUMVERIFY_API_KEY`.

## Reports

Every scan automatically generates two report files in the output directory:

- **JSON** -- Machine-readable, suitable for piping into other tools
- **HTML** -- Styled dark-themed report viewable in any browser

## Architecture

```
root3st/
  __init__.py          # Package metadata
  cli.py               # Click-based CLI entry point
  config.py            # Configuration management (YAML + env vars)
  utils.py             # Shared HTTP, DNS, and validation helpers
  report.py            # JSON and HTML report generators
  modules/
    __init__.py
    ip_recon.py        # IP address module
    domain_recon.py    # Domain module
    email_recon.py     # Email module
    username_recon.py  # Username platform checker
    phone_recon.py     # Phone number module
    social_recon.py    # Social media / name module
tests/
  test_utils.py
  test_config.py
  test_phone_recon.py
  test_email_recon.py
  test_report.py
  test_cli.py
```

## Running Tests

```bash
pip install -e ".[dev]"
pytest -v
```

## Legal Disclaimer

This tool is intended for **authorised security research and lawful OSINT gathering only**. Users are solely responsible for ensuring they comply with all applicable laws and regulations. Do not use this tool against targets you do not have permission to investigate.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

---

*Created: 2026-03-07*
