# 🦅 RedHawk — Automated Red Team Recon Framework

A modular, fast recon framework that automates subdomain enumeration, port scanning,
service fingerprinting, OSINT aggregation, and web asset screenshot capture —
outputting a unified JSON + HTML report.

---

## Features

| Module | Description |
|---|---|
| **Subdomain Enum** | DNS brute-force + crt.sh CT logs + HackerTarget passive |
| **Port Scanner** | Multi-threaded TCP scan with service fingerprinting & banner grabbing |
| **Shodan Intel** | Passive banner/CVE lookup via Shodan API (no packets to target) |
| **OSINT Harvester** | Emails, employees, hosts via theHarvester or built-in scrapers |
| **Screenshot Engine** | Headless Chromium auto-captures all live web assets |
| **Reporter** | Self-contained HTML report + machine-readable JSON |

---

## Installation

```bash
git clone https://github.com/yourname/redhawk.git
cd redhawk
pip install -r requirements.txt

# Optional: install theHarvester for full OSINT
pip install theHarvester

# Optional: install Chromium for screenshots
# Debian/Ubuntu:
apt install chromium-browser
# macOS:
brew install --cask google-chrome
```

---

## Usage

```bash
# Run all modules
python3 redhawk.py --target example.com --all --shodan-key YOUR_KEY

# Specific modules
python3 redhawk.py --target example.com --subdomains --ports --osint

# Custom options
python3 redhawk.py --target example.com --all \
  --wordlist /path/to/wordlist.txt \
  --threads 100 \
  --top-ports 500 \
  --timeout 5 \
  --output /tmp/recon \
  --verbose
```

### Options

| Flag | Default | Description |
|---|---|---|
| `--target / -t` | required | Target domain |
| `--all / -a` | false | Enable all modules |
| `--subdomains` | false | Run subdomain enumeration |
| `--ports` | false | Run port scanner |
| `--shodan` | false | Run Shodan intel |
| `--osint` | false | Run OSINT harvester |
| `--screenshots` | false | Capture screenshots |
| `--shodan-key` | `$SHODAN_API_KEY` | Shodan API key |
| `--wordlist` | built-in | Custom subdomain wordlist |
| `--threads` | 50 | Thread count |
| `--top-ports` | 1000 | Ports to scan |
| `--timeout` | 3 | Socket timeout (seconds) |
| `--output / -o` | `./output` | Output directory |
| `--json-only` | false | Skip HTML report |
| `--verbose / -v` | false | Verbose output |

---

## Output

Each run creates a timestamped directory under `--output`:

```
output/
└── example_com_20241201_143022/
    ├── redhawk_report.html   ← Self-contained HTML report
    ├── redhawk_report.json   ← Machine-readable data
    └── screenshots/
        ├── www_example_com_https_a1b2c3d4.png
        └── ...
```

### JSON structure

```json
{
  "meta": { "target": "...", "started_at": "...", "finished_at": "..." },
  "subdomains": ["www.example.com", "mail.example.com"],
  "ports": {
    "93.184.216.34": [
      { "port": 80, "state": "open", "service": "http", "banner": "..." }
    ]
  },
  "shodan": {
    "hosts": [{ "ip": "...", "org": "...", "vulns": ["CVE-..."] }]
  },
  "osint": {
    "emails": ["admin@example.com"],
    "hosts": [...],
    "source": "theHarvester"
  },
  "screenshots": [
    { "url": "https://www.example.com", "file": "...", "base64": "..." }
  ]
}
```

---

## Environment Variables

```bash
export SHODAN_API_KEY="your_shodan_key_here"
```

---

## Legal

> **RedHawk is for authorized penetration testing and security research only.**
> Running recon against targets without explicit written permission is illegal.
> The authors are not responsible for misuse of this tool.

---

## Module Architecture

```
redhawk.py                  ← Entry point & orchestrator
modules/
  subdomain_enum.py         ← DNS brute-force + CT logs + HackerTarget
  port_scanner.py           ← TCP scan + banner grab + service map
  shodan_intel.py           ← Shodan API passive intel
  harvester.py              ← theHarvester wrapper + fallback scrapers
  screenshot.py             ← Headless Chromium capture engine
  reporter.py               ← HTML + JSON report generator
```
