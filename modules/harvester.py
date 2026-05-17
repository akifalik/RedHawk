"""
modules/harvester.py
OSINT aggregation via theHarvester (subprocess wrapper)
with a fallback pure-Python passive scraper when theHarvester
is not installed.
"""

import subprocess
import shutil
import json
import re
import requests
from typing import Dict, List, Any


# ── Fallback: pure-Python passive scrapers ────────────────────────────────────

def _scrape_emails_from_text(text: str, domain: str) -> List[str]:
    pattern = rf"[a-zA-Z0-9._%+\-]+@(?:[a-zA-Z0-9\-]+\.)*{re.escape(domain)}"
    return list(set(re.findall(pattern, text, re.IGNORECASE)))


def _passive_emails_google(domain: str) -> List[str]:
    """Scrape email-like strings from a Google search (no API needed)."""
    emails = []
    try:
        headers = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"}
        url = f"https://www.google.com/search?q=%40{domain}&num=50"
        r = requests.get(url, headers=headers, timeout=10)
        emails = _scrape_emails_from_text(r.text, domain)
    except Exception:
        pass
    return emails


def _passive_hackertarget(domain: str) -> Dict[str, List[str]]:
    emails, hosts = [], []
    try:
        r = requests.get(f"https://api.hackertarget.com/hostsearch/?q={domain}", timeout=10)
        for line in r.text.strip().split("\n"):
            if "," in line:
                parts = line.split(",")
                hosts.append(parts[0].strip())
    except Exception:
        pass
    return {"emails": emails, "hosts": hosts}


def _passive_emailhunter(domain: str) -> List[str]:
    """Hunter.io public preview (no key, limited results)."""
    emails = []
    try:
        r = requests.get(
            f"https://hunter.io/api/v2/domain-search?domain={domain}&api_key=",
            timeout=10
        )
        data = r.json()
        for item in data.get("data", {}).get("emails", []):
            emails.append(item.get("value", ""))
    except Exception:
        pass
    return [e for e in emails if e]


# ── Main class ────────────────────────────────────────────────────────────────

class HarvesterOSINT:
    def __init__(self, target: str, verbose: bool = False):
        self.target = target
        self.verbose = verbose
        self.harvester_bin = shutil.which("theHarvester") or shutil.which("theharvester")

    def _run_theharvester(self) -> Dict[str, Any]:
        """Run theHarvester CLI and parse its JSON output."""
        sources = "bing,duckduckgo,google,linkedin,twitter,yahoo,hunter,securitytrails"
        cmd = [
            self.harvester_bin,
            "-d", self.target,
            "-b", sources,
            "-f", "/tmp/rh_harvester_out",
        ]
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120,
            )
            if self.verbose:
                print(proc.stdout[-2000:] if proc.stdout else "")
        except subprocess.TimeoutExpired:
            print("    [!] theHarvester timed out after 120s")
            return {}
        except Exception as e:
            print(f"    [!] theHarvester error: {e}")
            return {}

        # Parse output JSON
        try:
            with open("/tmp/rh_harvester_out.json") as f:
                raw = json.load(f)
            return {
                "emails": raw.get("emails", []),
                "hosts": raw.get("hosts", []),
                "ips": raw.get("ips", []),
                "linkedin_people": raw.get("linkedin_people", []),
                "linkedin_links": raw.get("linkedin_links", []),
                "twitter": raw.get("twitter_people", []),
                "interesting_urls": raw.get("interesting_urls", []),
                "source": "theHarvester",
            }
        except Exception:
            # theHarvester sometimes writes only .xml — parse stdout instead
            emails = []
            hosts = []
            for line in proc.stdout.split("\n"):
                line = line.strip()
                if "@" in line and self.target in line:
                    emails.append(line)
                elif self.target in line and not line.startswith("["):
                    hosts.append(line)
            return {
                "emails": list(set(emails)),
                "hosts": list(set(hosts)),
                "source": "theHarvester (stdout fallback)",
            }

    def _run_fallback(self) -> Dict[str, Any]:
        """Pure-Python passive OSINT when theHarvester is unavailable."""
        print("    [~] theHarvester not found — using built-in passive scrapers")
        ht = _passive_hackertarget(self.target)
        emails_g = _passive_emails_google(self.target)
        emails_h = _passive_emailhunter(self.target)

        all_emails = list(set(ht.get("emails", []) + emails_g + emails_h))
        all_hosts  = list(set(ht.get("hosts", [])))

        return {
            "emails": all_emails,
            "hosts": all_hosts,
            "ips": [],
            "linkedin_people": [],
            "source": "built-in passive (hackertarget, google, hunter.io)",
        }

    def run(self) -> Dict[str, Any]:
        if self.harvester_bin:
            print(f"    [~] theHarvester found at {self.harvester_bin}")
            data = self._run_theharvester()
        else:
            data = self._run_fallback()

        # Deduplicate and clean up
        for key in ("emails", "hosts", "ips"):
            if key in data:
                data[key] = sorted(set(str(v).strip() for v in data[key] if v))

        return data
