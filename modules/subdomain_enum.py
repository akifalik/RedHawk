"""
modules/subdomain_enum.py
Subdomain enumeration via:
  1. DNS brute-force using a built-in wordlist (or user-supplied one)
  2. Certificate Transparency logs (crt.sh)
  3. HackerTarget API (passive)
"""

import dns.resolver
import requests
import concurrent.futures
import threading
import json
import re
from typing import List

# Built-in compact wordlist for quick brute-force
BUILTIN_WORDLIST = [
    "www", "mail", "remote", "blog", "webmail", "server", "ns1", "ns2",
    "smtp", "secure", "vpn", "m", "shop", "ftp", "mail2", "test", "portal",
    "dns", "dns1", "dns2", "mx", "api", "dev", "staging", "admin", "login",
    "app", "apps", "beta", "cdn", "cloud", "demo", "help", "intranet",
    "media", "mobile", "monitor", "news", "old", "prod", "qa", "s3",
    "services", "support", "web", "wiki", "assets", "auth", "backup",
    "board", "cms", "conf", "confluence", "cpanel", "dashboard", "data",
    "db", "docs", "email", "erp", "file", "files", "git", "gitlab",
    "grafana", "hub", "id", "images", "img", "internal", "jenkins",
    "jira", "kibana", "ldap", "log", "logs", "mx1", "mx2", "nat",
    "office", "ops", "panel", "pay", "proxy", "redis", "registry",
    "repo", "sandbox", "search", "sftp", "share", "sso", "static",
    "status", "store", "stream", "svc", "test2", "tracking", "upload",
    "v2", "vault", "video", "webdav", "ws", "zabbix",
]


class SubdomainEnumerator:
    def __init__(self, target: str, wordlist: str = "", threads: int = 50, verbose: bool = False):
        self.target = target
        self.threads = threads
        self.verbose = verbose
        self.found = set()
        self.lock = threading.Lock()

        # Load wordlist
        if wordlist:
            try:
                with open(wordlist) as f:
                    self.wordlist = [l.strip() for l in f if l.strip()]
                print(f"    [~] Loaded {len(self.wordlist)} words from {wordlist}")
            except FileNotFoundError:
                print(f"    [!] Wordlist not found, using built-in list")
                self.wordlist = BUILTIN_WORDLIST
        else:
            self.wordlist = BUILTIN_WORDLIST

    # ── Certificate Transparency ──────────────────────────────────────────────
    def _crtsh(self) -> List[str]:
        results = []
        try:
            url = f"https://crt.sh/?q=%.{self.target}&output=json"
            r = requests.get(url, timeout=15)
            if r.status_code == 200:
                data = r.json()
                for entry in data:
                    names = entry.get("name_value", "")
                    for name in names.split("\n"):
                        name = name.strip().lower().lstrip("*.")
                        if name.endswith(f".{self.target}") or name == self.target:
                            results.append(name)
        except Exception as e:
            if self.verbose:
                print(f"    [~] crt.sh error: {e}")
        return list(set(results))

    # ── HackerTarget passive ──────────────────────────────────────────────────
    def _hackertarget(self) -> List[str]:
        results = []
        try:
            url = f"https://api.hackertarget.com/hostsearch/?q={self.target}"
            r = requests.get(url, timeout=15)
            if r.status_code == 200 and "API count exceeded" not in r.text:
                for line in r.text.strip().split("\n"):
                    if "," in line:
                        host = line.split(",")[0].strip().lower()
                        if host.endswith(f".{self.target}") or host == self.target:
                            results.append(host)
        except Exception as e:
            if self.verbose:
                print(f"    [~] HackerTarget error: {e}")
        return results

    # ── DNS brute-force ───────────────────────────────────────────────────────
    def _resolve(self, sub: str):
        fqdn = f"{sub}.{self.target}"
        try:
            answers = dns.resolver.resolve(fqdn, "A", lifetime=3)
            ips = [str(r) for r in answers]
            with self.lock:
                self.found.add(fqdn)
            if self.verbose:
                print(f"    [+] {fqdn} → {', '.join(ips)}")
        except Exception:
            pass

    def _bruteforce(self):
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as ex:
            ex.map(self._resolve, self.wordlist)

    # ── Public entry point ────────────────────────────────────────────────────
    def run(self) -> List[str]:
        print(f"    [~] crt.sh Certificate Transparency lookup...")
        ct_results = self._crtsh()
        for h in ct_results:
            self.found.add(h)
        print(f"    [~] HackerTarget passive lookup...")
        ht_results = self._hackertarget()
        for h in ht_results:
            self.found.add(h)
        print(f"    [~] DNS brute-force ({len(self.wordlist)} words, {self.threads} threads)...")
        self._bruteforce()

        # Always include base domain
        self.found.add(self.target)
        return sorted(self.found)
