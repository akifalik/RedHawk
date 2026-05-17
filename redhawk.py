#!/usr/bin/env python3
"""
RedHawk - Automated Red Team Recon Framework
Usage: python3 redhawk.py --target example.com [options]
"""

import argparse
import json
import os
import sys
import time
from datetime import datetime

from modules.subdomain_enum import SubdomainEnumerator
from modules.port_scanner import PortScanner
from modules.shodan_intel import ShodanIntel
from modules.harvester import HarvesterOSINT
from modules.screenshot import ScreenshotEngine
from modules.reporter import Reporter


BANNER = r"""
 ____          _ _   _               _    
|  _ \ ___  __| | | | | __ ___      _| | __
| |_) / _ \/ _` | |_| |/ _` \ \ /\ / / |/ /
|  _ <  __/ (_| |  _  | (_| |\ V  V /|   < 
|_| \_\___|\__,_|_| |_|\__,_| \_/\_/ |_|\_\

  Automated Red Team Recon Framework v1.0
  ----------------------------------------
"""

def parse_args():
    parser = argparse.ArgumentParser(
        description="RedHawk — Automated Red Team Recon Framework",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("--target", "-t", required=True, help="Target domain (e.g. example.com)")
    parser.add_argument("--output", "-o", default="output", help="Output directory (default: ./output)")
    parser.add_argument("--shodan-key", default=os.environ.get("SHODAN_API_KEY", ""), help="Shodan API key")

    # Module toggles
    parser.add_argument("--all", "-a", action="store_true", help="Run all modules")
    parser.add_argument("--subdomains", action="store_true", help="Run subdomain enumeration")
    parser.add_argument("--ports", action="store_true", help="Run port scanning")
    parser.add_argument("--shodan", action="store_true", help="Run Shodan intel gathering")
    parser.add_argument("--osint", action="store_true", help="Run theHarvester OSINT")
    parser.add_argument("--screenshots", action="store_true", help="Capture screenshots of web assets")

    # Options
    parser.add_argument("--wordlist", default="", help="Custom wordlist for subdomain brute-force")
    parser.add_argument("--threads", type=int, default=50, help="Threads for port scanning (default: 50)")
    parser.add_argument("--top-ports", type=int, default=1000, help="Top N ports to scan (default: 1000)")
    parser.add_argument("--timeout", type=int, default=3, help="Socket timeout in seconds (default: 3)")
    parser.add_argument("--no-report", action="store_true", help="Skip report generation")
    parser.add_argument("--json-only", action="store_true", help="Output JSON only, skip HTML report")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")

    return parser.parse_args()


def print_status(msg, status="*", color="\033[94m"):
    reset = "\033[0m"
    print(f"  {color}[{status}]{reset} {msg}")

def print_ok(msg):    print_status(msg, "+", "\033[92m")
def print_info(msg):  print_status(msg, "*", "\033[94m")
def print_warn(msg):  print_status(msg, "!", "\033[93m")
def print_err(msg):   print_status(msg, "✗", "\033[91m")
def print_done(msg):  print_status(msg, "✓", "\033[92m")


def run():
    print("\033[91m" + BANNER + "\033[0m")
    args = parse_args()

    # If --all, enable everything
    if args.all:
        args.subdomains = args.ports = args.shodan = args.osint = args.screenshots = True

    # Require at least one module
    if not any([args.subdomains, args.ports, args.shodan, args.osint, args.screenshots]):
        print_warn("No modules selected. Use --all or pick specific modules.")
        sys.exit(1)

    target = args.target.strip().lower().removeprefix("http://").removeprefix("https://").rstrip("/")
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_name = target.replace(".", "_")
    out_dir = os.path.join(args.output, f"{safe_name}_{timestamp}")
    os.makedirs(out_dir, exist_ok=True)

    print_info(f"Target  : \033[93m{target}\033[0m")
    print_info(f"Output  : {out_dir}")
    print_info(f"Started : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print()

    results = {
        "meta": {
            "target": target,
            "timestamp": timestamp,
            "started_at": datetime.now().isoformat(),
        },
        "subdomains": [],
        "ports": {},
        "shodan": {},
        "osint": {},
        "screenshots": [],
    }

    # ── 1. Subdomain Enumeration ──────────────────────────────────────────────
    if args.subdomains:
        print_info("Module: Subdomain Enumeration")
        enumerator = SubdomainEnumerator(
            target=target,
            wordlist=args.wordlist,
            threads=args.threads,
            verbose=args.verbose,
        )
        subdomains = enumerator.run()
        results["subdomains"] = subdomains
        print_ok(f"Discovered {len(subdomains)} subdomains")
        print()

    # ── 2. Port Scanning ──────────────────────────────────────────────────────
    scan_targets = results["subdomains"] if results["subdomains"] else [target]
    if args.ports:
        print_info("Module: Port Scanner")
        scanner = PortScanner(
            targets=scan_targets,
            top_ports=args.top_ports,
            threads=args.threads,
            timeout=args.timeout,
            verbose=args.verbose,
        )
        port_data = scanner.run()
        results["ports"] = port_data
        total_open = sum(len(v) for v in port_data.values())
        print_ok(f"Found {total_open} open ports across {len(port_data)} hosts")
        print()

    # ── 3. Shodan Intelligence ────────────────────────────────────────────────
    if args.shodan:
        print_info("Module: Shodan Passive Intel")
        if not args.shodan_key:
            print_warn("No Shodan API key provided. Set --shodan-key or $SHODAN_API_KEY.")
        else:
            shodan = ShodanIntel(
                target=target,
                api_key=args.shodan_key,
                subdomains=results["subdomains"],
                verbose=args.verbose,
            )
            shodan_data = shodan.run()
            results["shodan"] = shodan_data
            vuln_count = sum(len(h.get("vulns", [])) for h in shodan_data.get("hosts", []))
            print_ok(f"Shodan: {len(shodan_data.get('hosts', []))} hosts, {vuln_count} CVEs found")
        print()

    # ── 4. OSINT (theHarvester) ───────────────────────────────────────────────
    if args.osint:
        print_info("Module: OSINT (theHarvester)")
        harvester = HarvesterOSINT(target=target, verbose=args.verbose)
        osint_data = harvester.run()
        results["osint"] = osint_data
        emails = len(osint_data.get("emails", []))
        hosts  = len(osint_data.get("hosts", []))
        print_ok(f"Harvested {emails} emails, {hosts} additional hosts")
        print()

    # ── 5. Screenshot Capture ─────────────────────────────────────────────────
    if args.screenshots:
        print_info("Module: Screenshot Capture (headless Chromium)")
        web_targets = []
        for host in (results["subdomains"] or [target]):
            web_targets.append(f"http://{host}")
            web_targets.append(f"https://{host}")
        screenshotter = ScreenshotEngine(
            targets=web_targets,
            out_dir=os.path.join(out_dir, "screenshots"),
            threads=min(args.threads, 10),
            verbose=args.verbose,
        )
        screenshots = screenshotter.run()
        results["screenshots"] = screenshots
        print_ok(f"Captured {len(screenshots)} screenshots")
        print()

    # ── Save JSON ─────────────────────────────────────────────────────────────
    results["meta"]["finished_at"] = datetime.now().isoformat()
    json_path = os.path.join(out_dir, "redhawk_report.json")
    with open(json_path, "w") as f:
        json.dump(results, f, indent=2)
    print_done(f"JSON saved → {json_path}")

    # ── Generate HTML report ──────────────────────────────────────────────────
    if not args.no_report and not args.json_only:
        reporter = Reporter(results=results, out_dir=out_dir)
        html_path = reporter.generate()
        print_done(f"HTML report → {html_path}")

    print()
    print_done(f"RedHawk finished. Results in: {out_dir}")
    print()


if __name__ == "__main__":
    run()
