"""
modules/shodan_intel.py
Passive intelligence gathering via the Shodan API.
Queries by domain + resolved IPs. No packets sent to target.
"""

import socket
from typing import List, Dict, Any


class ShodanIntel:
    def __init__(self, target: str, api_key: str,
                 subdomains: List[str] = None, verbose: bool = False):
        self.target = target
        self.api_key = api_key
        self.subdomains = subdomains or [target]
        self.verbose = verbose

    def _resolve_ips(self) -> List[str]:
        ips = set()
        for host in self.subdomains:
            try:
                ip = socket.gethostbyname(host)
                ips.add(ip)
            except socket.gaierror:
                pass
        return list(ips)

    def _query_host(self, shodan, ip: str) -> Dict[str, Any]:
        try:
            host = shodan.host(ip)
            return {
                "ip": ip,
                "org": host.get("org", ""),
                "isp": host.get("isp", ""),
                "country": host.get("country_name", ""),
                "city": host.get("city", ""),
                "os": host.get("os", ""),
                "ports": host.get("ports", []),
                "vulns": list(host.get("vulns", {}).keys()),
                "hostnames": host.get("hostnames", []),
                "tags": host.get("tags", []),
                "last_update": host.get("last_update", ""),
                "services": [
                    {
                        "port": item.get("port"),
                        "transport": item.get("transport", "tcp"),
                        "product": item.get("product", ""),
                        "version": item.get("version", ""),
                        "cpe": item.get("cpe", []),
                        "data": item.get("data", "")[:300],
                    }
                    for item in host.get("data", [])
                ],
            }
        except Exception as e:
            if self.verbose:
                print(f"    [~] Shodan error for {ip}: {e}")
            return {"ip": ip, "error": str(e)}

    def _dns_lookup(self, shodan) -> Dict:
        try:
            result = shodan.dns.domain_info(self.target, history=False, type=None, page=1)
            return {
                "domain": self.target,
                "tags": result.get("tags", []),
                "subdomains": result.get("subdomains", []),
            }
        except Exception as e:
            if self.verbose:
                print(f"    [~] Shodan DNS info error: {e}")
            return {}

    def run(self) -> Dict[str, Any]:
        try:
            import shodan as shodan_lib
        except ImportError:
            print("    [!] shodan library not installed. Run: pip install shodan")
            return {"error": "shodan not installed"}

        api = shodan_lib.Shodan(self.api_key)

        print(f"    [~] Resolving IPs for {len(self.subdomains)} host(s)...")
        ips = self._resolve_ips()
        print(f"    [~] Querying Shodan for {len(ips)} unique IPs...")

        hosts = []
        for ip in ips:
            if self.verbose:
                print(f"    [~] Shodan lookup: {ip}")
            data = self._query_host(api, ip)
            hosts.append(data)

        dns_info = self._dns_lookup(api)

        return {
            "hosts": hosts,
            "dns_info": dns_info,
            "total_ips": len(ips),
            "total_vulns": sum(len(h.get("vulns", [])) for h in hosts),
        }
