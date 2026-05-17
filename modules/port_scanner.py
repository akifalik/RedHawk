"""
modules/port_scanner.py
TCP port scanner with basic service fingerprinting.
Uses raw sockets + concurrent threads for speed.
"""

import socket
import concurrent.futures
import threading
from typing import Dict, List

# Top 1000 ports (condensed common list; extend as needed)
TOP_1000 = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
    1723, 3306, 3389, 5900, 8080, 8443, 8888, 9090, 9200, 9300, 6379, 27017,
    27018, 5432, 1433, 1521, 5000, 5001, 8000, 8001, 8008, 8081, 8082, 8083,
    8444, 4443, 2375, 2376, 10250, 10255, 6443, 2379, 2380, 4001, 7001,
    7002, 4848, 8161, 61616, 5672, 15672, 1883, 8883, 5601, 9092, 2181,
    4040, 8080, 8088, 50070, 50075, 50090, 50105, 60010, 16010, 16030,
    # Common web
    80, 81, 82, 83, 88, 443, 444, 3000, 3001, 4000, 4200, 5000, 6000,
    7000, 8000, 8080, 8081, 8090, 8443, 8888, 9000, 9001, 9080, 9090,
    9443, 10000, 10443,
    # Databases
    1433, 1434, 1521, 3306, 5432, 5433, 6379, 7199, 7474, 7687, 8086,
    8087, 9042, 9160, 27017, 27018, 27019, 28015, 29015,
    # Infrastructure
    22, 23, 25, 53, 111, 123, 135, 137, 138, 139, 161, 162, 389, 445,
    464, 514, 515, 543, 544, 587, 631, 636, 873, 902, 989, 990, 1080,
    1194, 1723, 2049, 2082, 2083, 2086, 2087, 2095, 2096, 3128, 3268,
    3269, 4444, 4899, 5800, 5900, 5901, 6000, 6001, 8888, 9100,
]

# Grab banner for service fingerprinting
BANNER_PROBES = {
    80:  b"HEAD / HTTP/1.0\r\n\r\n",
    443: b"HEAD / HTTP/1.0\r\n\r\n",
    8080: b"HEAD / HTTP/1.0\r\n\r\n",
    22:  b"",
    21:  b"",
    25:  b"",
    110: b"",
    143: b"",
}

# Simple service name map
SERVICE_MAP = {
    21: "ftp",       22: "ssh",      23: "telnet",   25: "smtp",
    53: "dns",       80: "http",     110: "pop3",     111: "rpc",
    135: "msrpc",    139: "netbios", 143: "imap",     389: "ldap",
    443: "https",    445: "smb",     993: "imaps",    995: "pop3s",
    1433: "mssql",   1521: "oracle", 1723: "pptp",    2049: "nfs",
    3306: "mysql",   3389: "rdp",    5432: "postgres",5900: "vnc",
    5672: "amqp",    6379: "redis",  8080: "http-alt",8443: "https-alt",
    9200: "elasticsearch", 9300: "elasticsearch-cluster",
    10250: "kubelet",27017: "mongodb",
}


class PortScanner:
    def __init__(self, targets: List[str], top_ports: int = 1000,
                 threads: int = 50, timeout: int = 3, verbose: bool = False):
        self.targets = targets
        self.threads = threads
        self.timeout = timeout
        self.verbose = verbose
        # Deduplicate and limit port list
        self.ports = sorted(set(TOP_1000))[:top_ports]
        self.results: Dict[str, List[dict]] = {}
        self.lock = threading.Lock()

    def _grab_banner(self, host: str, port: int) -> str:
        try:
            with socket.create_connection((host, port), timeout=self.timeout) as s:
                probe = BANNER_PROBES.get(port, b"")
                if probe:
                    s.send(probe)
                banner = s.recv(1024).decode("utf-8", errors="replace").strip()
                return banner[:200]
        except Exception:
            return ""

    def _scan_port(self, host: str, port: int):
        try:
            with socket.create_connection((host, port), timeout=self.timeout):
                banner = self._grab_banner(host, port)
                service = SERVICE_MAP.get(port, "unknown")
                entry = {"port": port, "state": "open", "service": service, "banner": banner}
                with self.lock:
                    self.results.setdefault(host, []).append(entry)
                if self.verbose:
                    print(f"    [+] {host}:{port} open ({service})")
        except (socket.timeout, ConnectionRefusedError, OSError):
            pass

    def _scan_host(self, host: str):
        print(f"    [~] Scanning {host} ({len(self.ports)} ports)...")
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as ex:
            ex.map(lambda p: self._scan_port(host, p), self.ports)
        open_count = len(self.results.get(host, []))
        if open_count:
            print(f"    [+] {host}: {open_count} open port(s)")

    def run(self) -> Dict[str, List[dict]]:
        for target in self.targets:
            # Resolve hostname to IP first
            try:
                ip = socket.gethostbyname(target)
            except socket.gaierror:
                if self.verbose:
                    print(f"    [!] Cannot resolve {target}, skipping")
                continue
            self._scan_host(ip)
            # Map IP result back to hostname key
            if ip in self.results and ip != target:
                self.results[target] = self.results.pop(ip)
        return self.results
