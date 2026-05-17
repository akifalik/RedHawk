"""
modules/screenshot.py
Headless Chromium screenshot capture for web asset visualization.
Falls back to cutycapt / wkhtmltoimage if Chromium not found.
"""

import os
import shutil
import subprocess
import concurrent.futures
import threading
import hashlib
import base64
from typing import List, Dict
from urllib.parse import urlparse


def _find_chromium() -> str:
    candidates = [
        "chromium-browser", "chromium", "google-chrome", "google-chrome-stable",
        "chrome", "/usr/bin/chromium-browser", "/usr/bin/chromium",
        "/usr/bin/google-chrome",
        "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
        r"C:\Program Files\Google\Chrome\Application\chrome.exe",
    ]
    for c in candidates:
        found = shutil.which(c) or (os.path.isfile(c) and c)
        if found:
            return found
    return ""


class ScreenshotEngine:
    def __init__(self, targets: List[str], out_dir: str,
                 threads: int = 5, verbose: bool = False,
                 width: int = 1366, height: int = 768,
                 timeout: int = 20):
        self.targets = targets
        self.out_dir = out_dir
        self.threads = threads
        self.verbose = verbose
        self.width = width
        self.height = height
        self.timeout = timeout
        self.lock = threading.Lock()
        os.makedirs(out_dir, exist_ok=True)
        self.chromium = _find_chromium()

    def _safe_filename(self, url: str) -> str:
        h = hashlib.md5(url.encode()).hexdigest()[:8]
        parsed = urlparse(url)
        safe = parsed.netloc.replace(".", "_").replace(":", "_")
        return f"{safe}_{parsed.scheme}_{h}.png"

    def _screenshot_chromium(self, url: str, out_path: str) -> bool:
        cmd = [
            self.chromium,
            "--headless",
            "--disable-gpu",
            "--no-sandbox",
            "--disable-dev-shm-usage",
            "--disable-extensions",
            "--disable-software-rasterizer",
            "--hide-scrollbars",
            "--ignore-certificate-errors",
            f"--window-size={self.width},{self.height}",
            f"--screenshot={out_path}",
            url,
        ]
        try:
            proc = subprocess.run(
                cmd, capture_output=True, timeout=self.timeout
            )
            return os.path.isfile(out_path) and os.path.getsize(out_path) > 0
        except subprocess.TimeoutExpired:
            if self.verbose:
                print(f"    [!] Timeout capturing {url}")
        except Exception as e:
            if self.verbose:
                print(f"    [!] Chromium error for {url}: {e}")
        return False

    def _screenshot_cutycapt(self, url: str, out_path: str) -> bool:
        cutycapt = shutil.which("cutycapt") or shutil.which("CutyCapt")
        if not cutycapt:
            return False
        cmd = [
            cutycapt,
            f"--url={url}",
            f"--out={out_path}",
            f"--delay=2000",
        ]
        try:
            subprocess.run(cmd, capture_output=True, timeout=self.timeout)
            return os.path.isfile(out_path)
        except Exception:
            return False

    def _capture(self, url: str) -> Dict:
        fname = self._safe_filename(url)
        out_path = os.path.join(self.out_dir, fname)

        success = False
        method = "none"
        if self.chromium:
            success = self._screenshot_chromium(url, out_path)
            method = "chromium"
        if not success:
            success = self._screenshot_cutycapt(url, out_path)
            method = "cutycapt"

        if success:
            # Embed as base64 for HTML report portability
            try:
                with open(out_path, "rb") as f:
                    b64 = base64.b64encode(f.read()).decode()
            except Exception:
                b64 = ""
            entry = {
                "url": url,
                "file": out_path,
                "filename": fname,
                "base64": b64,
                "method": method,
                "success": True,
            }
            if self.verbose:
                print(f"    [+] Screenshot: {url}")
        else:
            entry = {"url": url, "success": False, "method": method}
            if self.verbose:
                print(f"    [~] No screenshot tool available for {url}")

        with self.lock:
            return entry

    def run(self) -> List[Dict]:
        if not self.chromium:
            print("    [!] Chromium not found. Install chromium-browser for screenshots.")
            print("        Falling back to cutycapt if available.")

        results = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as ex:
            futures = {ex.submit(self._capture, url): url for url in self.targets}
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    results.append(result)

        successful = [r for r in results if r.get("success")]
        return successful
