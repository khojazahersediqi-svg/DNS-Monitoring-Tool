#!/usr/bin/env python3
"""
DNS Domain Monitor
-------------------
Checks a list of domains/URLs against a blocklist of known malicious domains.
If a match is found, it logs a warning and shows a popup alert to the user.

Usage:
    python dns_monitor.py --input domains.txt --blocklist blocklist.txt
    python dns_monitor.py --input domains.txt --blocklist-url https://example.com/blocklist.txt

You can also import and use the DNSMonitor class directly in your own code.
"""

import argparse
import logging
import re
import sys
import urllib.request
from pathlib import Path
from urllib.parse import urlparse

# ---------------------------------------------------------------------------
# Logging setup
# ---------------------------------------------------------------------------
LOG_FILE = "dns_monitor.log"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE, encoding="utf-8"),
        logging.StreamHandler(sys.stdout),
    ],
)
logger = logging.getLogger("dns_monitor")


# ---------------------------------------------------------------------------
# Popup alert (cross-platform, falls back to console if no GUI available)
# ---------------------------------------------------------------------------
def show_popup_alert(title: str, message: str) -> None:
    """Show a popup alert. Falls back to a console banner if no GUI toolkit is available."""
    try:
        import tkinter as tk
        from tkinter import messagebox

        root = tk.Tk()
        root.withdraw()  # hide the main window, only show the messagebox
        messagebox.showwarning(title, message)
        root.destroy()
    except Exception as exc:
        # No display available (e.g. headless server) -- fall back to console
        logger.debug("Popup unavailable (%s); falling back to console alert.", exc)
        print("\n" + "!" * 60)
        print(f"  {title}")
        print(f"  {message}")
        print("!" * 60 + "\n")


# ---------------------------------------------------------------------------
# Core monitor class
# ---------------------------------------------------------------------------
class DNSMonitor:
    """Checks domains against a blocklist of known malicious domains."""

    def __init__(self, blocklist: set[str] | None = None):
        self.blocklist: set[str] = blocklist or set()

    # -- Blocklist loading ---------------------------------------------------
    def load_blocklist_file(self, path: str) -> None:
        """Load domains from a local text file (one domain per line, '#' for comments)."""
        file_path = Path(path)
        if not file_path.exists():
            raise FileNotFoundError(f"Blocklist file not found: {path}")

        count = 0
        with file_path.open("r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                domain = self._clean_line(line)
                if domain:
                    self.blocklist.add(domain)
                    count += 1
        logger.info("Loaded %d domains from blocklist file: %s", count, path)

    def load_blocklist_url(self, url: str, timeout: int = 10) -> None:
        """Download and load a blocklist from a URL (one domain per line)."""
        req = urllib.request.Request(url, headers={"User-Agent": "dns-monitor/1.0"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8", errors="ignore")

        count = 0
        for line in raw.splitlines():
            domain = self._clean_line(line)
            if domain:
                self.blocklist.add(domain)
                count += 1
        logger.info("Loaded %d domains from blocklist URL: %s", count, url)

    @staticmethod
    def _clean_line(line: str) -> str | None:
        """Normalize a blocklist line into a bare domain, or None if not usable."""
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("!"):
            return None

        # Support common hosts-file format: "0.0.0.0 baddomain.com"
        parts = line.split()
        candidate = parts[-1] if len(parts) > 1 else parts[0]

        return DNSMonitor._normalize_domain(candidate)

    @staticmethod
    def _normalize_domain(value: str) -> str | None:
        """Extract a bare lowercase domain from a URL or raw domain string."""
        value = value.strip().lower()
        if not value:
            return None

        # If it looks like a URL, parse out the netloc
        if "://" in value:
            netloc = urlparse(value).netloc
        else:
            netloc = value

        # Strip port, path, leading www.
        netloc = netloc.split("/")[0].split(":")[0]
        if netloc.startswith("www."):
            netloc = netloc[4:]

        # Basic sanity check: looks like a domain
        if not re.match(r"^[a-z0-9]([a-z0-9\-\.]*[a-z0-9])?$", netloc):
            return None

        return netloc or None

    # -- Checking --------------------------------------------------------
    def is_malicious(self, domain_or_url: str) -> bool:
        """Return True if the domain (or domain extracted from a URL) is on the blocklist."""
        domain = self._normalize_domain(domain_or_url)
        if not domain:
            return False

        # Exact match, or match against any parent domain (subdomain blocking)
        labels = domain.split(".")
        for i in range(len(labels) - 1):
            candidate = ".".join(labels[i:])
            if candidate in self.blocklist:
                return True
        return False

    def check(self, domain_or_url: str) -> bool:
        """Check a single domain/URL, log + alert if malicious. Returns True if malicious."""
        if self.is_malicious(domain_or_url):
            msg = f"Malicious domain detected: {domain_or_url}"
            logger.warning(msg)
            show_popup_alert(
                title="⚠ Security Warning",
                message=(
                    f"The site you tried to visit is flagged as malicious:\n\n"
                    f"{domain_or_url}\n\n"
                    f"Access has been blocked. Do not proceed to this site."
                ),
            )
            return True
        logger.info("Domain OK: %s", domain_or_url)
        return False

    def check_many(self, items: list[str]) -> dict[str, bool]:
        """Check a list of domains/URLs. Returns a dict of {item: is_malicious}."""
        return {item: self.check(item) for item in items}


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------
def read_input_list(path: str) -> list[str]:
    file_path = Path(path)
    if not file_path.exists():
        raise FileNotFoundError(f"Input file not found: {path}")
    with file_path.open("r", encoding="utf-8", errors="ignore") as f:
        return [line.strip() for line in f if line.strip() and not line.startswith("#")]


def main() -> None:
    parser = argparse.ArgumentParser(description="DNS / domain malicious-site monitor.")
    parser.add_argument("--input", required=True, help="Path to a text file with one domain/URL per line to check.")
    parser.add_argument("--blocklist", help="Path to a local blocklist file (one domain per line).")
    parser.add_argument("--blocklist-url", help="URL to download a blocklist from.")
    args = parser.parse_args()

    if not args.blocklist and not args.blocklist_url:
        parser.error("You must provide --blocklist and/or --blocklist-url")

    monitor = DNSMonitor()
    if args.blocklist:
        monitor.load_blocklist_file(args.blocklist)
    if args.blocklist_url:
        monitor.load_blocklist_url(args.blocklist_url)

    items = read_input_list(args.input)
    logger.info("Checking %d domain(s)/URL(s)...", len(items))

    results = monitor.check_many(items)
    flagged = [item for item, bad in results.items() if bad]

    logger.info("Done. %d of %d flagged as malicious.", len(flagged), len(items))
    if flagged:
        logger.info("Flagged items: %s", ", ".join(flagged))


if __name__ == "__main__":
    main()
