#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
WebAppSec Scanner
------------------
A passive / non-intrusive Web Application Security Testing tool.

Checks performed:
  - Security response headers (CSP, HSTS, X-Frame-Options, X-Content-Type-Options,
    Referrer-Policy, Permissions-Policy)
  - Cookie security flags (Secure, HttpOnly, SameSite)
  - SSL/TLS certificate validity & expiry
  - Server / technology banner disclosure
  - CORS misconfiguration (wildcard Access-Control-Allow-Origin)
  - Clickjacking exposure (missing X-Frame-Options / frame-ancestors)
  - Common sensitive file / path exposure (.env, .git/config, backups, etc.)
  - Directory listing exposure
  - robots.txt / sitemap.xml disclosure review

LEGAL / ETHICAL NOTICE:
This tool performs only passive checks (reading headers, fetching well-known
paths). It does NOT attempt exploitation (no SQLi/XSS payload injection, no
brute force, no RCE). Only run it against targets you own or are explicitly
authorized to test. Unauthorized scanning of systems you do not control may
be illegal in your jurisdiction.

coded by Mr Sabaz Ali Khan
"""

import sys
import ssl
import socket
import json
import argparse
import datetime
from urllib.parse import urlparse, urljoin

try:
    import requests
except ImportError:
    print("[!] Missing dependency. Install with: pip install requests")
    sys.exit(1)

requests.packages.urllib3.disable_warnings()

BANNER = r"""
⠀⠀⠀⠀⠀⠀⠀⢀⣴⣿⣷⣶⣄⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⢠⣿⣿⣿⣿⣿⣿⣿⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⣠⣿⣿⣿⣿⣿⣿⣿⣿⣿⣧⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⣴⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣧⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⣸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⢠⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣦⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⣼⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⣦⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⢀⣼⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⣄⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣶⣤⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣶⣤⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣀⣀⣀⣀⣀⡀⠀
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣶⣤⣀⠀⠀⠀⠀⠀⠀⠀⢀⣀⣤⣴⣶⣿⣿⣿⣿⣿⣿⣿⣿⣿⡆
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⣶⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠃
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠁⠀
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠁⠀⠀⠀
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠟⠁⠀⠀⠀⠀
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠁⠀⠀⠀⠀⠀⠀
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠃⠀⠀⠀⠀⠀⠀⠀
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠁⠀⠀⠀⠀⠀⠀⠀⠀
⣿⣿⣿⣿⣿⣿⣿⠟⠛⠛⠻⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠛⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀
⣿⣿⣿⣿⣿⣿⡏⠀⠀⢀⣾⡯⠉⢻⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡟⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⣿⣿⣿⣿⣿⣿⣇⠀⠀⠸⠿⠁⠀⠀⢻⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⣿⣿⣿⣿⣿⣿⣿⣦⡀⠀⠀⠀⠀⢀⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⣶⣶⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠿⠟⠿⡿⠿⠿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠏⠁⠀⢀⣾⡇⠀⠀⠘⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡀⠀⠀⠸⠟⠀⠀⠀⣸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⣄⡀⠀⠀⠀⣀⣴⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠿⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡟⠋⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡟⠣⢄⡈⠉⠓⠒⠦⠤⣤⣀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠿⢿⠁⠙⠦⡀⠈⠑⠦⣄⡀⠀⠀⠀⠉⠉⠐⠒⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⣿⣿⣿⣿⣿⣿⣿⣿⡿⠻⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠟⠋⠀⠀⠈⣧⠀⠀⠈⠣⡀⠀⠀⠉⠓⢤⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⣿⣿⣿⣿⣿⣿⠿⠋⠀⠀⠀⠈⠉⠙⠛⠋⠛⠛⠉⠉⠉⠉⠁⠀⠀⠀⠀⠀⠀⠸⣆⠀⠀⠀⠈⠢⡀⠀⠀⠀⠈⠑⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⣿⣿⣿⡿⠛⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢹⡄⠀⠀⠀⠀⠈⠢⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⣿⠟⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢧⠀⠀⠀⠀⠀⠀⠈⠂⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⡆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀

            W E B A P P S E C   S C A N N E R
         -------------------------------------
          coded by Mr Sabaz Ali Khan
          Cyber Security Engineer
"""

SENSITIVE_PATHS = [
    ".env", ".git/config", ".git/HEAD", "backup.zip", "backup.sql",
    "wp-config.php.bak", "config.php.bak", ".DS_Store", "web.config.bak",
    ".svn/entries", "composer.json", "package.json", "Dockerfile",
    "phpinfo.php", "server-status", ".htpasswd", "id_rsa",
]

SECURITY_HEADERS = {
    "Strict-Transport-Security": "Protects against SSL-stripping / protocol downgrade attacks.",
    "Content-Security-Policy": "Mitigates XSS and data-injection attacks.",
    "X-Content-Type-Options": "Prevents MIME-type sniffing.",
    "X-Frame-Options": "Mitigates clickjacking (legacy; CSP frame-ancestors preferred).",
    "Referrer-Policy": "Controls how much referrer info is leaked cross-origin.",
    "Permissions-Policy": "Restricts access to powerful browser features/APIs.",
}


def c(text, color):
    colors = {
        "red": "\033[91m", "green": "\033[92m", "yellow": "\033[93m",
        "blue": "\033[94m", "cyan": "\033[96m", "bold": "\033[1m", "end": "\033[0m",
    }
    return f"{colors.get(color,'')}{text}{colors['end']}"


class WebAppSecScanner:
    def __init__(self, target, timeout=10, verify_ssl=True):
        if not target.startswith(("http://", "https://")):
            target = "https://" + target
        self.target = target.rstrip("/")
        self.parsed = urlparse(self.target)
        self.host = self.parsed.hostname
        self.port = self.parsed.port or (443 if self.parsed.scheme == "https" else 80)
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "WebAppSecScanner/1.0 (authorized-testing)"})
        self.findings = []
        self.response = None

    def log(self, severity, title, detail):
        self.findings.append({"severity": severity, "title": title, "detail": detail})
        colors = {"HIGH": "red", "MEDIUM": "yellow", "LOW": "blue", "INFO": "cyan", "OK": "green"}
        print(f"  [{c(severity, colors.get(severity,'end'))}] {title} - {detail}")

    def fetch_base(self):
        print(c("\n[*] Fetching base response...", "bold"))
        try:
            self.response = self.session.get(
                self.target, timeout=self.timeout, verify=self.verify_ssl, allow_redirects=True
            )
            self.log("INFO", "Reachable", f"HTTP {self.response.status_code} from {self.response.url}")
            return True
        except requests.exceptions.SSLError as e:
            self.log("HIGH", "SSL Error", str(e))
            return False
        except requests.exceptions.RequestException as e:
            self.log("HIGH", "Connection Failed", str(e))
            return False

    def check_security_headers(self):
        print(c("\n[*] Checking security headers...", "bold"))
        if not self.response:
            return
        headers = self.response.headers
        for header, purpose in SECURITY_HEADERS.items():
            if header not in headers:
                self.log("MEDIUM", f"Missing {header}", purpose)
            else:
                self.log("OK", f"{header} present", headers[header][:80])

        server = headers.get("Server")
        if server:
            self.log("LOW", "Server banner disclosed", server)
        powered = headers.get("X-Powered-By")
        if powered:
            self.log("LOW", "X-Powered-By disclosed", powered)

    def check_cookies(self):
        print(c("\n[*] Checking cookie security flags...", "bold"))
        if not self.response or not self.session.cookies:
            self.log("INFO", "No cookies set", "No Set-Cookie header observed on base request")
            return
        for cookie in self.session.cookies:
            issues = []
            if not cookie.secure:
                issues.append("missing Secure flag")
            httponly = cookie.has_nonstandard_attr("HttpOnly") or cookie._rest.get("HttpOnly", False)
            if not httponly:
                issues.append("missing HttpOnly flag")
            samesite = cookie._rest.get("SameSite")
            if not samesite:
                issues.append("missing SameSite attribute")
            if issues:
                self.log("MEDIUM", f"Cookie '{cookie.name}' insecure", ", ".join(issues))
            else:
                self.log("OK", f"Cookie '{cookie.name}' flags OK", "Secure, HttpOnly, SameSite all set")

    def check_ssl_certificate(self):
        if self.parsed.scheme != "https":
            self.log("MEDIUM", "No HTTPS", "Site is not served over HTTPS")
            return
        print(c("\n[*] Checking SSL/TLS certificate...", "bold"))
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((self.host, self.port), timeout=self.timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=self.host) as ssock:
                    cert = ssock.getpeercert()
                    not_after = datetime.datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
                    days_left = (not_after - datetime.datetime.utcnow()).days
                    if days_left < 0:
                        self.log("HIGH", "Certificate expired", f"Expired {abs(days_left)} days ago")
                    elif days_left < 15:
                        self.log("MEDIUM", "Certificate expiring soon", f"{days_left} days remaining")
                    else:
                        self.log("OK", "Certificate valid", f"{days_left} days remaining")
                    self.log("INFO", "TLS version", ssock.version())
        except ssl.SSLCertVerificationError as e:
            self.log("HIGH", "Certificate verification failed", str(e))
        except Exception as e:
            self.log("MEDIUM", "Could not inspect certificate", str(e))

    def check_cors(self):
        print(c("\n[*] Checking CORS configuration...", "bold"))
        try:
            r = self.session.get(
                self.target, headers={"Origin": "https://evil-test-origin.example"},
                timeout=self.timeout, verify=self.verify_ssl,
            )
            acao = r.headers.get("Access-Control-Allow-Origin")
            acac = r.headers.get("Access-Control-Allow-Credentials")
            if acao == "*" and acac and acac.lower() == "true":
                self.log("HIGH", "Dangerous CORS config", "Wildcard origin combined with allow-credentials")
            elif acao == "*":
                self.log("MEDIUM", "Permissive CORS", "Access-Control-Allow-Origin is wildcard (*)")
            elif acao == "https://evil-test-origin.example":
                self.log("HIGH", "CORS reflects arbitrary origin", "Server reflects any Origin header back")
            elif acao:
                self.log("OK", "CORS restricted", f"Allow-Origin: {acao}")
            else:
                self.log("OK", "No permissive CORS header", "CORS not enabled on this response")
        except requests.exceptions.RequestException as e:
            self.log("INFO", "CORS check skipped", str(e))

    def check_clickjacking(self):
        print(c("\n[*] Checking clickjacking protection...", "bold"))
        if not self.response:
            return
        xfo = self.response.headers.get("X-Frame-Options")
        csp = self.response.headers.get("Content-Security-Policy", "")
        if xfo:
            self.log("OK", "X-Frame-Options set", xfo)
        elif "frame-ancestors" in csp:
            self.log("OK", "CSP frame-ancestors set", "Clickjacking mitigated via CSP")
        else:
            self.log("MEDIUM", "Clickjacking possible", "No X-Frame-Options or frame-ancestors directive")

    def check_sensitive_paths(self):
        print(c("\n[*] Probing for exposed sensitive files...", "bold"))
        for path in SENSITIVE_PATHS:
            url = urljoin(self.target + "/", path)
            try:
                r = self.session.get(url, timeout=self.timeout, verify=self.verify_ssl, allow_redirects=False)
                if r.status_code == 200 and len(r.content) > 0:
                    self.log("HIGH", f"Exposed file: /{path}", f"HTTP 200, {len(r.content)} bytes returned")
                elif r.status_code in (401, 403):
                    self.log("OK", f"/{path} protected", f"HTTP {r.status_code}")
            except requests.exceptions.RequestException:
                continue

    def check_directory_listing(self):
        print(c("\n[*] Checking for directory listing...", "bold"))
        common_dirs = ["uploads/", "images/", "backup/", "files/", "assets/"]
        for d in common_dirs:
            url = urljoin(self.target + "/", d)
            try:
                r = self.session.get(url, timeout=self.timeout, verify=self.verify_ssl)
                if r.status_code == 200 and ("Index of /" in r.text or "<title>Directory listing" in r.text):
                    self.log("MEDIUM", f"Directory listing enabled: /{d}", "Autoindex exposes file structure")
            except requests.exceptions.RequestException:
                continue

    def check_robots_sitemap(self):
        print(c("\n[*] Reviewing robots.txt / sitemap.xml...", "bold"))
        for fname in ["robots.txt", "sitemap.xml"]:
            url = urljoin(self.target + "/", fname)
            try:
                r = self.session.get(url, timeout=self.timeout, verify=self.verify_ssl)
                if r.status_code == 200:
                    self.log("INFO", f"{fname} found", f"{len(r.text)} bytes - review for disclosed paths")
            except requests.exceptions.RequestException:
                continue

    def run(self):
        print(c(BANNER, "cyan"))
        print(c(f"[*] Target: {self.target}", "bold"))
        print(c("[*] Only scan targets you own or are authorized to test.\n", "yellow"))

        if not self.fetch_base():
            return self.findings

        self.check_security_headers()
        self.check_cookies()
        self.check_ssl_certificate()
        self.check_cors()
        self.check_clickjacking()
        self.check_sensitive_paths()
        self.check_directory_listing()
        self.check_robots_sitemap()
        self.summary()
        return self.findings

    def summary(self):
        print(c("\n" + "=" * 60, "bold"))
        print(c("SCAN SUMMARY", "bold"))
        print(c("=" * 60, "bold"))
        counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0, "OK": 0}
        for f in self.findings:
            counts[f["severity"]] += 1
        print(f"  {c('HIGH', 'red')}:   {counts['HIGH']}")
        print(f"  {c('MEDIUM', 'yellow')}: {counts['MEDIUM']}")
        print(f"  {c('LOW', 'blue')}:    {counts['LOW']}")
        print(f"  {c('INFO', 'cyan')}:   {counts['INFO']}")
        print(f"  {c('OK', 'green')}:     {counts['OK']}")
        print(c("=" * 60, "bold"))
        print(c("coded by Mr Sabaz Ali Khan", "cyan"))

    def save_report(self, path):
        report = {
            "target": self.target,
            "scanned_at": datetime.datetime.utcnow().isoformat() + "Z",
            "findings": self.findings,
            "credit": "coded by Mr Sabaz Ali Khan",
        }
        with open(path, "w") as f:
            json.dump(report, f, indent=2)
        print(c(f"\n[*] Report saved to {path}", "green"))


def main():
    parser = argparse.ArgumentParser(
        description="WebAppSec Scanner - passive web application security tester (coded by Mr Sabaz Ali Khan)"
    )
    parser.add_argument("target", help="Target URL or domain (e.g. https://example.com)")
    parser.add_argument("-o", "--output", help="Save JSON report to file", default=None)
    parser.add_argument("--timeout", type=int, default=10, help="Request timeout in seconds")
    parser.add_argument("--no-verify-ssl", action="store_true", help="Disable SSL certificate verification")
    parser.add_argument(
        "--i-am-authorized", action="store_true",
        help="Confirm you own or are authorized to test this target (required)",
    )
    args = parser.parse_args()

    if not args.i_am_authorized:
        print(c(BANNER, "cyan"))
        print(c("[!] You must pass --i-am-authorized to confirm you own or have", "red"))
        print(c("    explicit written permission to test this target.", "red"))
        sys.exit(1)

    scanner = WebAppSecScanner(args.target, timeout=args.timeout, verify_ssl=not args.no_verify_ssl)
    scanner.run()

    if args.output:
        scanner.save_report(args.output)


if __name__ == "__main__":
    main()
