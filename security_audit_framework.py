#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Security Auditing & Frameworks
==============================
Read-only host security auditor that maps every check to industry frameworks
(CIS Benchmarks, NIST SP 800-53, ISO/IEC 27001:2022, PCI DSS v4.0) and produces
a weighted score plus per-framework compliance percentages.

Coded by Mr Sabaz Ali Khan - Cyber Security Engineer

Usage:
    python3 security_audit_framework.py                    # console report
    sudo python3 security_audit_framework.py               # full coverage (shadow, sudoers)
    python3 security_audit_framework.py --framework NIST   # filter to one framework
    python3 security_audit_framework.py --json report.json --html report.html
    python3 security_audit_framework.py --fail-under 70    # exit 1 if score < 70 (CI/CD gate)

Only audits the local machine you run it on. Makes NO changes to the system.
"""

import argparse
import glob
import html
import json
import os
import platform
import re
import shutil
import socket
import stat
import subprocess
import sys
from dataclasses import dataclass, field, asdict
from datetime import datetime

VERSION = "1.0.0"
AUTHOR = "Mr Sabaz Ali Khan"

BANNER = r"""
⠀⠀⠀⠀⠀⠀⣠⣴⣾⣿⣿⣿⣿⣿⣿⣶⣤⣄⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⣠⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣶⣄⠀⠀⠀⠀⠀
⠀⠀⣠⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⣆⠉⠉⢉⣿⣿⣿⣷⣦⣄⡀⠀
⠀⠚⢛⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡄
⠀⢠⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠿⠿⠿⠿⠿⣿⡇
⢀⣿⡿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠋⠁⠀⠀⠀⠀⠀⠀⠈⠃
⠸⠁⢀⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠏⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⢸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡏⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⣿⣿⣿⡿⣿⣿⣿⣿⣿⣿⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠹⣿⣿⡇⠈⠻⣿⣿⣿⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠈⠻⡇⠀⠀⠈⠙⠿⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
"""

CREDIT = f"Coded by {AUTHOR} | Cyber Security Engineer"

# --------------------------------------------------------------------------- #
# Colours
# --------------------------------------------------------------------------- #
USE_COLOR = sys.stdout.isatty() and os.name != "nt" or os.environ.get("FORCE_COLOR")


def c(text, code):
    return f"\033[{code}m{text}\033[0m" if USE_COLOR else str(text)


STATUS_COLOR = {"PASS": "92", "FAIL": "91", "WARN": "93", "SKIP": "90"}
SEV_WEIGHT = {"CRITICAL": 10, "HIGH": 7, "MEDIUM": 4, "LOW": 2}
FRAMEWORKS = ["CIS", "NIST", "ISO27001", "PCIDSS"]

# --------------------------------------------------------------------------- #
# Data model
# --------------------------------------------------------------------------- #


@dataclass
class Finding:
    check_id: str
    category: str
    title: str
    status: str            # PASS / FAIL / WARN / SKIP
    severity: str          # CRITICAL / HIGH / MEDIUM / LOW
    detail: str = ""
    remediation: str = ""
    controls: dict = field(default_factory=dict)


class Auditor:
    def __init__(self):
        self.findings: list[Finding] = []
        self.is_root = hasattr(os, "geteuid") and os.geteuid() == 0
        self.is_linux = sys.platform.startswith("linux")

    def add(self, check_id, category, title, status, severity, detail="",
            remediation="", controls=None):
        self.findings.append(Finding(check_id, category, title, status, severity,
                                     detail, remediation, controls or {}))

    # ------------------------------ helpers -------------------------------- #
    @staticmethod
    def read(path):
        try:
            with open(path, "r", errors="ignore") as fh:
                return fh.read()
        except (OSError, PermissionError):
            return None

    @staticmethod
    def run(cmd, timeout=10):
        try:
            out = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            return out.returncode, out.stdout.strip()
        except (OSError, subprocess.SubprocessError):
            return None, ""

    @staticmethod
    def parse_kv(text, comment="#"):
        """Parse 'Key value' config files (sshd_config, login.defs). First match wins."""
        result = {}
        for line in (text or "").splitlines():
            line = line.strip()
            if not line or line.startswith(comment):
                continue
            parts = re.split(r"[\s=]+", line, maxsplit=1)
            if len(parts) == 2:
                result.setdefault(parts[0].lower(), parts[1].strip())
        return result

    # ----------------------------- SSH audit -------------------------------- #
    def audit_ssh(self):
        cat = "SSH Hardening"
        text = self.read("/etc/ssh/sshd_config")
        if text is None:
            self.add("SSH-000", cat, "sshd_config readable", "SKIP", "LOW",
                     "SSH server config not found or unreadable (SSH may not be installed).")
            return
        # include drop-ins
        for extra in sorted(glob.glob("/etc/ssh/sshd_config.d/*.conf")):
            text = (self.read(extra) or "") + "\n" + text
        cfg = self.parse_kv(text)

        def check(cid, key, bad, default, title, sev, fix, controls):
            val = cfg.get(key, default).lower()
            ok = not bad(val)
            self.add(cid, cat, title, "PASS" if ok else "FAIL", sev,
                     f"{key} = {val}", "" if ok else fix, controls)

        check("SSH-001", "permitrootlogin", lambda v: v in ("yes", "without-password", "prohibit-password") and v == "yes",
              "prohibit-password", "Root login over SSH disabled", "HIGH",
              "Set 'PermitRootLogin no' in /etc/ssh/sshd_config",
              {"CIS": "5.2.10", "NIST": "AC-6(2)", "ISO27001": "A.8.2", "PCIDSS": "2.2.6"})
        check("SSH-002", "passwordauthentication", lambda v: v == "yes", "yes",
              "SSH password authentication disabled (keys only)", "MEDIUM",
              "Set 'PasswordAuthentication no' and use public-key auth",
              {"CIS": "5.2.12", "NIST": "IA-2", "ISO27001": "A.8.5", "PCIDSS": "8.3.1"})
        check("SSH-003", "permitemptypasswords", lambda v: v == "yes", "no",
              "Empty passwords rejected over SSH", "CRITICAL",
              "Set 'PermitEmptyPasswords no'",
              {"CIS": "5.2.11", "NIST": "IA-5(1)", "ISO27001": "A.8.5", "PCIDSS": "8.3.6"})
        check("SSH-004", "x11forwarding", lambda v: v == "yes", "yes",
              "X11 forwarding disabled", "LOW", "Set 'X11Forwarding no'",
              {"CIS": "5.2.6", "NIST": "CM-7", "ISO27001": "A.8.9", "PCIDSS": "2.2.4"})
        try:
            tries = int(cfg.get("maxauthtries", "6"))
        except ValueError:
            tries = 6
        self.add("SSH-005", cat, "MaxAuthTries <= 4", "PASS" if tries <= 4 else "FAIL", "MEDIUM",
                 f"MaxAuthTries = {tries}", "" if tries <= 4 else "Set 'MaxAuthTries 4'",
                 {"CIS": "5.2.7", "NIST": "AC-7", "ISO27001": "A.8.5", "PCIDSS": "8.3.4"})
        check("SSH-006", "protocol", lambda v: v == "1", "2",
              "SSH protocol 2 only", "CRITICAL", "Remove 'Protocol 1'; use protocol 2",
              {"CIS": "5.2.4", "NIST": "SC-8", "ISO27001": "A.8.24", "PCIDSS": "4.2.1"})
        try:
            idle = int(cfg.get("clientaliveinterval", "0"))
        except ValueError:
            idle = 0
        self.add("SSH-007", cat, "Idle session timeout configured", "PASS" if 0 < idle <= 300 else "WARN",
                 "LOW", f"ClientAliveInterval = {idle}",
                 "" if 0 < idle <= 300 else "Set 'ClientAliveInterval 300' and 'ClientAliveCountMax 0'",
                 {"CIS": "5.2.16", "NIST": "AC-12", "ISO27001": "A.8.5", "PCIDSS": "8.2.8"})

    # ------------------------- Accounts / passwords ------------------------- #
    def audit_accounts(self):
        cat = "Accounts & Authentication"
        defs = self.parse_kv(self.read("/etc/login.defs"))
        if defs:
            def num(k, d):
                try:
                    return int(defs.get(k.lower(), d))
                except ValueError:
                    return d
            maxd = num("PASS_MAX_DAYS", 99999)
            self.add("ACC-001", cat, "Password max age <= 365 days",
                     "PASS" if maxd <= 365 else "FAIL", "MEDIUM", f"PASS_MAX_DAYS = {maxd}",
                     "" if maxd <= 365 else "Set PASS_MAX_DAYS 365 (or less) in /etc/login.defs",
                     {"CIS": "5.4.1.1", "NIST": "IA-5(1)", "ISO27001": "A.5.17", "PCIDSS": "8.3.9"})
            mind = num("PASS_MIN_DAYS", 0)
            self.add("ACC-002", cat, "Password min age >= 1 day",
                     "PASS" if mind >= 1 else "WARN", "LOW", f"PASS_MIN_DAYS = {mind}",
                     "" if mind >= 1 else "Set PASS_MIN_DAYS 1",
                     {"CIS": "5.4.1.2", "NIST": "IA-5(1)", "ISO27001": "A.5.17", "PCIDSS": "8.3.7"})
            minl = num("PASS_MIN_LEN", 0)
            self.add("ACC-003", cat, "Password minimum length >= 12", 
                     "PASS" if minl >= 12 else "WARN", "MEDIUM",
                     f"PASS_MIN_LEN = {minl or 'unset (PAM may enforce)'}",
                     "" if minl >= 12 else "Enforce minlen=12 via pam_pwquality / login.defs",
                     {"CIS": "5.4.1", "NIST": "IA-5(1)", "ISO27001": "A.5.17", "PCIDSS": "8.3.6"})

        passwd = self.read("/etc/passwd")
        if passwd:
            uid0 = [l.split(":")[0] for l in passwd.splitlines()
                    if l and not l.startswith("#") and len(l.split(":")) > 2 and l.split(":")[2] == "0"]
            extra = [u for u in uid0 if u != "root"]
            self.add("ACC-004", cat, "Only 'root' has UID 0", "PASS" if not extra else "FAIL", "CRITICAL",
                     "UID 0 accounts: " + ", ".join(uid0),
                     "" if not extra else f"Investigate/remove extra UID 0 accounts: {', '.join(extra)}",
                     {"CIS": "6.2.9", "NIST": "AC-6", "ISO27001": "A.8.2", "PCIDSS": "7.2.1"})

        shadow = self.read("/etc/shadow")
        if shadow is None:
            self.add("ACC-005", cat, "No accounts with empty passwords", "SKIP", "CRITICAL",
                     "Cannot read /etc/shadow (run as root for this check).")
        else:
            empty = [l.split(":")[0] for l in shadow.splitlines()
                     if l and len(l.split(":")) > 1 and l.split(":")[1] == ""]
            self.add("ACC-005", cat, "No accounts with empty passwords", "PASS" if not empty else "FAIL",
                     "CRITICAL", "Empty-password accounts: " + (", ".join(empty) or "none"),
                     "" if not empty else "Lock or set passwords: passwd -l <user>",
                     {"CIS": "6.2.1", "NIST": "IA-5", "ISO27001": "A.5.17", "PCIDSS": "8.3.6"})

        # sudoers NOPASSWD
        sudo_files = ["/etc/sudoers"] + glob.glob("/etc/sudoers.d/*")
        content, readable = "", False
        for f in sudo_files:
            t = self.read(f)
            if t is not None:
                readable = True
                content += t + "\n"
        if not readable:
            self.add("ACC-006", cat, "sudo does not allow NOPASSWD", "SKIP", "MEDIUM",
                     "Cannot read sudoers (run as root).")
        else:
            nop = [l.strip() for l in content.splitlines()
                   if "NOPASSWD" in l and not l.strip().startswith("#")]
            self.add("ACC-006", cat, "sudo does not allow NOPASSWD", "PASS" if not nop else "WARN", "MEDIUM",
                     f"{len(nop)} NOPASSWD rule(s) found" + (": " + "; ".join(nop[:3]) if nop else ""),
                     "" if not nop else "Remove NOPASSWD unless strictly required",
                     {"CIS": "5.3.4", "NIST": "AC-6(5)", "ISO27001": "A.8.2", "PCIDSS": "7.2.2"})

    # ----------------------------- File permissions ------------------------- #
    def audit_permissions(self):
        cat = "File System Permissions"
        targets = [
            ("FS-001", "/etc/passwd", 0o644, "6.1.2"),
            ("FS-002", "/etc/shadow", 0o640, "6.1.3"),
            ("FS-003", "/etc/group", 0o644, "6.1.4"),
            ("FS-004", "/etc/gshadow", 0o640, "6.1.5"),
            ("FS-005", "/etc/ssh/sshd_config", 0o600, "5.2.1"),
            ("FS-006", "/etc/crontab", 0o600, "5.1.2"),
        ]
        for cid, path, max_mode, cis in targets:
            if not os.path.exists(path):
                continue
            try:
                st = os.stat(path)
            except OSError:
                continue
            mode = stat.S_IMODE(st.st_mode)
            too_open = bool(mode & ~max_mode & 0o777)
            self.add(cid, cat, f"{path} permissions <= {oct(max_mode)[2:]}",
                     "FAIL" if too_open else "PASS", "HIGH",
                     f"mode={oct(mode)[2:]} uid={st.st_uid} gid={st.st_gid}",
                     f"chmod {oct(max_mode)[2:]} {path}" if too_open else "",
                     {"CIS": cis, "NIST": "AC-3", "ISO27001": "A.8.3", "PCIDSS": "7.2.1"})

        # world-writable files in /etc
        ww = []
        for root, _dirs, files in os.walk("/etc"):
            for name in files:
                p = os.path.join(root, name)
                try:
                    if not os.path.islink(p) and os.stat(p).st_mode & stat.S_IWOTH:
                        ww.append(p)
                except OSError:
                    pass
            if len(ww) > 25:
                break
        self.add("FS-007", cat, "No world-writable files in /etc", "PASS" if not ww else "FAIL", "HIGH",
                 "World-writable: " + (", ".join(ww[:5]) or "none"),
                 "" if not ww else "chmod o-w on listed files",
                 {"CIS": "6.1.10", "NIST": "AC-3", "ISO27001": "A.8.3", "PCIDSS": "7.2.1"})

        # SUID/SGID in user-writable locations
        sus = []
        for base in ("/tmp", "/var/tmp", "/dev/shm", "/home"):
            for root, _d, files in os.walk(base):
                for name in files:
                    p = os.path.join(root, name)
                    try:
                        if os.stat(p).st_mode & (stat.S_ISUID | stat.S_ISGID):
                            sus.append(p)
                    except OSError:
                        pass
                if len(sus) > 25:
                    break
        self.add("FS-008", cat, "No SUID/SGID files in user-writable paths", "PASS" if not sus else "FAIL",
                 "HIGH", "Found: " + (", ".join(sus[:5]) or "none"),
                 "" if not sus else "Review and remove SUID/SGID bit: chmod u-s,g-s <file>",
                 {"CIS": "6.1.13", "NIST": "CM-6", "ISO27001": "A.8.9", "PCIDSS": "2.2.1"})

        # sticky bit on /tmp
        try:
            m = os.stat("/tmp").st_mode
            self.add("FS-009", cat, "Sticky bit set on /tmp", "PASS" if m & stat.S_ISVTX else "FAIL", "MEDIUM",
                     f"/tmp mode={oct(stat.S_IMODE(m))[2:]}",
                     "" if m & stat.S_ISVTX else "chmod +t /tmp",
                     {"CIS": "1.1.x", "NIST": "AC-3", "ISO27001": "A.8.3", "PCIDSS": "2.2.1"})
        except OSError:
            pass

    # ----------------------------- Network ---------------------------------- #
    RISKY_PORTS = {
        21: "FTP (cleartext)", 23: "Telnet (cleartext)", 69: "TFTP", 111: "RPCbind",
        135: "MS-RPC", 139: "NetBIOS", 445: "SMB", 512: "rexec", 513: "rlogin", 514: "rsh",
        2049: "NFS", 3389: "RDP", 5900: "VNC", 6379: "Redis (often unauth)",
        27017: "MongoDB (often unauth)", 9200: "Elasticsearch (often unauth)", 11211: "Memcached",
    }

    def listening_ports(self):
        """Return list of (proto, address, port) from /proc/net on Linux."""
        ports = []
        for proto, path in (("tcp", "/proc/net/tcp"), ("tcp6", "/proc/net/tcp6")):
            text = self.read(path)
            if not text:
                continue
            for line in text.splitlines()[1:]:
                p = line.split()
                if len(p) > 3 and p[3] == "0A":
                    addr_hex, port_hex = p[1].split(":")
                    all_ifaces = set(addr_hex) == {"0"}
                    loop = addr_hex in ("0100007F", "00000000000000000000000001000000")
                    ports.append((proto, "0.0.0.0" if all_ifaces else ("127.0.0.1" if loop else "specific"),
                                  int(port_hex, 16)))
        return ports

    def audit_network(self):
        cat = "Network Exposure"
        if not self.is_linux:
            self.add("NET-001", cat, "Listening port review", "SKIP", "MEDIUM",
                     "Port enumeration implemented for Linux (/proc/net).")
        else:
            ports = self.listening_ports()
            exposed = sorted({(pr, a, pt) for pr, a, pt in ports if a != "127.0.0.1"})
            risky = [(pt, self.RISKY_PORTS[pt]) for _, _, pt in exposed if pt in self.RISKY_PORTS]
            self.add("NET-001", cat, "No high-risk services exposed on network", "PASS" if not risky else "FAIL",
                     "HIGH", "Risky listeners: " + (", ".join(f"{p}/{n}" for p, n in risky) or "none"),
                     "" if not risky else "Disable the service or bind to 127.0.0.1 / firewall it",
                     {"CIS": "2.2.x", "NIST": "CM-7", "ISO27001": "A.8.20", "PCIDSS": "1.4.2"})
            self.add("NET-002", cat, "Count of externally listening ports",
                     "PASS" if len(exposed) <= 10 else "WARN", "LOW",
                     f"{len(exposed)} listening on non-loopback: " +
                     ", ".join(str(pt) for _, _, pt in exposed[:15]),
                     "" if len(exposed) <= 10 else "Reduce attack surface; close unused ports",
                     {"CIS": "2.1", "NIST": "SC-7", "ISO27001": "A.8.20", "PCIDSS": "1.4.1"})

        # firewall presence
        fw = None
        for tool in ("ufw", "firewall-cmd", "nft", "iptables"):
            if shutil.which(tool):
                fw = tool
                break
        status, detail = "FAIL", "No firewall tooling found"
        if fw == "ufw":
            rc, out = self.run(["ufw", "status"])
            if rc is not None and "active" in out.lower() and "inactive" not in out.lower():
                status, detail = "PASS", "ufw is active"
            else:
                status, detail = "WARN", "ufw installed but inactive/unknown (need root?)"
        elif fw == "firewall-cmd":
            rc, out = self.run(["firewall-cmd", "--state"])
            status, detail = ("PASS", "firewalld running") if out == "running" else ("WARN", "firewalld not running")
        elif fw:
            status, detail = "WARN", f"{fw} present; ruleset not verified"
        self.add("NET-003", cat, "Host firewall configured", status, "HIGH", detail,
                 "" if status == "PASS" else "Enable ufw/firewalld/nftables with default-deny inbound",
                 {"CIS": "3.5", "NIST": "SC-7", "ISO27001": "A.8.20", "PCIDSS": "1.2.1"})

        # kernel networking
        sysctls = [
            ("NET-010", "net/ipv4/ip_forward", "0", "IP forwarding disabled", "MEDIUM", "3.2.1"),
            ("NET-011", "net/ipv4/conf/all/accept_redirects", "0", "ICMP redirects not accepted", "MEDIUM", "3.2.2"),
            ("NET-012", "net/ipv4/conf/all/accept_source_route", "0", "Source routing disabled", "MEDIUM", "3.2.1"),
            ("NET-013", "net/ipv4/tcp_syncookies", "1", "TCP SYN cookies enabled", "MEDIUM", "3.2.8"),
            ("NET-014", "net/ipv4/conf/all/rp_filter", "1", "Reverse path filtering enabled", "LOW", "3.2.7"),
            ("NET-015", "kernel/randomize_va_space", "2", "ASLR fully enabled", "HIGH", "1.5.2"),
            ("NET-016", "kernel/kptr_restrict", "1", "Kernel pointer exposure restricted", "LOW", "1.5.x"),
            ("NET-017", "kernel/dmesg_restrict", "1", "dmesg restricted to privileged users", "LOW", "1.5.x"),
        ]
        for cid, key, want, title, sev, cis in sysctls:
            val = self.read("/proc/sys/" + key)
            if val is None:
                continue
            val = val.strip()
            ok = val == want or (key.endswith("kptr_restrict") and val in ("1", "2"))
            self.add(cid, "Kernel Hardening", title, "PASS" if ok else "FAIL", sev,
                     f"{key.replace('/', '.')} = {val}",
                     "" if ok else f"sysctl -w {key.replace('/', '.')}={want}  (persist in /etc/sysctl.d/)",
                     {"CIS": cis, "NIST": "SC-5" if "syn" in key else "CM-6",
                      "ISO27001": "A.8.9", "PCIDSS": "2.2.1"})

    # ----------------------------- Services / logging ----------------------- #
    LEGACY_SERVICES = ["telnet", "telnetd", "rsh-server", "rlogin", "vsftpd", "tftpd", "xinetd", "ypserv"]

    def audit_services(self):
        cat = "Services & Logging"
        if shutil.which("systemctl"):
            active = []
            for svc in self.LEGACY_SERVICES:
                rc, out = self.run(["systemctl", "is-active", svc])
                if out == "active":
                    active.append(svc)
            self.add("SVC-001", cat, "No legacy/insecure services running", "PASS" if not active else "FAIL",
                     "HIGH", "Active legacy services: " + (", ".join(active) or "none"),
                     "" if not active else "systemctl disable --now " + " ".join(active),
                     {"CIS": "2.2", "NIST": "CM-7", "ISO27001": "A.8.9", "PCIDSS": "2.2.4"})
            for cid, svc, title, sev in (
                ("SVC-002", "auditd", "auditd (system auditing) running", "MEDIUM"),
                ("SVC-003", "rsyslog", "rsyslog running", "LOW"),
            ):
                rc, out = self.run(["systemctl", "is-active", svc])
                if svc == "rsyslog" and out != "active":
                    rc2, out2 = self.run(["systemctl", "is-active", "systemd-journald"])
                    if out2 == "active":
                        out = "active"
                self.add(cid, cat, title, "PASS" if out == "active" else "WARN", sev,
                         f"{svc}: {out or 'unknown'}",
                         "" if out == "active" else f"Install/enable {svc}",
                         {"CIS": "4.1.1.1" if svc == "auditd" else "4.2.1", "NIST": "AU-2",
                          "ISO27001": "A.8.15", "PCIDSS": "10.2.1"})
            rc, out = self.run(["systemctl", "is-active", "unattended-upgrades"])
            rc2, out2 = self.run(["systemctl", "is-active", "dnf-automatic.timer"])
            auto = "active" in (out, out2)
            self.add("SVC-004", cat, "Automatic security updates enabled", "PASS" if auto else "WARN", "MEDIUM",
                     "Automatic update service " + ("active" if auto else "not detected"),
                     "" if auto else "Enable unattended-upgrades (Debian) or dnf-automatic (RHEL)",
                     {"CIS": "1.9", "NIST": "SI-2", "ISO27001": "A.8.8", "PCIDSS": "6.3.3"})
        else:
            self.add("SVC-001", cat, "Service review", "SKIP", "LOW", "systemctl not available on this host.")

        # MAC (SELinux / AppArmor)
        mac = None
        if os.path.exists("/sys/fs/selinux/enforce"):
            mac = "SELinux enforcing" if (self.read("/sys/fs/selinux/enforce") or "").strip() == "1" else None
        if not mac and os.path.isdir("/sys/kernel/security/apparmor"):
            mac = "AppArmor loaded"
        self.add("SVC-005", cat, "Mandatory Access Control active", "PASS" if mac else "WARN", "MEDIUM",
                 mac or "No SELinux/AppArmor detected",
                 "" if mac else "Enable SELinux (enforcing) or AppArmor",
                 {"CIS": "1.6", "NIST": "AC-3(3)", "ISO27001": "A.8.3", "PCIDSS": "2.2.1"})

        # Disk encryption hint
        _, lsblk = self.run(["lsblk", "-o", "TYPE"]) if shutil.which("lsblk") else (None, "")
        crypt = "crypt" in lsblk
        self.add("SVC-006", cat, "Disk encryption (LUKS) detected", "PASS" if crypt else "WARN", "LOW",
                 "Encrypted volume present" if crypt else "No dm-crypt volume detected",
                 "" if crypt else "Consider full-disk encryption for laptops/portable systems",
                 {"CIS": "1.x", "NIST": "SC-28", "ISO27001": "A.8.24", "PCIDSS": "3.5.1"})

    # ----------------------------- Run -------------------------------------- #
    def run_all(self):
        if not self.is_linux:
            print(c("[!] Most checks target Linux. Non-Linux hosts will see many SKIPs.", "93"))
        for fn in (self.audit_ssh, self.audit_accounts, self.audit_permissions,
                   self.audit_network, self.audit_services):
            try:
                fn()
            except Exception as exc:  # never let one module kill the audit
                self.add("ERR-000", "Auditor", f"{fn.__name__} crashed", "SKIP", "LOW", str(exc))
        return self.findings


# --------------------------------------------------------------------------- #
# Scoring & reporting
# --------------------------------------------------------------------------- #

def score(findings):
    total = got = 0.0
    for f in findings:
        if f.status == "SKIP":
            continue
        w = SEV_WEIGHT[f.severity]
        total += w
        got += w if f.status == "PASS" else (w * 0.5 if f.status == "WARN" else 0)
    return round(100 * got / total, 1) if total else 0.0


def framework_compliance(findings):
    out = {}
    for fw in FRAMEWORKS:
        rel = [f for f in findings if fw in f.controls and f.status != "SKIP"]
        if not rel:
            out[fw] = None
            continue
        passed = sum(1 for f in rel if f.status == "PASS")
        out[fw] = {"passed": passed, "total": len(rel), "percent": round(100 * passed / len(rel), 1)}
    return out


def grade(s):
    return "A" if s >= 90 else "B" if s >= 80 else "C" if s >= 70 else "D" if s >= 60 else "F"


def bar(pct, width=30):
    filled = int(width * pct / 100)
    col = "92" if pct >= 80 else "93" if pct >= 60 else "91"
    return c("█" * filled, col) + c("░" * (width - filled), "90")


def print_report(findings, fw_filter, verbose):
    cats = []
    for f in findings:
        if f.category not in cats:
            cats.append(f.category)
    for cat in cats:
        print("\n" + c(f"━━ {cat} ━━", "96;1"))
        for f in [x for x in findings if x.category == cat]:
            if fw_filter and fw_filter not in f.controls:
                continue
            tag = c(f"[{f.status}]", STATUS_COLOR[f.status])
            ctl = f.controls.get(fw_filter) if fw_filter else None
            ctl_txt = c(f" ({fw_filter} {ctl})", "90") if ctl else ""
            print(f" {tag} {c(f.check_id, '90')} {f.title} {c(f.severity, '95')}{ctl_txt}")
            if f.detail and (verbose or f.status != "PASS"):
                print(f"        {c('↳', '90')} {f.detail}")
            if f.status in ("FAIL", "WARN") and f.remediation:
                print(f"        {c('Fix:', '92')} {f.remediation}")

    s = score(findings)
    counts = {k: sum(1 for f in findings if f.status == k) for k in STATUS_COLOR}
    print("\n" + c("━━ SUMMARY ━━", "96;1"))
    print(f" Passed {c(counts['PASS'], '92')}  Failed {c(counts['FAIL'], '91')}  "
          f"Warnings {c(counts['WARN'], '93')}  Skipped {c(counts['SKIP'], '90')}")
    print(f" Security Score: {bar(s)} {c(f'{s}/100  Grade {grade(s)}', '1')}")
    print("\n" + c(" Framework Compliance", "1"))
    names = {"CIS": "CIS Benchmarks", "NIST": "NIST SP 800-53", "ISO27001": "ISO/IEC 27001:2022",
             "PCIDSS": "PCI DSS v4.0"}
    for fw, v in framework_compliance(findings).items():
        if v is None:
            continue
        print(f"  {names[fw]:<20} {bar(v['percent'], 20)} {v['percent']:>5}% ({v['passed']}/{v['total']})")
    crit = [f for f in findings if f.status == "FAIL" and f.severity in ("CRITICAL", "HIGH")]
    if crit:
        print("\n" + c(" Priority Remediation", "91;1"))
        for f in sorted(crit, key=lambda x: -SEV_WEIGHT[x.severity])[:8]:
            print(f"  • [{f.severity}] {f.title} -> {f.remediation}")


def build_json(findings, meta):
    return {
        "tool": "Security Auditing & Frameworks", "version": VERSION, "author": AUTHOR,
        "meta": meta, "score": score(findings), "grade": grade(score(findings)),
        "framework_compliance": framework_compliance(findings),
        "findings": [asdict(f) for f in findings],
    }


def build_html(data):
    rows = []
    colors = {"PASS": "#2ecc71", "FAIL": "#e74c3c", "WARN": "#f1c40f", "SKIP": "#7f8c8d"}
    for f in data["findings"]:
        ctl = ", ".join(f"{k}: {v}" for k, v in f["controls"].items())
        rows.append(
            f"<tr><td>{html.escape(f['check_id'])}</td><td>{html.escape(f['category'])}</td>"
            f"<td>{html.escape(f['title'])}</td>"
            f"<td style='color:{colors[f['status']]};font-weight:bold'>{f['status']}</td>"
            f"<td>{f['severity']}</td><td>{html.escape(f['detail'])}</td>"
            f"<td>{html.escape(f['remediation'])}</td><td class='s'>{html.escape(ctl)}</td></tr>")
    fw_rows = "".join(
        f"<li><b>{k}</b>: {v['percent']}% ({v['passed']}/{v['total']})</li>"
        for k, v in data["framework_compliance"].items() if v)
    banner = html.escape(BANNER)
    return f"""<!DOCTYPE html><html><head><meta charset="utf-8"><title>Security Audit Report</title>
<style>body{{background:#0d1117;color:#c9d1d9;font-family:Segoe UI,Arial,sans-serif;padding:24px}}
pre{{color:#58a6ff;line-height:1.1;font-size:12px}}table{{border-collapse:collapse;width:100%;font-size:13px}}
th,td{{border:1px solid #30363d;padding:6px 8px;text-align:left;vertical-align:top}}th{{background:#161b22}}
.s{{color:#8b949e;font-size:11px}}.score{{font-size:42px;font-weight:bold;color:#58a6ff}}</style></head><body>
<pre>{banner}</pre><h1>Security Auditing &amp; Frameworks</h1>
<p>{html.escape(CREDIT)}</p>
<p>Host: {html.escape(data['meta']['host'])} | {html.escape(data['meta']['os'])} | {data['meta']['timestamp']}</p>
<div class="score">{data['score']}/100 &mdash; Grade {data['grade']}</div><ul>{fw_rows}</ul>
<table><tr><th>ID</th><th>Category</th><th>Check</th><th>Status</th><th>Severity</th><th>Detail</th><th>Remediation</th><th>Controls</th></tr>
{''.join(rows)}</table></body></html>"""


def main():
    ap = argparse.ArgumentParser(description="Security Auditing & Frameworks - coded by " + AUTHOR)
    ap.add_argument("--framework", choices=FRAMEWORKS, help="show control IDs for one framework only")
    ap.add_argument("--json", metavar="FILE", help="write JSON report")
    ap.add_argument("--html", metavar="FILE", help="write HTML report")
    ap.add_argument("--fail-under", type=float, metavar="N", help="exit code 1 if score < N")
    ap.add_argument("-v", "--verbose", action="store_true", help="show details for passing checks too")
    ap.add_argument("--no-banner", action="store_true")
    args = ap.parse_args()

    if not args.no_banner:
        print(c(BANNER, "96"))
        print(c(f"  Security Auditing & Frameworks v{VERSION}", "1"))
        print(c(f"  {CREDIT}", "92"))
        print(c("  Read-only audit of the local host. Authorized use only.\n", "90"))

    auditor = Auditor()
    if not auditor.is_root and auditor.is_linux:
        print(c("[i] Not running as root - /etc/shadow and sudoers checks will be skipped.", "93"))
    findings = auditor.run_all()

    print_report(findings, args.framework, args.verbose)

    meta = {"host": socket.gethostname(), "os": f"{platform.system()} {platform.release()}",
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "root": auditor.is_root}
    data = build_json(findings, meta)
    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2, ensure_ascii=False)
        print(c(f"\n[+] JSON report saved: {args.json}", "92"))
    if args.html:
        with open(args.html, "w", encoding="utf-8") as fh:
            fh.write(build_html(data))
        print(c(f"[+] HTML report saved: {args.html}", "92"))

    print("\n" + c(f"  {CREDIT}", "90"))
    if args.fail_under is not None and data["score"] < args.fail_under:
        sys.exit(1)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Interrupted.")
        sys.exit(130)
