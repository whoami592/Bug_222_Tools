#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
RevEngine - Reverse Engineering & Binary Analysis Toolkit (static analysis)
Coded by Mr Sabaz Ali Khan

Features
  * File identification (PE / ELF / Mach-O / scripts / archives) + hashes
  * Shannon entropy (whole file + per section) -> packed/encrypted detection
  * PE parser: headers, sections, imports, exports, overlay, mitigations
  * ELF parser: headers, sections, segments, dynamic libs, symbols, mitigations
  * String extraction (ASCII + UTF-16LE) with IOC extraction (URLs, IPs, ...)
  * Suspicious API / capability detection (injection, anti-debug, crypto, ...)
  * Packer / protector heuristics and a simple risk score
  * Optional disassembly of the entry point (needs: pip install capstone)
  * Hex dump, JSON report export

SAFE BY DESIGN: the sample is only READ as bytes. It is never executed.
Usage:
  python reveng_analyzer.py sample.exe
  python reveng_analyzer.py sample.elf --disasm 40 --json report.json
  python reveng_analyzer.py sample.bin --hex 0x0 256 --min-len 6
"""

import argparse
import collections
import datetime
import hashlib
import json
import math
import os
import re
import struct
import sys

BANNER = """
⠀⠀⠀⠀⢀⣶⡖⢦⣤⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠙⠋⠹⣦⠘⠉⠳⢤⣤⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠙⠛⠓⠶⣶⣶⣿⣛⣀⣰⣆⣀⣀⠉⠛⢶⣄⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠈⠉⠉⠉⠉⠁⠉⠉⠙⢷⣦⡀⠈⠻⣦⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⢀⣠⡤⠶⢶⣶⣾⣿⡀⠀⢸⡆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⢠⡞⠋⠀⣠⣶⣖⣻⣿⠟⠀⠀⣸⣧⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⢻⣄⠀⠀⠈⠙⠛⠉⠁⠀⣠⣾⡟⠉⢷⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⢀⣠⠿⠿⣿⣿⣿⡿⠿⢿⣿⣯⣿⡇⠀⢸⡇⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⣰⠟⠁⠀⣀⣤⣤⣤⣤⣤⣤⣼⣿⣿⠇⠀⢈⣟⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⢰⡏⠀⠀⣾⣏⠁⠀⠀⠀⢀⣀⣴⡿⠋⠀⠀⣼⠟⣦⡀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠈⢷⣄⡀⠈⠙⠛⠛⠛⠛⠋⠉⠁⢀⣠⣴⣿⡟⠀⠸⣇⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⣈⣽⣿⣶⣶⣶⣶⣶⣶⣾⣿⣯⣍⠀⠘⡗⠀⠀⣿⠀⠀⠀⠀⠀⠀
⠀⠀⠀⣰⠞⠉⠉⠀⢀⣀⣀⣀⣀⡀⠀⠀⠹⣿⣷⣼⡇⠀⢀⡿⠀⠀⠀⠀⢠⢦
⠀⠀⣾⠋⠀⠀⢰⡿⠛⠉⠉⠉⠉⠙⠿⠷⣦⣼⣿⠏⠀⢀⣾⡃⠀⠀⠀⣀⡿⣹
⠀⠀⢿⡀⠀⠀⠘⢿⣦⣄⣀⣤⣤⣤⣤⡶⠿⠋⠁⠀⣠⣾⡏⠛⠓⠒⠛⣩⡴⠃
⠀⠀⠈⠻⣦⣀⡀⠀⠀⠈⠉⠉⠀⠀⠀⠀⠀⣀⣴⡾⠛⠛⠿⠶⠶⠶⠞⠋⠀⠀
⠀⠀⠀⠀⠈⠛⠿⠿⠿⠿⣿⣶⡶⠶⠶⠿⠟⠛⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
"""

TOOL_NAME = "RevEngine - Reverse Engineering & Binary Analysis"
CREDIT = "Coded by Mr Sabaz Ali Khan | Cyber Security Engineer"

# --------------------------------------------------------------------------
# Knowledge bases
# --------------------------------------------------------------------------
SUSPICIOUS_APIS = {
    "Process injection": [
        "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread",
        "NtCreateThreadEx", "QueueUserAPC", "SetThreadContext",
        "NtMapViewOfSection", "RtlCreateUserThread", "ptrace",
    ],
    "Anti-debugging": [
        "IsDebuggerPresent", "CheckRemoteDebuggerPresent",
        "NtQueryInformationProcess", "OutputDebugStringA",
        "NtSetInformationThread", "ptrace",
    ],
    "Dynamic code loading": [
        "LoadLibraryA", "LoadLibraryW", "LoadLibraryExA", "GetProcAddress",
        "LdrLoadLibrary", "LdrGetProcedureAddress", "dlopen", "dlsym",
    ],
    "Persistence / registry": [
        "RegSetValueExA", "RegSetValueExW", "RegCreateKeyExA",
        "RegCreateKeyExW", "CreateServiceA", "CreateServiceW",
    ],
    "Networking": [
        "InternetOpenA", "InternetOpenUrlA", "URLDownloadToFileA",
        "URLDownloadToFileW", "WSAStartup", "connect", "send", "recv",
        "socket", "HttpSendRequestA", "WinHttpOpen", "gethostbyname",
    ],
    "Cryptography": [
        "CryptEncrypt", "CryptDecrypt", "CryptAcquireContextA",
        "CryptAcquireContextW", "BCryptEncrypt", "CryptGenKey",
        "EVP_EncryptInit_ex", "AES_encrypt",
    ],
    "Process / command execution": [
        "CreateProcessA", "CreateProcessW", "ShellExecuteA", "ShellExecuteW",
        "WinExec", "system", "execve", "execl", "popen", "fork",
    ],
    "Privilege manipulation": [
        "AdjustTokenPrivileges", "OpenProcessToken", "LookupPrivilegeValueA",
        "setuid", "setgid",
    ],
    "Keylogging / input capture": [
        "SetWindowsHookExA", "SetWindowsHookExW", "GetAsyncKeyState",
        "GetKeyState", "GetForegroundWindow",
    ],
    "Memory protection changes": [
        "VirtualProtect", "VirtualProtectEx", "mprotect", "VirtualAlloc", "mmap",
    ],
}

PACKER_SECTIONS = {
    "UPX0": "UPX", "UPX1": "UPX", "UPX2": "UPX", ".aspack": "ASPack",
    ".adata": "ASPack", ".themida": "Themida", ".vmp0": "VMProtect",
    ".vmp1": "VMProtect", ".petite": "Petite", ".nsp0": "NsPack",
    ".nsp1": "NsPack", ".mpress1": "MPRESS", ".mpress2": "MPRESS",
    ".enigma1": "Enigma", ".packed": "Generic packer",
}

IOC_PATTERNS = {
    "URL": re.compile(r"https?://[^\s'\"<>]{4,200}", re.I),
    "IPv4": re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"),
    "Email": re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]{2,}\b"),
    "Registry key": re.compile(r"\b(?:HKEY_[A-Z_]+|HKLM|HKCU)\\[^\s'\"]{3,150}", re.I),
    "Windows path": re.compile(r"\b[A-Za-z]:\\(?:[^\s\\/:*?\"<>|]+\\?){1,8}"),
    "Unix path": re.compile(r"(?<![\w.])/(?:etc|tmp|var|usr|bin|dev|proc|home|root)/[\w./-]{2,100}"),
    "Domain": re.compile(r"\b(?:[a-z0-9-]{2,63}\.)+(?:com|net|org|io|ru|cn|info|xyz|top|biz|onion|tk)\b", re.I),
    "Base64 blob": re.compile(r"\b[A-Za-z0-9+/]{60,}={0,2}"),
}

MACHINES_PE = {0x14C: "x86", 0x8664: "x86-64", 0x1C0: "ARM", 0xAA64: "ARM64", 0x200: "IA-64"}
MACHINES_ELF = {3: "x86", 62: "x86-64", 40: "ARM", 183: "ARM64", 8: "MIPS",
                243: "RISC-V", 20: "PowerPC", 21: "PowerPC64"}
SUBSYSTEMS = {1: "Native", 2: "Windows GUI", 3: "Windows CUI (console)", 9: "WinCE GUI",
              10: "EFI application", 14: "Xbox"}
ELF_TYPES = {1: "REL (relocatable)", 2: "EXEC (executable)", 3: "DYN (shared/PIE)", 4: "CORE"}

# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------
class C:
    on = sys.stdout.isatty()
    R = "\033[91m" if on else ""
    G = "\033[92m" if on else ""
    Y = "\033[93m" if on else ""
    B = "\033[94m" if on else ""
    M = "\033[95m" if on else ""
    CY = "\033[96m" if on else ""
    BD = "\033[1m" if on else ""
    X = "\033[0m" if on else ""


def entropy(data):
    if not data:
        return 0.0
    n = len(data)
    return -sum((v / n) * math.log2(v / n) for v in collections.Counter(data).values())


def hashes(data):
    return {
        "md5": hashlib.md5(data).hexdigest(),
        "sha1": hashlib.sha1(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
    }


def cstr(d, off, limit=300):
    if off < 0 or off >= len(d):
        return ""
    end = d.find(b"\x00", off, off + limit)
    if end == -1:
        end = min(len(d), off + limit)
    return d[off:end].decode("latin-1", "replace")


def human(n):
    for u in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.1f} {u}" if u != "B" else f"{n} B"
        n /= 1024
    return f"{n:.1f} TB"


def section_title(t):
    print(f"\n{C.BD}{C.CY}=== {t} ==={C.X}")


def kv(k, v):
    print(f"  {C.B}{k:<22}{C.X} {v}")


def ent_label(e):
    if e >= 7.2:
        return f"{C.R}{e:.2f} (packed/encrypted?){C.X}"
    if e >= 6.5:
        return f"{C.Y}{e:.2f} (high){C.X}"
    return f"{C.G}{e:.2f}{C.X}"


# --------------------------------------------------------------------------
# Format identification
# --------------------------------------------------------------------------
def identify(d):
    sigs = [
        (b"MZ", "DOS/PE executable"),
        (b"\x7fELF", "ELF executable"),
        (b"\xfe\xed\xfa\xce", "Mach-O 32-bit (BE)"), (b"\xfe\xed\xfa\xcf", "Mach-O 64-bit (BE)"),
        (b"\xce\xfa\xed\xfe", "Mach-O 32-bit (LE)"), (b"\xcf\xfa\xed\xfe", "Mach-O 64-bit (LE)"),
        (b"\xca\xfe\xba\xbe", "Mach-O fat binary / Java class"),
        (b"PK\x03\x04", "ZIP / APK / JAR / DOCX"),
        (b"%PDF", "PDF document"), (b"\x1f\x8b", "GZIP archive"),
        (b"Rar!", "RAR archive"), (b"7z\xbc\xaf", "7-Zip archive"),
        (b"#!", "Script (shebang)"), (b"dex\n", "Android DEX"),
    ]
    for s, name in sigs:
        if d.startswith(s):
            return name
    return "Unknown / raw data"


# --------------------------------------------------------------------------
# PE parser
# --------------------------------------------------------------------------
def parse_pe(d):
    try:
        if d[:2] != b"MZ" or len(d) < 0x40:
            return None
        pe = struct.unpack_from("<I", d, 0x3C)[0]
        if d[pe:pe + 4] != b"PE\x00\x00":
            return None
        machine, nsec, ts, _, _, szopt, chars = struct.unpack_from("<HHIIIHH", d, pe + 4)
        opt = pe + 24
        magic = struct.unpack_from("<H", d, opt)[0]
        is64 = magic == 0x20B
        entry = struct.unpack_from("<I", d, opt + 16)[0]
        if is64:
            imagebase = struct.unpack_from("<Q", d, opt + 24)[0]
            nrva_off, dd_off = opt + 108, opt + 112
        else:
            imagebase = struct.unpack_from("<I", d, opt + 28)[0]
            nrva_off, dd_off = opt + 92, opt + 96
        subsystem, dllchars = struct.unpack_from("<HH", d, opt + 68)
        nrva = struct.unpack_from("<I", d, nrva_off)[0]
        dirs = []
        for i in range(min(nrva, 16)):
            o = dd_off + 8 * i
            if o + 8 <= len(d):
                dirs.append(struct.unpack_from("<II", d, o))

        sections = []
        so = opt + szopt
        for i in range(min(nsec, 96)):
            o = so + 40 * i
            if o + 40 > len(d):
                break
            name = d[o:o + 8].rstrip(b"\x00").decode("latin-1", "replace")
            vsize, va, rsize, rptr = struct.unpack_from("<IIII", d, o + 8)
            flags = struct.unpack_from("<I", d, o + 36)[0]
            raw = d[rptr:rptr + rsize]
            sections.append({
                "name": name, "vaddr": va, "vsize": vsize, "rawsize": rsize,
                "rawptr": rptr, "flags": flags, "entropy": round(entropy(raw), 3),
                "perm": ("R" if flags & 0x40000000 else "-") +
                        ("W" if flags & 0x80000000 else "-") +
                        ("X" if flags & 0x20000000 else "-"),
            })

        def rva2off(rva):
            for s in sections:
                span = max(s["vsize"], s["rawsize"])
                if s["vaddr"] <= rva < s["vaddr"] + span:
                    return rva - s["vaddr"] + s["rawptr"]
            return rva if rva < (sections[0]["vaddr"] if sections else 0x1000) else None

        imports = collections.OrderedDict()
        if len(dirs) > 1 and dirs[1][0]:
            off = rva2off(dirs[1][0])
            for _ in range(512):
                if off is None or off + 20 > len(d):
                    break
                oft, _, _, name_rva, ft = struct.unpack_from("<IIIII", d, off)
                if not (oft or ft or name_rva):
                    break
                dll = cstr(d, rva2off(name_rva) or 0).lower()
                thunk = rva2off(oft or ft)
                funcs = []
                step = 8 if is64 else 4
                ordflag = 1 << (63 if is64 else 31)
                for _ in range(4096):
                    if thunk is None or thunk + step > len(d):
                        break
                    val = struct.unpack_from("<Q" if is64 else "<I", d, thunk)[0]
                    if val == 0:
                        break
                    if val & ordflag:
                        funcs.append(f"ordinal_{val & 0xFFFF}")
                    else:
                        n_off = rva2off(val & 0x7FFFFFFF)
                        funcs.append(cstr(d, n_off + 2) if n_off is not None else "?")
                    thunk += step
                imports[dll] = funcs
                off += 20

        exports = []
        if dirs and dirs[0][0]:
            off = rva2off(dirs[0][0])
            if off is not None and off + 40 <= len(d):
                nnames = struct.unpack_from("<I", d, off + 24)[0]
                names_rva = struct.unpack_from("<I", d, off + 32)[0]
                no = rva2off(names_rva)
                for i in range(min(nnames, 4096)):
                    if no is None or no + 4 * i + 4 > len(d):
                        break
                    nr = struct.unpack_from("<I", d, no + 4 * i)[0]
                    exports.append(cstr(d, rva2off(nr) or 0))

        end_raw = max((s["rawptr"] + s["rawsize"] for s in sections), default=0)
        overlay = max(0, len(d) - end_raw)
        try:
            stamp = datetime.datetime.fromtimestamp(ts, datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        except (OverflowError, OSError, ValueError):
            stamp = f"invalid ({ts})"

        return {
            "format": "PE64" if is64 else "PE32",
            "machine": MACHINES_PE.get(machine, hex(machine)),
            "machine_id": machine,
            "is_dll": bool(chars & 0x2000),
            "timestamp": stamp,
            "entry_rva": entry,
            "entry_offset": rva2off(entry),
            "imagebase": hex(imagebase),
            "subsystem": SUBSYSTEMS.get(subsystem, str(subsystem)),
            "mitigations": {
                "ASLR (DYNAMIC_BASE)": bool(dllchars & 0x40),
                "High-entropy VA": bool(dllchars & 0x20),
                "DEP/NX": bool(dllchars & 0x100),
                "CFG": bool(dllchars & 0x4000),
                "SEH disabled (NO_SEH)": bool(dllchars & 0x400),
            },
            "has_signature": bool(len(dirs) > 4 and dirs[4][0]),
            "has_tls": bool(len(dirs) > 9 and dirs[9][0]),
            "sections": sections,
            "imports": imports,
            "exports": exports,
            "overlay_size": overlay,
        }
    except (struct.error, IndexError):
        return None


# --------------------------------------------------------------------------
# ELF parser
# --------------------------------------------------------------------------
def parse_elf(d):
    try:
        if d[:4] != b"\x7fELF":
            return None
        is64 = d[4] == 2
        e = "<" if d[5] == 1 else ">"
        if is64:
            (etype, machine, _, entry, phoff, shoff, _, _, phentsz, phnum,
             shentsz, shnum, shstrndx) = struct.unpack_from(e + "HHIQQQIHHHHHH", d, 16)
        else:
            (etype, machine, _, entry, phoff, shoff, _, _, phentsz, phnum,
             shentsz, shnum, shstrndx) = struct.unpack_from(e + "HHIIIIIHHHHHH", d, 16)

        raw_secs = []
        for i in range(min(shnum, 256)):
            o = shoff + i * shentsz
            if o + shentsz > len(d):
                break
            if is64:
                nm, tp, fl, addr, off, sz, link, info, _, entsz = struct.unpack_from(e + "IIQQQQIIQQ", d, o)
            else:
                nm, tp, fl, addr, off, sz, link, info, _, entsz = struct.unpack_from(e + "IIIIIIIIII", d, o)
            raw_secs.append(dict(nm=nm, type=tp, flags=fl, addr=addr, off=off, size=sz, link=link, entsz=entsz))

        stroff = raw_secs[shstrndx]["off"] if 0 <= shstrndx < len(raw_secs) else 0
        sections = []
        for s in raw_secs:
            s["name"] = cstr(d, stroff + s["nm"])
            data = d[s["off"]:s["off"] + s["size"]] if s["type"] != 8 else b""
            s["entropy"] = round(entropy(data), 3)
            s["perm"] = "R" + ("W" if s["flags"] & 1 else "-") + ("X" if s["flags"] & 4 else "-")
            sections.append(s)

        segments = []
        for i in range(min(phnum, 128)):
            o = phoff + i * phentsz
            if o + phentsz > len(d):
                break
            if is64:
                tp, fl, off, va, _, fsz, msz, _ = struct.unpack_from(e + "IIQQQQQQ", d, o)
            else:
                tp, off, va, _, fsz, msz, fl, _ = struct.unpack_from(e + "IIIIIIII", d, o)
            segments.append(dict(type=tp, flags=fl, offset=off, vaddr=va, filesz=fsz, memsz=msz))

        by_name = {s["name"]: s for s in sections}
        needed, symbols = [], []
        dynstr = by_name.get(".dynstr")
        dynamic = by_name.get(".dynamic")
        bind_now = False
        if dynamic and dynstr:
            esz = 16 if is64 else 8
            for i in range(dynamic["size"] // esz):
                o = dynamic["off"] + i * esz
                tag, val = struct.unpack_from(e + ("qQ" if is64 else "iI"), d, o)
                if tag == 0:
                    break
                if tag == 1:
                    needed.append(cstr(d, dynstr["off"] + val))
                elif tag == 24 or (tag == 30 and val & 8) or (tag == 0x6FFFFFFB and val & 1):
                    bind_now = True
        for sname in (".dynsym", ".symtab"):
            sec = by_name.get(sname)
            if not sec:
                continue
            strsec = raw_secs[sec["link"]] if sec["link"] < len(raw_secs) else None
            if not strsec:
                continue
            esz = 24 if is64 else 16
            for i in range(min(sec["size"] // esz, 20000)):
                o = sec["off"] + i * esz
                nm = struct.unpack_from(e + "I", d, o)[0]
                n = cstr(d, strsec["off"] + nm)
                if n:
                    symbols.append(n)

        gnu_stack = next((s for s in segments if s["type"] == 0x6474E551), None)
        relro = any(s["type"] == 0x6474E552 for s in segments)
        symset = set(symbols)
        return {
            "format": "ELF64" if is64 else "ELF32",
            "machine": MACHINES_ELF.get(machine, str(machine)),
            "machine_id": machine,
            "type": ELF_TYPES.get(etype, str(etype)),
            "endian": "little" if e == "<" else "big",
            "entry": hex(entry),
            "entry_va": entry,
            "mitigations": {
                "PIE": etype == 3,
                "NX (non-exec stack)": bool(gnu_stack and not gnu_stack["flags"] & 1),
                "RELRO": ("Full" if relro and bind_now else "Partial" if relro else "None"),
                "Stack canary": "__stack_chk_fail" in symset,
                "FORTIFY": any(s.endswith("_chk") and s != "__stack_chk_fail" for s in symset),
            },
            "stripped": ".symtab" not in by_name,
            "sections": sections,
            "segments": segments,
            "needed_libs": needed,
            "symbols": sorted(symset),
        }
    except (struct.error, IndexError, KeyError):
        return None


# --------------------------------------------------------------------------
# Strings & IOCs
# --------------------------------------------------------------------------
def extract_strings(d, minlen=5):
    ascii_re = re.compile(rb"[\x20-\x7e]{%d,}" % minlen)
    wide_re = re.compile(rb"(?:[\x20-\x7e]\x00){%d,}" % minlen)
    out = [(m.start(), "A", m.group().decode("ascii")) for m in ascii_re.finditer(d)]
    out += [(m.start(), "W", m.group().decode("utf-16le", "ignore")) for m in wide_re.finditer(d)]
    out.sort()
    return out


def extract_iocs(strings):
    found = {k: set() for k in IOC_PATTERNS}
    for _, _, s in strings:
        for name, rx in IOC_PATTERNS.items():
            for m in rx.findall(s):
                found[name].add(m)
    # drop obvious noise
    found["IPv4"] = {i for i in found["IPv4"] if not i.startswith(("0.", "255.")) and i != "127.0.0.1"}
    return {k: sorted(v)[:40] for k, v in found.items() if v}


# --------------------------------------------------------------------------
# Capability / packer / risk analysis
# --------------------------------------------------------------------------
def detect_capabilities(api_names):
    lower = {a.lower(): a for a in api_names}
    caps = {}
    for cat, apis in SUSPICIOUS_APIS.items():
        hits = sorted({lower[a.lower()] for a in apis if a.lower() in lower})
        if hits:
            caps[cat] = hits
    return caps


def detect_packers(sections, d, n_imports):
    notes = []
    for s in sections:
        if s["name"] in PACKER_SECTIONS:
            notes.append(f"Section '{s['name']}' indicates {PACKER_SECTIONS[s['name']]}")
    if b"UPX!" in d[:4096] or b"$Info: This file is packed with the UPX" in d:
        notes.append("UPX signature found")
    hi = [s["name"] for s in sections if s["entropy"] >= 7.2 and s.get("rawsize", s.get("size", 0)) > 1024]
    if hi:
        notes.append("High-entropy sections: " + ", ".join(hi))
    if sections and n_imports is not None and n_imports < 10:
        notes.append(f"Very few imports ({n_imports}) - typical of packed/obfuscated binaries")
    return notes


def risk_score(findings):
    pts = {"HIGH": 25, "MED": 10, "LOW": 3}
    score = min(100, sum(pts[s] for s, _ in findings))
    label = "CRITICAL" if score >= 70 else "HIGH" if score >= 45 else "MEDIUM" if score >= 20 else "LOW"
    return score, label


# --------------------------------------------------------------------------
# Disassembly (optional)
# --------------------------------------------------------------------------
def disassemble_entry(d, info, count):
    try:
        import capstone as cs
    except ImportError:
        return None, "capstone not installed (pip install capstone) - skipping disassembly"
    mid = info.get("machine_id")
    table = {3: (cs.CS_ARCH_X86, cs.CS_MODE_32), 0x14C: (cs.CS_ARCH_X86, cs.CS_MODE_32),
             62: (cs.CS_ARCH_X86, cs.CS_MODE_64), 0x8664: (cs.CS_ARCH_X86, cs.CS_MODE_64),
             40: (cs.CS_ARCH_ARM, cs.CS_MODE_ARM), 0x1C0: (cs.CS_ARCH_ARM, cs.CS_MODE_ARM),
             183: (cs.CS_ARCH_ARM64, cs.CS_MODE_ARM), 0xAA64: (cs.CS_ARCH_ARM64, cs.CS_MODE_ARM)}
    if mid not in table:
        return None, "unsupported architecture for disassembly"
    if info["format"].startswith("PE"):
        off = info.get("entry_offset")
        base = int(info["imagebase"], 16) + info["entry_rva"]
    else:
        base = info["entry_va"]
        off = None
        for s in info["segments"]:
            if s["type"] == 1 and s["vaddr"] <= base < s["vaddr"] + s["filesz"]:
                off = base - s["vaddr"] + s["offset"]
                break
    if off is None:
        return None, "could not map entry point to file offset"
    md = cs.Cs(*table[mid])
    lines = []
    for i in md.disasm(d[off:off + count * 16], base):
        lines.append(f"  0x{i.address:08x}:  {i.bytes.hex():<20} {i.mnemonic} {i.op_str}")
        if len(lines) >= count:
            break
    return lines, None


def hexdump(d, offset, length):
    for i in range(offset, min(offset + length, len(d)), 16):
        chunk = d[i:i + 16]
        hx = " ".join(f"{b:02x}" for b in chunk)
        asc = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        print(f"  {i:08x}  {hx:<47}  |{asc}|")


# --------------------------------------------------------------------------
# Report
# --------------------------------------------------------------------------
def analyze(path, args):
    with open(path, "rb") as f:
        d = f.read()
    report = {"file": os.path.abspath(path), "size": len(d), "type": identify(d)}
    report["hashes"] = hashes(d)
    report["entropy"] = round(entropy(d), 3)
    findings = []

    section_title("FILE INFORMATION")
    kv("Path", report["file"])
    kv("Size", f"{human(len(d))} ({len(d)} bytes)")
    kv("Detected type", report["type"])
    for k, v in report["hashes"].items():
        kv(k.upper(), v)
    kv("Overall entropy", ent_label(report["entropy"]))
    if report["entropy"] >= 7.2:
        findings.append(("MED", "Overall entropy very high (compressed/encrypted content)"))

    info = parse_pe(d) or parse_elf(d)
    api_names, n_imports = [], None
    if info:
        report["binary"] = {k: v for k, v in info.items() if k not in ("symbols",)}
        section_title(f"{info['format']} HEADER")
        kv("Architecture", info["machine"])
        if info["format"].startswith("PE"):
            kv("Type", "DLL" if info["is_dll"] else "EXE")
            kv("Compile timestamp", info["timestamp"])
            kv("Subsystem", info["subsystem"])
            kv("Image base", info["imagebase"])
            kv("Entry point RVA", f"0x{info['entry_rva']:x}")
            kv("Digitally signed", info["has_signature"])
            kv("TLS callbacks dir", info["has_tls"])
            kv("Overlay", human(info["overlay_size"]) if info["overlay_size"] else "none")
            if info["has_tls"]:
                findings.append(("LOW", "TLS directory present (can run code before entry point)"))
            if info["overlay_size"] > 1024:
                findings.append(("LOW", f"Overlay data appended ({human(info['overlay_size'])})"))
            if not info["has_signature"]:
                findings.append(("LOW", "Binary is not digitally signed"))
        else:
            kv("Type", info["type"])
            kv("Endianness", info["endian"])
            kv("Entry point", info["entry"])
            kv("Stripped", info["stripped"])
            kv("Needed libraries", ", ".join(info["needed_libs"]) or "none (static?)")

        section_title("SECURITY MITIGATIONS")
        for k, v in info["mitigations"].items():
            good = v is True or v == "Full"
            colr = C.G if good else (C.Y if v == "Partial" else C.R)
            kv(k, f"{colr}{v}{C.X}")
            if v is False or v == "None":
                if k in ("DEP/NX", "NX (non-exec stack)"):
                    findings.append(("MED", f"{k} disabled"))
                elif k in ("ASLR (DYNAMIC_BASE)", "PIE"):
                    findings.append(("LOW", f"{k} disabled"))

        section_title("SECTIONS")
        print(f"  {C.BD}{'Name':<12}{'VirtAddr':<12}{'Size':<12}{'Perm':<6}Entropy{C.X}")
        for s in info["sections"]:
            size = s.get("rawsize", s.get("size", 0))
            va = s.get("vaddr", s.get("addr", 0))
            warn = ""
            if s["perm"] == "RWX":
                warn = f" {C.R}<-- RWX{C.X}"
                findings.append(("HIGH", f"Section '{s['name']}' is writable AND executable"))
            print(f"  {s['name']:<12}0x{va:<10x}{size:<12}{s['perm']:<6}{ent_label(s['entropy'])}{warn}")

        if info["format"].startswith("PE"):
            section_title("IMPORTS")
            n_imports = sum(len(v) for v in info["imports"].values())
            for dll, fn in info["imports"].items():
                print(f"  {C.M}{dll}{C.X} ({len(fn)})")
                api_names += fn
                for name in fn[:args.max_imports]:
                    print(f"      {name}")
                if len(fn) > args.max_imports:
                    print(f"      ... +{len(fn) - args.max_imports} more")
            if not info["imports"]:
                print("  (no import table found)")
            if info["exports"]:
                section_title("EXPORTS")
                for n in info["exports"][:50]:
                    print(f"  {n}")
        else:
            api_names = info["symbols"]
            n_imports = len(info["symbols"])
            section_title("SYMBOLS (sample)")
            print("  " + ", ".join(info["symbols"][:40]) + (" ..." if len(info["symbols"]) > 40 else ""))

        caps = detect_capabilities(api_names)
        report["capabilities"] = caps
        section_title("SUSPICIOUS CAPABILITIES")
        if caps:
            for cat, hits in caps.items():
                sev = "HIGH" if cat in ("Process injection", "Anti-debugging", "Keylogging / input capture") else "MED" if cat in ("Persistence / registry", "Privilege manipulation", "Dynamic code loading") else "LOW"
                findings.append((sev, f"{cat}: {', '.join(hits[:5])}"))
                print(f"  {C.Y}[{cat}]{C.X} {', '.join(hits)}")
        else:
            print("  none detected")

        packers = detect_packers(info["sections"], d, n_imports)
        report["packer_notes"] = packers
        section_title("PACKER / PROTECTOR HEURISTICS")
        if packers:
            for p in packers:
                print(f"  {C.R}!{C.X} {p}")
                findings.append(("MED", p))
        else:
            print("  nothing suspicious")

        if args.disasm:
            section_title(f"ENTRY POINT DISASSEMBLY ({args.disasm} instr)")
            lines, err = disassemble_entry(d, info, args.disasm)
            print(err if err else "\n".join(lines))

    if not args.no_strings:
        strings = extract_strings(d, args.min_len)
        iocs = extract_iocs(strings)
        report["string_count"] = len(strings)
        report["iocs"] = iocs
        section_title(f"STRINGS ({len(strings)} found, min length {args.min_len})")
        for off, kind, s in strings[:args.max_strings]:
            print(f"  0x{off:08x} [{kind}] {s[:120]}")
        if len(strings) > args.max_strings:
            print(f"  ... {len(strings) - args.max_strings} more (use --max-strings)")
        section_title("INDICATORS EXTRACTED FROM STRINGS")
        if iocs:
            for k, vals in iocs.items():
                print(f"  {C.Y}{k}{C.X} ({len(vals)})")
                for v in vals[:10]:
                    print(f"      {v[:110]}")
            if "URL" in iocs or "IPv4" in iocs:
                findings.append(("LOW", "Embedded URLs / IP addresses found"))
        else:
            print("  none")

    if args.hex:
        off = int(args.hex[0], 0)
        ln = int(args.hex[1], 0)
        section_title(f"HEX DUMP @ 0x{off:x} ({ln} bytes)")
        hexdump(d, off, ln)

    score, label = risk_score(findings)
    report["findings"] = findings
    report["risk"] = {"score": score, "label": label}
    section_title("FINDINGS & RISK")
    colour = {"HIGH": C.R, "MED": C.Y, "LOW": C.G}
    for sev, msg in findings:
        print(f"  {colour[sev]}[{sev}]{C.X} {msg}")
    bar = "#" * (score // 5) + "." * (20 - score // 5)
    print(f"\n  {C.BD}Risk score:{C.X} [{bar}] {score}/100 -> {C.BD}{label}{C.X}")
    print("  (Heuristic static score only - not proof of malicious intent.)")

    if args.json:
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, default=str)
        print(f"\n  JSON report saved to {args.json}")


def main():
    print(C.CY + BANNER + C.X)
    print(f"{C.BD}{TOOL_NAME}{C.X}")
    print(f"{C.G}{CREDIT}{C.X}\n")

    ap = argparse.ArgumentParser(description="Static reverse engineering & binary analysis (never executes the sample).")
    ap.add_argument("file", help="binary to analyze")
    ap.add_argument("--min-len", type=int, default=5, help="minimum string length (default 5)")
    ap.add_argument("--max-strings", type=int, default=60, help="strings to print (default 60)")
    ap.add_argument("--max-imports", type=int, default=15, help="imports shown per DLL (default 15)")
    ap.add_argument("--no-strings", action="store_true", help="skip string extraction")
    ap.add_argument("--disasm", type=int, metavar="N", help="disassemble N instructions at entry point (needs capstone)")
    ap.add_argument("--hex", nargs=2, metavar=("OFFSET", "LENGTH"), help="hex dump region, e.g. --hex 0x0 256")
    ap.add_argument("--json", metavar="FILE", help="write full JSON report")
    args = ap.parse_args()

    if not os.path.isfile(args.file):
        print(f"{C.R}[!] File not found: {args.file}{C.X}")
        sys.exit(1)
    try:
        analyze(args.file, args)
    except KeyboardInterrupt:
        print("\n[!] Interrupted")
    print(f"\n{C.CY}{CREDIT}{C.X}")


if __name__ == "__main__":
    main()
