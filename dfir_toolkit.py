#!/usr/bin/env python3
"""
DFIR Toolkit - Digital Forensics & Incident Response
Linux Executable Script
Requires: Python 3.8+, various open-source tools (auto-checks availability)
"""

import os
import sys
import subprocess
import shutil
import argparse
import json
import hashlib
import datetime
import socket
import platform
from pathlib import Path

# ─── ANSI Colors ─────────────────────────────────────────────────────────────
RED    = "\033[91m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

# ─── Banner ───────────────────────────────────────────────────────────────────
BANNER = f"""
{CYAN}{BOLD}
╔══════════════════════════════════════════════════════════════╗
║          DFIR TOOLKIT - Digital Forensics & IR               ║
║          Linux | Open-Source Tools | v1.0                    ║
╚══════════════════════════════════════════════════════════════╝
{RESET}"""

# ─── Open-Source Tool Registry ────────────────────────────────────────────────
TOOLS = {
    "volatility3":  {"cmd": "vol",          "install": "pip3 install volatility3",           "purpose": "Memory forensics"},
    "autopsy":      {"cmd": "autopsy",       "install": "apt install autopsy",                "purpose": "Disk forensics GUI"},
    "sleuthkit":    {"cmd": "fls",           "install": "apt install sleuthkit",              "purpose": "Disk/filesystem analysis"},
    "wireshark":    {"cmd": "tshark",        "install": "apt install tshark",                 "purpose": "Network packet analysis"},
    "tcpdump":      {"cmd": "tcpdump",       "install": "apt install tcpdump",                "purpose": "Live packet capture"},
    "yara":         {"cmd": "yara",          "install": "apt install yara",                   "purpose": "Malware pattern matching"},
    "clamav":       {"cmd": "clamscan",      "install": "apt install clamav",                 "purpose": "Antivirus scanning"},
    "strings":      {"cmd": "strings",       "install": "apt install binutils",               "purpose": "Extract strings from binaries"},
    "strace":       {"cmd": "strace",        "install": "apt install strace",                 "purpose": "System call tracing"},
    "lsof":         {"cmd": "lsof",          "install": "apt install lsof",                   "purpose": "List open files/network"},
    "netstat":      {"cmd": "netstat",       "install": "apt install net-tools",              "purpose": "Network connections"},
    "ss":           {"cmd": "ss",            "install": "apt install iproute2",               "purpose": "Socket statistics"},
    "chkrootkit":   {"cmd": "chkrootkit",    "install": "apt install chkrootkit",             "purpose": "Rootkit detection"},
    "rkhunter":     {"cmd": "rkhunter",      "install": "apt install rkhunter",               "purpose": "Rootkit hunter"},
    "lynis":        {"cmd": "lynis",         "install": "apt install lynis",                  "purpose": "Security auditing"},
    "foremost":     {"cmd": "foremost",      "install": "apt install foremost",               "purpose": "File carving"},
    "bulk_extractor":{"cmd": "bulk_extractor","install": "apt install bulk-extractor",        "purpose": "Bulk data extraction"},
    "binwalk":      {"cmd": "binwalk",       "install": "pip3 install binwalk",               "purpose": "Firmware/binary analysis"},
    "exiftool":     {"cmd": "exiftool",      "install": "apt install libimage-exiftool-perl", "purpose": "Metadata extraction"},
    "dc3dd":        {"cmd": "dc3dd",         "install": "apt install dc3dd",                  "purpose": "Forensic disk imaging"},
    "dcfldd":       {"cmd": "dcfldd",        "install": "apt install dcfldd",                 "purpose": "Enhanced dd for forensics"},
"hashdeep":     {"cmd": "hashdeep",      "install": "apt install hashdeep",               "purpose": "Recursive hashing"},
     "ssdeep":       {"cmd": "ssdeep",        "install": "apt install ssdeep",                 "purpose": "Fuzzy hashing"},
     "john":         {"cmd": "john",          "install": "apt install john",                   "purpose": "Password auditing"},
     "log2timeline": {"cmd": "log2timeline.pl","install": "apt install plaso",                "purpose": "Timeline analysis"},
     "auditd":       {"cmd": "auditctl",      "install": "apt install auditd",                 "purpose": "Linux audit framework"},
     "rekall":       {"cmd": "rekall",        "install": "pip3 install rekall",                "purpose": "Memory forensics (alt)"},
     "volatility2":  {"cmd": "vol.py",        "install": "pip3 install volatility",            "purpose": "Memory forensics (v2)"},
     "hivex":        {"cmd": "hivexsh",       "install": "apt install libhivex-bin",           "purpose": "Windows registry extraction"},
     "regipy":       {"cmd": "regipy",        "install": "pip3 install regipy",                "purpose": "Registry parser"},
     "peframe":      {"cmd": "peframe",       "install": "pip3 install peframe",               "purpose": "PE file analysis"},
     "oledump":      {"cmd": "oledump.py",    "install": "pip3 install oledump",               "purpose": "Office doc analysis"},
     "pdfid":        {"cmd": "pdfid.py",      "install": "pip3 install pdfid",                 "purpose": "PDF malware analysis"},
     "pdfparser":    {"cmd": "pdf-parser.py", "install": "pip3 install pdf-parser",              "purpose": "PDF structure analysis"},
     "radare2":      {"cmd": "r2",            "install": "apt install radare2",                "purpose": "Reverse engineering"},
     "capa":         {"cmd": "capa",          "install": "pip3 install capa",                "purpose": "Malware capability analysis"},
     "osquery":      {"cmd": "osqueryi",      "install": "apt install osquery",                "purpose": "SQL-based endpoint query"},
     "lief":         {"cmd": "lief",          "install": "pip3 install lief",                  "purpose": "Binary analysis library"},
     "unicorn":      {"cmd": "unicorn",       "install": "pip3 install unicorn",               "purpose": "CPU emulation"},
 }

# ─── Helpers ──────────────────────────────────────────────────────────────────
def log(msg, level="info"):
    ts = datetime.datetime.now().strftime("%H:%M:%S")
    colors = {"info": CYAN, "ok": GREEN, "warn": YELLOW, "err": RED}
    icons  = {"info": "ℹ", "ok": "✓", "warn": "⚠", "err": "✗"}
    print(f"{colors.get(level,'')}{icons.get(level,'')} [{ts}] {msg}{RESET}")

def run_cmd(cmd, capture=True, timeout=60):
    try:
        use_shell = isinstance(cmd, str)
        result = subprocess.run(
            cmd, shell=use_shell, capture_output=capture,
            stdout=subprocess.PIPE if capture else None,
            stderr=subprocess.STDOUT if capture and not use_shell else None,
            text=True, timeout=timeout
        )
        stdout = result.stdout.strip() if capture and result.stdout else ""
        return stdout, result.returncode
    except subprocess.TimeoutExpired:
        log(f"Command timed out after {timeout}s: {cmd[:60] if isinstance(cmd, str) else str(cmd)[:60]}", "warn")
        return "", -2
    except Exception as e:
        return str(e), -1

def is_root():
    return os.geteuid() == 0

def check_tool(name):
    entry = TOOLS.get(name, {})
    cmd = entry.get("cmd", name)
    return shutil.which(cmd) is not None

def require_root():
    if not is_root():
        log("This module requires root privileges. Run with sudo.", "err")
        sys.exit(1)

def save_output(content, path):
    try:
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", encoding="utf-8", errors="replace") as f:
            f.write(content)
        log(f"Saved → {path}", "ok")
    except OSError as e:
        log(f"Failed to save {path}: {e}", "err")

# ─── Modules ──────────────────────────────────────────────────────────────────

def check_tools():
    """Check availability of all DFIR tools."""
    print(f"\n{BOLD}{'Tool':<20} {'Binary':<18} {'Status':<12} {'Purpose'}{RESET}")
    print("─" * 80)
    available = 0
    for name, meta in TOOLS.items():
        found = check_tool(name)
        status = f"{GREEN}INSTALLED{RESET}" if found else f"{RED}MISSING{RESET}"
        if found: available += 1
        print(f"{name:<20} {meta['cmd']:<18} {status:<22} {meta['purpose']}")
    print(f"\n{GREEN}{available}{RESET}/{len(TOOLS)} tools available.\n")
    missing = [n for n in TOOLS if not check_tool(n)]
    if missing:
        print(f"{YELLOW}Install missing tools:{RESET}")
        for m in missing:
            print(f"  {TOOLS[m]['install']}")


def triage_system(output_dir):
    """Rapid system triage - collect volatile data."""
    require_root()
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    base = f"{output_dir}/triage_{ts}"
    os.makedirs(base, exist_ok=True)
    log(f"Starting triage → {base}")

    hostname = socket.gethostname()
    uname = platform.uname()

    steps = [
        # (label, command, output_file)
        ("System Info",        "uname -a && uptime && date",                    "system_info.txt"),
        ("Running Processes",  "ps auxf",                                        "processes.txt"),
        ("Network Connections","ss -tulpn 2>/dev/null || netstat -tulpn",        "network_conn.txt"),
        ("Listening Ports",    "ss -lntp",                                       "listening_ports.txt"),
        ("Active Users",       "w && last | head -50",                           "active_users.txt"),
        ("Logged-in Users",    "who -a",                                         "who.txt"),
        ("Cron Jobs",          "cat /etc/crontab; ls /etc/cron*",                "crontabs.txt"),
        ("Startup Services",   "systemctl list-units --type=service --state=running 2>/dev/null || service --status-all 2>&1", "services.txt"),
        ("Open Files",         "lsof -n 2>/dev/null | head -500",                "open_files.txt"),
        ("Loaded Modules",     "lsmod",                                          "kernel_modules.txt"),
        ("ARP Cache",          "arp -n 2>/dev/null || ip neigh",                 "arp_cache.txt"),
        ("Routing Table",      "ip route",                                       "routing.txt"),
        ("DNS Config",         "cat /etc/resolv.conf",                           "dns.txt"),
        ("Hosts File",         "cat /etc/hosts",                                 "hosts.txt"),
        ("Passwd File",        "cat /etc/passwd",                                "passwd.txt"),
        ("Shadow Hashes",      "cat /etc/shadow 2>/dev/null",                    "shadow.txt"),
        ("Sudoers",            "cat /etc/sudoers 2>/dev/null",                   "sudoers.txt"),
        ("SUID Files",         "find / -perm -4000 -type f 2>/dev/null",         "suid_files.txt"),
        ("World-Writable",     "find /tmp /var/tmp /dev/shm -writable 2>/dev/null","world_writable.txt"),
        ("Recent Files (24h)", "find /home /tmp /var/tmp -mtime -1 2>/dev/null", "recent_files.txt"),
        ("Bash History",       "cat ~/.bash_history 2>/dev/null; cat /root/.bash_history 2>/dev/null", "bash_history.txt"),
        ("Environment",        "env",                                            "environment.txt"),
        ("Mounted FS",         "mount | cat /proc/mounts",                       "mounts.txt"),
        ("Disk Usage",         "df -h",                                          "disk_usage.txt"),
        ("Memory Info",        "free -h && cat /proc/meminfo",                   "memory.txt"),
        ("Dmesg (last 200)",   "dmesg | tail -200",                              "dmesg.txt"),
        ("Auth Log",           "tail -500 /var/log/auth.log 2>/dev/null || tail -500 /var/log/secure 2>/dev/null", "auth_log.txt"),
        ("Syslog",             "tail -500 /var/log/syslog 2>/dev/null || tail -500 /var/log/messages 2>/dev/null", "syslog.txt"),
    ]

    results = {}
    for label, cmd, fname in steps:
        log(f"  Collecting: {label}")
        out, rc = run_cmd(cmd)
        fpath = f"{base}/{fname}"
        save_output(out, fpath)
        results[label] = {"file": fpath, "rc": rc, "lines": len(out.splitlines())}

    # Write index
    idx = {"hostname": hostname, "timestamp": ts, "platform": str(uname), "collections": results}
    save_output(json.dumps(idx, indent=2), f"{base}/triage_index.json")
    log(f"Triage complete → {base}/triage_index.json", "ok")
    return base


def hash_files(target_path, algo="sha256"):
    """Recursively hash files for integrity verification."""
    algos = {"md5": hashlib.md5, "sha1": hashlib.sha1, "sha256": hashlib.sha256}
    h_func = algos.get(algo, hashlib.sha256)
    results = {}
    target = Path(target_path)
    files = list(target.rglob("*")) if target.is_dir() else [target]
    log(f"Hashing {len(files)} files with {algo.upper()}...")
    for f in files:
        if f.is_file():
            try:
                h = h_func()
                with open(f, "rb") as fh:
                    for chunk in iter(lambda: fh.read(65536), b""):
                        h.update(chunk)
                results[str(f)] = {"hash": h.hexdigest(), "size": f.stat().st_size}
            except (PermissionError, OSError) as e:
                results[str(f)] = {"hash": "ERROR", "error": str(e)}
    return results


def memory_analysis(mem_image, output_dir, profile=None):
    """Run Volatility3 memory analysis."""
    if not check_tool("volatility3"):
        log("volatility3 not installed. Run: pip3 install volatility3", "err")
        return
    if not os.path.isfile(mem_image):
        log(f"Memory image not found: {mem_image}", "err")
        return
    os.makedirs(output_dir, exist_ok=True)
    plugins = [
        "windows.pslist.PsList",
        "windows.pstree.PsTree",
        "windows.cmdline.CmdLine",
        "windows.netstat.NetStat",
        "windows.malfind.Malfind",
        "windows.dlllist.DllList",
        "windows.handles.Handles",
        "linux.pslist.PsList",
        "linux.bash.Bash",
        "linux.netstat.Netstat",
    ]
    for plugin in plugins:
        log(f"Running plugin: {plugin}")
        out_file = f"{output_dir}/{plugin.replace('.', '_')}.txt"
        cmd = ["vol", "-f", mem_image, plugin]
        out, _ = run_cmd(cmd, timeout=300)
        save_output(out, out_file)
    log("Memory analysis complete.", "ok")


def scan_with_yara(rules_path, target_path, output_file):
    """Scan files/directory with YARA rules."""
    if not check_tool("yara"):
        log("yara not installed. Run: apt install yara", "err")
        return
    if not os.path.exists(rules_path):
        log(f"YARA rules path not found: {rules_path}", "err")
        return
    if not os.path.exists(target_path):
        log(f"Target path not found: {target_path}", "err")
        return
    log(f"YARA scan: {target_path} with rules: {rules_path}")
    cmd = ["yara", "-r", rules_path, target_path]
    out, rc = run_cmd(cmd, timeout=300)
    save_output(out, output_file)
    hits = len([l for l in out.splitlines() if l.strip()])
    log(f"YARA scan complete: {hits} hits → {output_file}", "ok" if hits == 0 else "warn")


def network_capture(interface, duration, output_pcap):
    """Capture network traffic with tcpdump."""
    require_root()
    if not check_tool("tcpdump"):
        log("tcpdump not installed. Run: apt install tcpdump", "err")
        return
    log(f"Capturing on {interface} for {duration}s → {output_pcap}")
    cmd = ["tcpdump", "-i", interface, "-w", output_pcap, "-G", str(duration), "-W", "1"]
    _, rc = run_cmd(cmd, capture=False, timeout=duration + 15)
    if rc not in (0, -2):
        log(f"tcpdump exited with code {rc}. Check interface name and permissions.", "warn")
    else:
        log(f"Capture complete → {output_pcap}", "ok")


def collect_logs(output_dir):
    """Collect and archive critical system logs."""
    os.makedirs(output_dir, exist_ok=True)
    log_sources = [
        "/var/log/auth.log", "/var/log/secure",
        "/var/log/syslog", "/var/log/messages",
        "/var/log/kern.log", "/var/log/dpkg.log",
        "/var/log/apt/history.log",
        "/var/log/apache2/access.log", "/var/log/apache2/error.log",
        "/var/log/nginx/access.log", "/var/log/nginx/error.log",
        "/var/log/mysql/error.log",
        "/var/log/audit/audit.log",
    ]
    collected = []
    for src in log_sources:
        if os.path.exists(src):
            dst = f"{output_dir}/{os.path.basename(src)}"
            try:
                shutil.copy2(src, dst)
                log(f"Collected: {src}", "ok")
                collected.append(src)
            except OSError as e:
                log(f"Could not copy {src}: {e}", "warn")
        else:
            log(f"Not found: {src}", "warn")
    # journalctl
    out, _ = run_cmd("journalctl --since '7 days ago' 2>/dev/null | head -10000")
    if out:
        save_output(out, f"{output_dir}/journalctl_7days.txt")
        collected.append("journalctl")
    log(f"Log collection done: {len(collected)} sources → {output_dir}", "ok")


def rootkit_check(output_file):
    """Run rootkit detection tools."""
    require_root()
    results = []
    for tool in ["chkrootkit", "rkhunter"]:
        if check_tool(tool):
            log(f"Running {tool}...")
            cmds = {
                "chkrootkit": "chkrootkit 2>&1",
                "rkhunter": "rkhunter --check --skip-keypress --no-summary 2>&1",
            }
            out, _ = run_cmd(cmds[tool], timeout=300)
            results.append(f"\n{'='*60}\n{tool.upper()} OUTPUT\n{'='*60}\n{out}")
        else:
            log(f"{tool} not available.", "warn")
    if results:
        save_output("\n".join(results), output_file)
        log(f"Rootkit check complete → {output_file}", "ok")
    else:
        log("No rootkit tools found. Install: apt install chkrootkit rkhunter", "err")


def generate_report(triage_dir, output_file):
    """Generate a human-readable DFIR report from triage data."""
    index_file = f"{triage_dir}/triage_index.json"
    if not os.path.exists(index_file):
        log("No triage_index.json found. Run triage first.", "err")
        return
    with open(index_file, encoding="utf-8") as f:
        idx = json.load(f)

    lines = [
        "=" * 70,
        "DFIR INCIDENT REPORT",
        "=" * 70,
        f"Hostname   : {idx.get('hostname', 'N/A')}",
        f"Timestamp  : {idx.get('timestamp', 'N/A')}",
        f"Platform   : {idx.get('platform', 'N/A')}",
        f"Generated  : {datetime.datetime.now().isoformat()}",
        "",
        "COLLECTIONS SUMMARY",
        "-" * 40,
    ]
    for label, meta in idx.get("collections", {}).items():
        lines.append(f"  {label:<30} {meta['lines']:>6} lines  RC={meta['rc']}")

    # Highlight suspicious items
    lines += ["", "INDICATORS OF INTEREST", "-" * 40]
    for fname in ["suid_files.txt", "recent_files.txt", "auth_log.txt"]:
        fpath = f"{triage_dir}/{fname}"
        if os.path.exists(fpath):
            with open(fpath, encoding="utf-8", errors="replace") as f:
                content = f.read()
            lines.append(f"\n[{fname}] ({len(content.splitlines())} lines)")
            lines.append(content[:2000] + ("... [truncated]" if len(content) > 2000 else ""))

    save_output("\n".join(lines), output_file)
    log(f"Report generated → {output_file}", "ok")


def _run_hash(path, algo, output):
    """Helper: hash files then save JSON results."""
    if not os.path.exists(path):
        log(f"Path not found: {path}", "err")
        return
    results = hash_files(path, algo)
    save_output(json.dumps(results, indent=2), output)
    log(f"Hashed {len(results)} files → {output}", "ok")


def install_all_tools():
    """Install all recommended DFIR tools."""
    require_root()
    log("Installing all recommended DFIR tools...")
    apt_pkgs = set()
    pip_pkgs = set()
    for name, meta in TOOLS.items():
        install = meta.get("install", "")
        if install.startswith("apt install"):
            apt_pkgs.add(install.replace("apt install ", ""))
        elif install.startswith("pip3 install"):
            pip_pkgs.add(install.replace("pip3 install ", ""))
    if apt_pkgs:
        log(f"Installing APT packages: {', '.join(sorted(apt_pkgs))}")
        run_cmd(["apt-get", "update"], timeout=120)
        run_cmd(["apt-get", "install", "-y"] + list(apt_pkgs), timeout=600)
    if pip_pkgs:
        log(f"Installing pip packages: {', '.join(sorted(pip_pkgs))}")
        for pkg in sorted(pip_pkgs):
            run_cmd([sys.executable, "-m", "pip", "install", pkg], timeout=300)
    log("Installation complete. Run 'check-tools' to verify.", "ok")


# ─── CLI ──────────────────────────────────────────────────────────────────────

def main():
    print(BANNER)
    parser = argparse.ArgumentParser(
        description="DFIR Toolkit - Digital Forensics & Incident Response for Linux",
        formatter_class=argparse.RawTextHelpFormatter
    )
    sub = parser.add_subparsers(dest="command", title="Modules")

    # check-tools
    sub.add_parser("check-tools", help="Check availability of all DFIR tools")

    # install-all
    sub.add_parser("install-all", help="Install all recommended DFIR tools (requires root)")

    # triage
    p_tri = sub.add_parser("triage", help="Rapid system triage (requires root)")
    p_tri.add_argument("--output", default="/tmp/dfir_output", help="Output directory")

    # hash
    p_hash = sub.add_parser("hash", help="Hash files for integrity verification")
    p_hash.add_argument("path", help="File or directory to hash")
    p_hash.add_argument("--algo", choices=["md5","sha1","sha256"], default="sha256")
    p_hash.add_argument("--output", default="hashes.json")

    # memory
    p_mem = sub.add_parser("memory", help="Volatility3 memory analysis")
    p_mem.add_argument("image", help="Memory image file")
    p_mem.add_argument("--output", default="/tmp/dfir_memory")

    # yara
    p_yara = sub.add_parser("yara", help="YARA scan")
    p_yara.add_argument("rules", help="YARA rules file")
    p_yara.add_argument("target", help="File or directory to scan")
    p_yara.add_argument("--output", default="yara_results.txt")

    # capture
    p_cap = sub.add_parser("capture", help="Live network capture (requires root)")
    p_cap.add_argument("--iface", default="any", help="Network interface")
    p_cap.add_argument("--duration", type=int, default=60, help="Capture duration (seconds)")
    p_cap.add_argument("--output", default="/tmp/capture.pcap")

    # logs
    p_log = sub.add_parser("logs", help="Collect system logs")
    p_log.add_argument("--output", default="/tmp/dfir_logs")

    # rootkit
    p_rk = sub.add_parser("rootkit", help="Rootkit detection (requires root)")
    p_rk.add_argument("--output", default="/tmp/rootkit_check.txt")

    # report
    p_rep = sub.add_parser("report", help="Generate DFIR report from triage data")
    p_rep.add_argument("triage_dir", help="Triage output directory")
    p_rep.add_argument("--output", default="/tmp/dfir_report.txt")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        print(f"\n{YELLOW}Quick start:{RESET}")
        print("  sudo ./dfir_toolkit.py install-all")
        print("  sudo ./dfir_toolkit.py triage --output /tmp/dfir")
        print("  ./dfir_toolkit.py check-tools")
        print("  ./dfir_toolkit.py hash /etc --algo sha256 --output /tmp/etc_hashes.json")
        sys.exit(0)

    dispatch = {
        "check-tools": lambda: check_tools(),
        "install-all": lambda: install_all_tools(),
        "triage":      lambda: triage_system(args.output),
        "hash":        lambda: _run_hash(args.path, args.algo, args.output),
        "memory":      lambda: memory_analysis(args.image, args.output),
        "yara":        lambda: scan_with_yara(args.rules, args.target, args.output),
        "capture":     lambda: network_capture(args.iface, args.duration, args.output),
        "logs":        lambda: collect_logs(args.output),
        "rootkit":     lambda: rootkit_check(args.output),
        "report":      lambda: generate_report(args.triage_dir, args.output),
    }

    try:
        dispatch[args.command]()
    except KeyboardInterrupt:
        print(f"\n{YELLOW}Interrupted by user.{RESET}")
    except Exception as e:
        log(f"Unexpected error: {e}", "err")
        sys.exit(1)


if __name__ == "__main__":
    main()
