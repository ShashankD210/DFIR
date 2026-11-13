# DFIR Toolkit - Installation Guide

Digital Forensics & Incident Response toolkit for Linux environments.

## Requirements

- Python 3.8+
- Root privileges (for triage, capture, and rootkit modules)

## Quick Install

```bash
# Make executable (already done)
chmod +x dfir_toolkit.py

# Check available tools
./dfir_toolkit.py check-tools

# Install all recommended DFIR tools (requires sudo)
sudo ./dfir_toolkit.py install-all
```

## Manual Tool Installation

### APT Packages (Ubuntu/Debian)

```bash
sudo apt update
sudo apt install -y \
    autopsy sleuthkit \
    tshark tcpdump \
    yara clamav \
    binutils strace lsof net-tools iproute2 \
    chkrootkit rkhunter lynis \
    foremost bulk-extractor \
    libimage-exiftool-perl \
    dc3dd dcfldd \
    hashdeep ssdeep \
    john \
    plaso auditd \
    radare2 osquery \
    libhivex-bin
```

### pip Packages

```bash
pip3 install volatility3 binwalk rekall peframe regipy oledump pdf-parser capa lief unicorn
```

## Pre-built Distributions

Some tools require manual download:

- **Ghidra**: Download from NSA [GitHub](https://github.com/NationalSecurityAgency/ghidra)
- **Velociraptor**: Download from [GitHub](https://github.com/Velocidex/velociraptor)

## Usage

```bash
# System triage
sudo ./dfir_toolkit.py triage --output /tmp/dfir

# File hashing
./dfir_toolkit.py hash /path/to/files --algo sha256 --output hashes.json

# Memory analysis
./dfir_toolkit.py memory memory.dump --output /tmp/memory_analysis

# YARA scanning
./dfir_toolkit.py yara rules.yar /target/path --output yara_results.txt

# Network capture
sudo ./dfir_toolkit.py capture --iface eth0 --duration 120 --output capture.pcap

# Log collection
./dfir_toolkit.py logs --output /tmp/logs

# Rootkit check
sudo ./dfir_toolkit.py rootkit --output /tmp/rootkit.txt

# Generate report
./dfir_toolkit.py report /tmp/dfir/triage_* --output report.txt
```

## Cloud and Local Application

The integrated cloud/local application is in [dfir_app](./dfir_app/). It runs
the same [dfir_toolkit.py](./dfir_toolkit.py) locally through the outbound
connector and inside the cloud container through an authenticated API. The
application copy at [dfir_app/dfir_toolkit.py](./dfir_app/dfir_toolkit.py)
resolves to that same file. See
[dfir_app/README.md](./dfir_app/README.md) for local Compose and cloud
deployment instructions.

To start the cloud service locally from the repository root:

```bash
export DFIR_ADMIN_TOKEN="replace-with-a-long-random-secret"
docker compose -f dfir_app/docker-compose.yml up --build
```

The cloud API supports `check-tools`, `triage`, `hash`, `memory`, `yara`,
`capture`, `logs`, `rootkit`, and `report`. The `install-all` command remains a
local-only operation because it changes the host package environment.

## Tool Categories

| Category | Tools |
|----------|-------|
| Memory Forensics | volatility3, rekall, volatility2 |
| Disk Forensics | autopsy, sleuthkit, foremost, bulk-extractor, dc3dd, dcfldd |
| Network Analysis | wireshark/tshark, tcpdump |
| Malware Analysis | yara, clamav, peframe, oledump, pdfid, capa, radare2, lief, binwalk |
| Rootkit Detection | chkrootkit, rkhunter |
| Security Auditing | lynis, auditd, osquery |
| File Carving | hashdeep, ssdeep |
| Registry Analysis | hivex, regipy |
| Metadata Extraction | exiftool |

## License

Open-source - use responsibly and in compliance with applicable laws.
