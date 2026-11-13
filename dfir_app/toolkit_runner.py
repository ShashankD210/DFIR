#!/usr/bin/env python3
"""Shared, allowlisted execution wrapper for dfir_toolkit.py."""

from __future__ import annotations

import os
import json
import shlex
import subprocess
import sys
from pathlib import Path


TOOLKIT = Path(
    os.getenv("DFIR_TOOLKIT_PATH", str(Path(__file__).resolve().with_name("dfir_toolkit.py")))
).expanduser().resolve()
OUTPUT_DIR = Path(os.getenv("DFIR_LOCAL_OUTPUT", os.getenv("DFIR_CLOUD_OUTPUT", "./output")))
ALLOWED_ACTIONS = {
    "check-tools", "triage", "hash", "memory", "yara",
    "capture", "logs", "rootkit", "report",
}


def _arguments(argument: str) -> list[str]:
    """Accept either a shell-like argument string or a JSON string list."""
    if not argument.strip():
        return []
    try:
        parsed = json.loads(argument)
    except json.JSONDecodeError:
        return shlex.split(argument)
    if not isinstance(parsed, list) or not all(isinstance(item, str) for item in parsed):
        raise ValueError("argument must be a shell argument string or JSON string list")
    return parsed


def _default_output(action: str, arguments: list[str]) -> list[str]:
    """Keep default toolkit outputs inside the application data directory."""
    if "--output" in arguments:
        return arguments
    defaults = {
        "triage": ["--output", str(OUTPUT_DIR / "triage")],
        "hash": ["--output", str(OUTPUT_DIR / "hashes.json")],
        "logs": ["--output", str(OUTPUT_DIR / "logs")],
        "rootkit": ["--output", str(OUTPUT_DIR / "rootkit_check.txt")],
        "memory": ["--output", str(OUTPUT_DIR / "memory")],
        "yara": ["--output", str(OUTPUT_DIR / "yara_results.txt")],
        "capture": ["--output", str(OUTPUT_DIR / "capture.pcap")],
        "report": ["--output", str(OUTPUT_DIR / "report.txt")],
    }
    return arguments + defaults.get(action, [])


def execute(action: str, argument: str = "") -> tuple[str, str]:
    """Execute one approved toolkit action and return status plus output."""
    if not TOOLKIT.is_file():
        return "failed", f"DFIR toolkit not found: {TOOLKIT}"
    if action not in ALLOWED_ACTIONS:
        return "failed", f"unsupported action: {action}"

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    try:
        arguments = _default_output(action, _arguments(argument))
    except ValueError as error:
        return "failed", str(error)
    command = [sys.executable, str(TOOLKIT), action, *arguments]

    try:
        completed = subprocess.run(command, capture_output=True, text=True, timeout=300)
    except subprocess.TimeoutExpired:
        return "failed", "toolkit command timed out after 300 seconds"
    output = (completed.stdout + completed.stderr)[-200_000:]
    return ("completed" if completed.returncode == 0 else "failed"), output
