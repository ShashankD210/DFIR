#!/usr/bin/env python3
"""Shared, allowlisted execution wrapper for dfir_toolkit.py."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path


TOOLKIT = Path(
    os.getenv("DFIR_TOOLKIT_PATH", str(Path(__file__).resolve().parents[1] / "dfir_toolkit.py"))
).expanduser().resolve()
OUTPUT_DIR = Path(os.getenv("DFIR_LOCAL_OUTPUT", os.getenv("DFIR_CLOUD_OUTPUT", "./output")))
ALLOWED_ACTIONS = {"check-tools", "hash", "logs"}


def execute(action: str, argument: str = "") -> tuple[str, str]:
    """Execute one approved toolkit action and return status plus output."""
    if not TOOLKIT.is_file():
        return "failed", f"DFIR toolkit not found: {TOOLKIT}"
    if action not in ALLOWED_ACTIONS:
        return "failed", f"unsupported action: {action}"

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    if action == "check-tools":
        command = [sys.executable, str(TOOLKIT), "check-tools"]
    elif action == "hash":
        target = Path(argument).expanduser().resolve()
        if not target.exists():
            return "failed", f"path does not exist: {target}"
        command = [sys.executable, str(TOOLKIT), "hash", str(target), "--output", str(OUTPUT_DIR / "hashes.json")]
    else:
        command = [sys.executable, str(TOOLKIT), "logs", "--output", str(OUTPUT_DIR / "logs")]

    try:
        completed = subprocess.run(command, capture_output=True, text=True, timeout=300)
    except subprocess.TimeoutExpired:
        return "failed", "toolkit command timed out after 300 seconds"
    output = (completed.stdout + completed.stderr)[-200_000:]
    return ("completed" if completed.returncode == 0 else "failed"), output
