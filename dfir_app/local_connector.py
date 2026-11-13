#!/usr/bin/env python3
"""Outbound-only local connector for the DFIR cloud control plane."""

from __future__ import annotations

import json
import os
import sys
import time
import urllib.error
import urllib.request
from toolkit_runner import TOOLKIT, execute


CLOUD_URL = os.getenv("DFIR_CLOUD_URL", "http://127.0.0.1:8080").rstrip("/")
AGENT_ID = os.getenv("DFIR_AGENT_ID", "")
AGENT_TOKEN = os.getenv("DFIR_AGENT_TOKEN", "")
POLL_SECONDS = max(2, int(os.getenv("DFIR_POLL_SECONDS", "10")))


def request(path: str, method: str = "GET", payload: dict | None = None) -> tuple[int, dict]:
    body = None if payload is None else json.dumps(payload).encode()
    req = urllib.request.Request(
        CLOUD_URL + path,
        data=body,
        method=method,
        headers={"Authorization": f"Bearer {AGENT_TOKEN}", "Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as response:
            raw = response.read()
            return response.status, json.loads(raw or b"{}")
    except urllib.error.HTTPError as error:
        if error.code == 204:
            return 204, {}
        raise


def main() -> None:
    if not AGENT_ID or not AGENT_TOKEN:
        raise SystemExit("DFIR_AGENT_ID and DFIR_AGENT_TOKEN must be set")
    if not TOOLKIT.is_file():
        raise SystemExit(f"DFIR toolkit not found: {TOOLKIT}. Set DFIR_TOOLKIT_PATH to its location.")
    print(f"Polling {CLOUD_URL} as agent {AGENT_ID}")
    print(f"Using toolkit {TOOLKIT}")
    while True:
        try:
            status, command = request(f"/api/agents/{AGENT_ID}/commands")
            if status == 200:
                result_status, output = execute(command["action"], command.get("argument", ""))
                request(
                    f"/api/agents/{AGENT_ID}/results",
                    "POST",
                    {"command_id": command["id"], "status": result_status, "output": output},
                )
                print(f"{command['id']}: {result_status}")
        except (OSError, urllib.error.URLError, TimeoutError) as error:
            print(f"connection error: {error}", file=sys.stderr)
        time.sleep(POLL_SECONDS)


if __name__ == "__main__":
    main()
