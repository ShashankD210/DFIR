#!/usr/bin/env python3
"""Small cloud control plane for the DFIR local connector.

The service stores agents, queued commands, and command results in SQLite. A
local connector polls this service over HTTPS, so no inbound port is needed on
the investigator's machine.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import uuid
from datetime import datetime, timezone
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse


HOST = os.getenv("HOST", "0.0.0.0")
PORT = int(os.getenv("PORT", "8080"))
DATABASE = Path(os.getenv("DFIR_DATABASE", "./data/dfir-cloud.sqlite3"))
ADMIN_TOKEN = os.getenv("DFIR_ADMIN_TOKEN", "")


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def db() -> sqlite3.Connection:
    DATABASE.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(DATABASE)
    connection.row_factory = sqlite3.Row
    connection.executescript(
        """
        CREATE TABLE IF NOT EXISTS agents (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            token_hash TEXT NOT NULL,
            last_seen TEXT,
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS commands (
            id TEXT PRIMARY KEY,
            agent_id TEXT NOT NULL,
            action TEXT NOT NULL,
            argument TEXT,
            status TEXT NOT NULL,
            output TEXT,
            created_at TEXT NOT NULL,
            completed_at TEXT,
            FOREIGN KEY(agent_id) REFERENCES agents(id)
        );
        """
    )
    return connection


def json_bytes(value: object) -> bytes:
    return json.dumps(value, separators=(",", ":")).encode("utf-8")


class Handler(BaseHTTPRequestHandler):
    server_version = "DFIRCloud/1.0"

    def log_message(self, format: str, *args: object) -> None:
        print(f"[{now()}] {self.address_string()} {format % args}")

    def send_json(self, status: int, value: object) -> None:
        body = json_bytes(value)
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def read_json(self) -> dict:
        length = int(self.headers.get("Content-Length", "0"))
        if length > 64 * 1024:
            raise ValueError("request body is too large")
        return json.loads(self.rfile.read(length) or b"{}")

    def authorized_admin(self) -> bool:
        supplied = self.headers.get("Authorization", "")
        return bool(ADMIN_TOKEN) and hmac.compare_digest(
            supplied.removeprefix("Bearer "), ADMIN_TOKEN
        )

    def agent(self, agent_id: str) -> sqlite3.Row | None:
        connection = db()
        try:
            row = connection.execute("SELECT * FROM agents WHERE id = ?", (agent_id,)).fetchone()
            supplied = self.headers.get("Authorization", "").removeprefix("Bearer ")
            if row and supplied and hmac.compare_digest(token_hash(supplied), row["token_hash"]):
                connection.execute("UPDATE agents SET last_seen = ? WHERE id = ?", (now(), agent_id))
                connection.commit()
                return row
            return None
        finally:
            connection.close()

    def do_GET(self) -> None:
        path = urlparse(self.path).path
        if path == "/health":
            self.send_json(HTTPStatus.OK, {"status": "ok", "time": now()})
            return
        if path == "/" and self.authorized_admin():
            self.dashboard()
            return
        if path == "/api/agents" and self.authorized_admin():
            connection = db()
            try:
                rows = connection.execute(
                    "SELECT id, name, last_seen, created_at FROM agents ORDER BY created_at DESC"
                ).fetchall()
                self.send_json(HTTPStatus.OK, {"agents": [dict(row) for row in rows]})
            finally:
                connection.close()
            return
        parts = path.strip("/").split("/")
        if len(parts) == 4 and parts[0:2] == ["api", "agents"] and parts[3] == "commands":
            if not self.agent(parts[2]):
                self.send_json(HTTPStatus.UNAUTHORIZED, {"error": "invalid agent token"})
                return
            connection = db()
            try:
                row = connection.execute(
                    "SELECT id, action, argument FROM commands "
                    "WHERE agent_id = ? AND status = 'queued' ORDER BY created_at LIMIT 1",
                    (parts[2],),
                ).fetchone()
                if not row:
                    self.send_json(HTTPStatus.NO_CONTENT, {})
                else:
                    connection.execute("UPDATE commands SET status = 'running' WHERE id = ?", (row["id"],))
                    connection.commit()
                    self.send_json(HTTPStatus.OK, dict(row))
            finally:
                connection.close()
            return
        self.send_json(HTTPStatus.NOT_FOUND, {"error": "not found"})

    def do_POST(self) -> None:
        path = urlparse(self.path).path
        try:
            payload = self.read_json()
        except (ValueError, json.JSONDecodeError) as error:
            self.send_json(HTTPStatus.BAD_REQUEST, {"error": str(error)})
            return

        if path == "/api/agents" and self.authorized_admin():
            name = str(payload.get("name", "")).strip()
            if not name or len(name) > 120:
                self.send_json(HTTPStatus.BAD_REQUEST, {"error": "name is required"})
                return
            agent_id, token = str(uuid.uuid4()), secrets.token_urlsafe(32)
            connection = db()
            try:
                connection.execute(
                    "INSERT INTO agents VALUES (?, ?, ?, NULL, ?)",
                    (agent_id, name, token_hash(token), now()),
                )
                connection.commit()
            finally:
                connection.close()
            self.send_json(HTTPStatus.CREATED, {"id": agent_id, "name": name, "token": token})
            return

        parts = path.strip("/").split("/")
        if len(parts) == 4 and parts[0:2] == ["api", "agents"] and parts[3] == "commands":
            if not self.authorized_admin():
                self.send_json(HTTPStatus.UNAUTHORIZED, {"error": "admin authorization required"})
                return
            action = str(payload.get("action", "")).strip()
            if action not in {"check-tools", "hash", "logs"}:
                self.send_json(HTTPStatus.BAD_REQUEST, {"error": "unsupported action"})
                return
            connection = db()
            try:
                agent = connection.execute("SELECT id FROM agents WHERE id = ?", (parts[2],)).fetchone()
                if not agent:
                    self.send_json(HTTPStatus.NOT_FOUND, {"error": "agent not found"})
                    return
                command_id = str(uuid.uuid4())
                connection.execute(
                    "INSERT INTO commands VALUES (?, ?, ?, ?, 'queued', NULL, ?, NULL)",
                    (command_id, parts[2], action, str(payload.get("argument", "")), now()),
                )
                connection.commit()
                self.send_json(HTTPStatus.CREATED, {"id": command_id, "status": "queued"})
            finally:
                connection.close()
            return

        if len(parts) == 4 and parts[0:2] == ["api", "agents"] and parts[3] == "results":
            if not self.agent(parts[2]):
                self.send_json(HTTPStatus.UNAUTHORIZED, {"error": "invalid agent token"})
                return
            command_id, status = str(payload.get("command_id", "")), str(payload.get("status", "failed"))
            if status not in {"completed", "failed"}:
                self.send_json(HTTPStatus.BAD_REQUEST, {"error": "invalid result status"})
                return
            connection = db()
            try:
                connection.execute(
                    "UPDATE commands SET status = ?, output = ?, completed_at = ? "
                    "WHERE id = ? AND agent_id = ?",
                    (status, str(payload.get("output", ""))[:200_000], now(), command_id, parts[2]),
                )
                connection.commit()
                self.send_json(HTTPStatus.OK, {"status": status})
            finally:
                connection.close()
            return

        self.send_json(HTTPStatus.NOT_FOUND, {"error": "not found"})

    def dashboard(self) -> None:
        body = b"""<!doctype html><meta charset=utf-8><title>DFIR Cloud</title>
<style>body{font:16px system-ui;max-width:900px;margin:40px auto;padding:0 16px}table{border-collapse:collapse;width:100%}td,th{border:1px solid #ddd;padding:8px;text-align:left}code{word-break:break-all}</style>
<h1>DFIR Cloud control plane</h1><p>Agents connect outbound and poll for approved DFIR commands.</p>
<p>Use the JSON API with the admin bearer token to register agents and queue work.</p>"""
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def main() -> None:
    if not ADMIN_TOKEN:
        raise SystemExit("DFIR_ADMIN_TOKEN must be set")
    db().close()
    print(f"DFIR cloud service listening on {HOST}:{PORT}")
    ThreadingHTTPServer((HOST, PORT), Handler).serve_forever()


if __name__ == "__main__":
    main()
