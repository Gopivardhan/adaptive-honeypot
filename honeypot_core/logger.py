"""
Honeypot logging module.

This module defines the ``EventLogger`` class which is responsible for collecting
and persisting all activity observed by the honeypot. Each service (HTTP, SSH,
FTP/SMB) should create an ``EventLogger`` instance and call ``log_event``
whenever a client interacts with the honeypot. Events are stored both in
memory and persisted to a SQLite database so that they can be visualised later.

The schema for the database is intentionally denormalised. Each event record
captures the essentials: timestamp, service name, client IP, client port,
request type (e.g. GET, USER, LOGIN), request path (for HTTP) or command,
payload/body, headers (serialised to JSON), detected tool signature,
classification (e.g. human, bot, scanner), and an opaque meta field for any
additional information. Keeping everything in a single table simplifies
analysis using Dash/SQLite.

If the database file does not exist it will be created automatically.
"""

from __future__ import annotations

import json
import os
import sqlite3
from datetime import datetime
from threading import RLock
from typing import Any, Dict, List, Optional


class EventLogger:
    """Centralised logger for honeypot events.

    Each instance is thread‑safe and can be shared among multiple services.
    Internally an RLock protects concurrent writes to the SQLite database and
    the in‑memory cache. Services should call :meth:`log_event` whenever they
    want to record an interaction.
    """

    def __init__(self, db_path: str = "logs/honeypot.db") -> None:
        # Ensure the directory exists. Skip if no directory portion (e.g. ':memory:').
        dir_name = os.path.dirname(db_path)
        if dir_name:
            os.makedirs(dir_name, exist_ok=True)
        self.db_path = db_path
        self._conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._create_schema()
        self._lock = RLock()
        # In‑memory cache of recent events (not persisted on restart)
        self.events: List[Dict[str, Any]] = []

    def _create_schema(self) -> None:
        """Create the events table if it does not already exist."""
        cur = self._conn.cursor()
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                service TEXT NOT NULL,
                ip TEXT NOT NULL,
                port INTEGER NOT NULL,
                request_type TEXT,
                path TEXT,
                payload TEXT,
                headers TEXT,
                tool TEXT,
                classification TEXT,
                meta TEXT
            )
            """
        )
        self._conn.commit()

    def log_event(
        self,
        service: str,
        ip: str,
        port: int,
        request_type: str,
        path: Optional[str] = None,
        payload: Optional[str] = None,
        headers: Optional[Dict[str, str]] = None,
        tool: Optional[str] = None,
        classification: Optional[str] = None,
        meta: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Record a honeypot interaction.

        Parameters
        ----------
        service:
            Name of the service generating the event (e.g. 'http', 'ssh', 'ftp').
        ip:
            IP address of the remote client.
        port:
            Local port on which the service was reached.
        request_type:
            High-level type of request (e.g. GET, POST, USER, PASS).
        path:
            Request path or command (optional for SSH/FTP).
        payload:
            Raw payload or body data sent by the client.
        headers:
            Mapping of header names to values (for HTTP). Will be serialised to JSON.
        tool:
            Detected tool signature (e.g. 'nmap', 'nikto', 'sqlmap').
        classification:
            Classification of the client (e.g. 'human', 'bot', 'scanner').
        meta:
            Additional arbitrary metadata (anything JSON serialisable).
        """
        event = {
            "timestamp": datetime.utcnow().isoformat(),
            "service": service,
            "ip": ip,
            "port": port,
            "request_type": request_type,
            "path": path,
            "payload": payload,
            "headers": headers or {},
            "tool": tool,
            "classification": classification,
            "meta": meta or {},
        }
        # Append to in‑memory cache
        with self._lock:
            self.events.append(event)
            # Persist to SQLite
            cur = self._conn.cursor()
            cur.execute(
                """
                INSERT INTO events
                (timestamp, service, ip, port, request_type, path, payload, headers, tool, classification, meta)
                VALUES (:timestamp, :service, :ip, :port, :request_type, :path, :payload, :headers, :tool, :classification, :meta)
                """,
                {
                    "timestamp": event["timestamp"],
                    "service": service,
                    "ip": ip,
                    "port": port,
                    "request_type": request_type,
                    "path": path,
                    "payload": payload,
                    "headers": json.dumps(event["headers"]),
                    "tool": tool,
                    "classification": classification,
                    "meta": json.dumps(event["meta"]),
                },
            )
            self._conn.commit()

    def query_events(self, limit: int = 1000) -> List[Dict[str, Any]]:
        """Return the most recent events from the database.

        Parameters
        ----------
        limit:
            Maximum number of events to return, ordered by descending ID.
        """
        with self._lock:
            cur = self._conn.cursor()
            cur.execute(
                "SELECT * FROM events ORDER BY id DESC LIMIT ?",
                (limit,),
            )
            rows = cur.fetchall()
            results: List[Dict[str, Any]] = []
            for row in rows:
                event = dict(row)
                # Parse JSON fields
                try:
                    event["headers"] = json.loads(event["headers"]) if event.get("headers") else {}
                except Exception:
                    event["headers"] = {}
                try:
                    event["meta"] = json.loads(event["meta"]) if event.get("meta") else {}
                except Exception:
                    event["meta"] = {}
                results.append(event)
            return results

    def close(self) -> None:
        """Close the underlying SQLite connection."""
        with self._lock:
            self._conn.close()
