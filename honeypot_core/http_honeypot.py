"""Async HTTP honeypot service.

This module implements a simple HTTP server using asyncio streams. It listens
for TCP connections, parses minimal HTTP requests and returns synthetic
responses. It mimics common behaviours of real servers by randomising headers
and injecting decoy vulnerabilities based on detected scanner behaviour.

Because we do not depend on external packages, the server only supports a
subset of HTTP/1.0/1.1 (GET and POST with Content-Length). It is adequate
for collecting recon data from scanners such as `nikto`, `sqlmap` and `nmap`.
"""

from __future__ import annotations

import asyncio
import random
from typing import Dict, Optional, Tuple

from ..detectors import fingerprint
from .logger import EventLogger


class AsyncHTTPHoneypot:
    """Asynchronous HTTP honeypot.

    Parameters
    ----------
    logger:
        Shared EventLogger instance.
    port:
        Port to bind the server.
    """

    def __init__(self, logger: EventLogger, port: int = 8080) -> None:
        self.logger = logger
        self.port = port
        # History of events per IP for classification
        self.history: Dict[str, list] = {}

    async def start(self) -> None:
        server = await asyncio.start_server(self.handle_client, host="0.0.0.0", port=self.port)
        # Print info for operator
        addr = ", ".join(str(sock.getsockname()) for sock in server.sockets)
        print(f"HTTP honeypot listening on {addr}")
        async with server:
            await server.serve_forever()

    async def handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        client_ip, client_port = writer.get_extra_info("peername")[:2]
        try:
            request_data = await self._read_http_request(reader)
            if request_data is None:
                writer.close()
                await writer.wait_closed()
                return
            method, path, headers, body = request_data
            detected_tool = fingerprint.detect_tool(headers, body, path, method)
            # Update history and classify
            from datetime import datetime
            ts = datetime.utcnow().isoformat()
            hist = self.history.setdefault(client_ip, [])
            hist.append({"timestamp": ts})
            classification = fingerprint.classify_client(hist, detected_tool)
            # Generate response body
            response_body = self._generate_response_body(path, detected_tool)
            # Log event
            self.logger.log_event(
                service="http",
                ip=client_ip,
                port=self.port,
                request_type=method,
                path=path,
                payload=body,
                headers=headers,
                tool=detected_tool,
                classification=classification,
                meta={},
            )
            # Send response
            await self._send_response(writer, response_body, headers)
        except Exception as exc:
            # Ignore malformed requests
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    async def _read_http_request(
        self, reader: asyncio.StreamReader
    ) -> Optional[Tuple[str, str, Dict[str, str], Optional[str]]]:
        """Parse an HTTP request from the stream.

        Returns (method, path, headers, body) or None if the request could not
        be parsed (e.g. connection closed prematurely).
        """
        # Read request line
        line = await reader.readline()
        if not line:
            return None
        try:
            request_line = line.decode().strip()
            parts = request_line.split()
            if len(parts) < 2:
                return None
            method, path = parts[0], parts[1]
        except Exception:
            return None
        # Read headers
        headers: Dict[str, str] = {}
        while True:
            header_line = await reader.readline()
            if not header_line:
                break
            header_str = header_line.decode(errors="replace").strip()
            if header_str == "":
                break  # End of headers
            if ":" in header_str:
                key, value = header_str.split(":", 1)
                headers[key.strip()] = value.strip()
        # Read body if Content-Length present
        body: Optional[str] = None
        content_length = headers.get("Content-Length")
        if content_length:
            try:
                length = int(content_length)
                body_bytes = await reader.readexactly(length)
                body = body_bytes.decode(errors="replace")
            except Exception:
                body = None
        return method, path, headers, body

    async def _send_response(self, writer: asyncio.StreamWriter, body: str, request_headers: Dict[str, str]) -> None:
        server_header = self._random_server_header()
        powered_by = random.choice([
            "PHP/7.3.11", "ASP.NET", "Express", "Django", "Werkzeug/2.0.1", "Node.js"
        ])
        response = (
            "HTTP/1.1 200 OK\r\n"
            f"Server: {server_header}\r\n"
            f"X-Powered-By: {powered_by}\r\n"
            "Content-Type: text/html; charset=utf-8\r\n"
            f"Content-Length: {len(body.encode())}\r\n"
            "Connection: close\r\n"
            "\r\n"
            f"{body}"
        )
        writer.write(response.encode())
        await writer.drain()
        writer.close()
        await writer.wait_closed()

    def _random_server_header(self) -> str:
        return random.choice([
            "Apache/2.4.29 (Ubuntu)",
            "nginx/1.14.0 (Ubuntu)",
            "lighttpd/1.4.45",
            "Microsoft-IIS/10.0",
            "gunicorn/20.1.0",
            "AmazonS3",
        ])

    def _generate_response_body(self, path: str, detected_tool: Optional[str]) -> str:
        lower = path.lower()
        # Specific decoy pages
        if "wp-login" in lower or "wp-admin" in lower:
            return (
                "<html><body><h1>WordPress Login</h1>"
                "<form><label>Username</label><input type='text' name='log' />"
                "<label>Password</label><input type='password' name='pwd' />"
                "<input type='submit' value='Log In' /></form>"
                "</body></html>"
            )
        if "phpmyadmin" in lower:
            return (
                "<html><body><h1>phpMyAdmin</h1>"
                "<form><label>Username</label><input type='text' name='pma_username' />"
                "<label>Password</label><input type='password' name='pma_password' />"
                "<input type='submit' value='Go' /></form>"
                "</body></html>"
            )
        if lower.endswith("/.env"):
            return "APP_KEY=base64:psJxQ0ZkVJ9K8lkz2YoKZm\nDB_PASSWORD=secret"
        if lower.endswith("config.php") or lower.endswith("config.inc.php"):
            return "<?php\n$db_host='localhost';\n$db_user='root';\n$db_pass='password';\n?>"
        # Tool-specific injections
        if detected_tool == "sqlmap":
            return (
                "<html><body><h1>Products</h1><p>Product ID: 1</p><p>Name: Widget</p>"
                "<form action='' method='post'><input name='id' /><input type='submit' value='Submit' /></form>"
                "<!-- SQL Injection hint -->"
                "</body></html>"
            )
        if detected_tool == "nikto":
            return (
                "<html><body><h1>Administration</h1><p>This area is restricted.</p>"
                "<a href='/admin.php'>Admin</a>"
                "</body></html>"
            )
        if detected_tool == "nmap":
            return "<html><body><h1>Welcome</h1><p>Hello there!</p></body></html>"
        # Generic responses
        messages = [
            "<h1>Welcome to our site!</h1><p>Under construction...</p>",
            "<h1>Shop</h1><p>Out of stock.</p>",
            "<h1>Blog</h1><p>No posts yet.</p>",
            "<h1>404 Not Found</h1><p>The requested resource could not be found.</p>",
        ]
        return f"<html><body>{random.choice(messages)}</body></html>"
