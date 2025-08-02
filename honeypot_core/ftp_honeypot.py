"""Async FTP/SMB honeypot service.

This module provides a trivial implementation of an FTP server using asyncio
streams. It responds to a handful of FTP commands (USER, PASS, PWD, LIST,
QUIT) and logs all interactions. Authentication always fails to prevent real
access. The server is intentionally minimal but sufficient to lure
credential-stuffing bots.
"""

from __future__ import annotations

import asyncio
from typing import Optional

from ..detectors import fingerprint
from .logger import EventLogger


class AsyncFTPHoneypot:
    def __init__(self, logger: EventLogger, port: int = 2121) -> None:
        self.logger = logger
        self.port = port

    async def start(self) -> None:
        server = await asyncio.start_server(self.handle_client, host="0.0.0.0", port=self.port)
        addr = ", ".join(str(sock.getsockname()) for sock in server.sockets)
        print(f"FTP honeypot listening on {addr}")
        async with server:
            await server.serve_forever()

    async def handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        client_ip, _ = writer.get_extra_info("peername")[:2]
        # Send greeting
        writer.write(b"220 (vsFTPd 3.0.3)\r\n")
        await writer.drain()
        username: Optional[str] = None
        while True:
            line_bytes = await reader.readline()
            if not line_bytes:
                break
            line = line_bytes.decode(errors="replace").strip()
            if not line:
                continue
            parts = line.split(" ", 1)
            cmd = parts[0].upper()
            arg = parts[1] if len(parts) > 1 else ""
            # log command
            self.logger.log_event(
                service="ftp",
                ip=client_ip,
                port=self.port,
                request_type=cmd,
                path=arg,
                payload=None,
                headers={},
                tool=fingerprint.detect_tool({}, None, None, cmd),
                classification="bot" if cmd in {"USER", "PASS", "LIST"} else "unknown",
                meta={},
            )
            # Process commands
            if cmd == "USER":
                username = arg
                writer.write(b"331 Please specify the password.\r\n")
            elif cmd == "PASS":
                writer.write(b"530 Login incorrect.\r\n")
            elif cmd == "PWD":
                writer.write(b'257 "/" is the current directory\r\n')
            elif cmd == "LIST":
                writer.write(b"150 Here comes the directory listing.\r\n")
                listing = ("-rw-r--r-- 1 root root    0 Jan 01 00:00 README.txt\r\n"
                           "drwxr-xr-x 2 root root 4096 Jan 01 00:00 data\r\n")
                writer.write(listing.encode())
                writer.write(b"226 Directory send OK.\r\n")
            elif cmd == "QUIT":
                writer.write(b"221 Goodbye.\r\n")
                await writer.drain()
                break
            else:
                writer.write(b"502 Command not implemented.\r\n")
            await writer.drain()
        writer.close()
        await writer.wait_closed()
