"""Async SSH honeypot service.

This module simulates an SSH server using asyncio streams. It does not speak
the SSH protocol; instead it sends a banner and prompts for a username and
password over plain text. All credentials are logged. After three attempts
the connection is closed.
"""

from __future__ import annotations

import asyncio
from typing import Optional

from ..detectors import fingerprint
from .logger import EventLogger


class AsyncSSHHoneypot:
    def __init__(self, logger: EventLogger, port: int = 2222) -> None:
        self.logger = logger
        self.port = port

    async def start(self) -> None:
        server = await asyncio.start_server(self.handle_client, host="0.0.0.0", port=self.port)
        addr = ", ".join(str(sock.getsockname()) for sock in server.sockets)
        print(f"SSH honeypot listening on {addr}")
        async with server:
            await server.serve_forever()

    async def handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        client_ip, client_port = writer.get_extra_info("peername")[:2]
        # send banner
        writer.write(b"SSH-2.0-OpenSSH_7.4p1 Debian-10+deb9u6\r\n")
        await writer.drain()
        attempts = 0
        while attempts < 3:
            # prompt for username
            writer.write(b"login as: ")
            await writer.drain()
            username = await self._read_line(reader)
            if username is None:
                break
            writer.write(f"{username}@server's password: ".encode())
            await writer.drain()
            password = await self._read_line(reader)
            if password is None:
                break
            attempts += 1
            # log credentials
            self.logger.log_event(
                service="ssh",
                ip=client_ip,
                port=self.port,
                request_type="LOGIN",
                path=username,
                payload=password,
                headers={"banner": "OpenSSH_7.4p1"},
                tool=fingerprint.detect_tool({}, None, None, "SSH"),
                classification="bot" if attempts > 1 else "unknown",
                meta={},
            )
            if attempts >= 3:
                writer.write(b"Permission denied (publickey,password).\r\n")
                await writer.drain()
                break
            else:
                writer.write(b"Permission denied, please try again.\r\n")
                await writer.drain()
        writer.close()
        await writer.wait_closed()

    async def _read_line(self, reader: asyncio.StreamReader) -> Optional[str]:
        try:
            line = await reader.readline()
            if not line:
                return None
            return line.strip(b"\r\n").decode(errors="replace")
        except Exception:
            return None
