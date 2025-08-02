"""
Integration tests for the adaptive honeypot services.

These tests spin up each of the asynchronous honeypot services on
ephemeral ports, drive a minimal client against them, and verify that
events are recorded by the logger.  The goal is not to exhaustively
validate every feature but to ensure that the core request/response
loop functions without requiring external dependencies such as
Twisted or Dash.  The tests run entirely on the loopback interface
within the current process and should not require network access
outside of the container.

To execute the tests simply run this module with Python:

    python test_honeypot.py

If the services bind successfully, you should see a small amount of
output summarising responses and logged events.  Any unhandled
exceptions will surface directly and cause the program to exit with
non‑zero status.
"""

from __future__ import annotations

import asyncio
import sys
from typing import List

# Add the extracted package to the import path.  We use an absolute
# path here because this script lives alongside the adaptive_honeypot
# Prepend the parent directory of the adaptive_honeypot package so that
# ``import adaptive_honeypot`` resolves correctly.  Without this the
# package's internal relative imports (``..detectors``) will fail when
# modules are imported directly.
sys.path.insert(0, '/home/oai/share/adaptive_honeypot_extracted')

from adaptive_honeypot.honeypot_core.http_honeypot import AsyncHTTPHoneypot
from adaptive_honeypot.honeypot_core.ftp_honeypot import AsyncFTPHoneypot
from adaptive_honeypot.honeypot_core.ssh_honeypot import AsyncSSHHoneypot
from adaptive_honeypot.honeypot_core.logger import EventLogger


async def run_with_timeout(coro, timeout: float):
    """Helper to run a coroutine with a timeout and cancel it on expiry."""
    task = asyncio.create_task(coro)
    try:
        return await asyncio.wait_for(task, timeout)
    except Exception:
        task.cancel()
        try:
            await task
        except Exception:
            pass
        raise


async def test_http_service(events: List[str]) -> None:
    """Start the HTTP honeypot on a high port, send a simple GET and record results."""
    logger = EventLogger(db_path=':memory:')
    port = 50800
    http = AsyncHTTPHoneypot(logger, port=port)
    # Launch the HTTP server in the background
    server_task = asyncio.create_task(http.start())
    # Give the server a moment to bind
    await asyncio.sleep(0.2)
    # Connect via loopback and send a GET request
    reader, writer = await asyncio.open_connection('127.0.0.1', port)
    request = b"GET /test HTTP/1.1\r\nHost: localhost\r\nUser-Agent: unittest\r\n\r\n"
    writer.write(request)
    await writer.drain()
    # Read the first chunk of the response
    data = await reader.read(1024)
    first_line = data.decode(errors='replace').split("\r\n")[0]
    events.append(f"HTTP response line: {first_line}")
    writer.close()
    await writer.wait_closed()
    # Cancel the server task
    server_task.cancel()
    try:
        await server_task
    except asyncio.CancelledError:
        # Suppress cancellation propagated by server shutdown
        pass
    # Record logged events
    events.append(f"HTTP events logged: {len(logger.events)}")


async def test_ssh_service(events: List[str]) -> None:
    """Start the SSH honeypot, perform login attempts and observe logging."""
    logger = EventLogger(db_path=':memory:')
    port = 50222
    ssh = AsyncSSHHoneypot(logger, port=port)
    server_task = asyncio.create_task(ssh.start())
    await asyncio.sleep(0.2)
    reader, writer = await asyncio.open_connection('127.0.0.1', port)
    # Read banner
    banner = await reader.readline()
    events.append(f"SSH banner: {banner.decode().strip()}")
    # Perform three login attempts
    for i in range(3):
        # Wait for username prompt
        try:
            prompt = await reader.readuntil(b': ')
        except Exception:
            break
        writer.write(b"user\r\n")
        await writer.drain()
        try:
            pwd_prompt = await reader.readuntil(b"word: ")
        except Exception:
            break
        writer.write(b"pass\r\n")
        await writer.drain()
        # Read rejection or close line
        line = await reader.readline()
        if not line:
            break
    # Attempt to read to confirm closure after third attempt
    data = await reader.read()
    events.append(f"SSH connection closed after login attempts: {len(data) == 0}")
    writer.close()
    await writer.wait_closed()
    server_task.cancel()
    try:
        await server_task
    except asyncio.CancelledError:
        pass
    events.append(f"SSH events logged: {len(logger.events)}")


async def test_ftp_service(events: List[str]) -> None:
    """Start the FTP honeypot, send a few commands and inspect logging."""
    logger = EventLogger(db_path=':memory:')
    port = 51212
    ftp = AsyncFTPHoneypot(logger, port=port)
    server_task = asyncio.create_task(ftp.start())
    await asyncio.sleep(0.2)
    reader, writer = await asyncio.open_connection('127.0.0.1', port)
    # Read greeting
    greeting = await reader.readline()
    events.append(f"FTP greeting: {greeting.decode().strip()}")
    # Send USER and PASS commands
    writer.write(b"USER test\r\n")
    await writer.drain()
    resp_user = await reader.readline()
    writer.write(b"PASS test\r\n")
    await writer.drain()
    resp_pass = await reader.readline()
    # Send PWD and LIST
    writer.write(b"PWD\r\n")
    await writer.drain()
    resp_pwd = await reader.readline()
    writer.write(b"LIST\r\n")
    await writer.drain()
    # Read multi‑line LIST response until final 226 line
    while True:
        line = await reader.readline()
        if not line:
            break
        if line.startswith(b"226"):
            break
    # Quit
    writer.write(b"QUIT\r\n")
    await writer.drain()
    goodbye = await reader.readline()
    events.append(f"FTP goodbye: {goodbye.decode().strip()}")
    writer.close()
    await writer.wait_closed()
    server_task.cancel()
    try:
        await server_task
    except asyncio.CancelledError:
        pass
    events.append(f"FTP events logged: {len(logger.events)}")


async def main() -> None:
    events: List[str] = []
    await test_http_service(events)
    await test_ssh_service(events)
    await test_ftp_service(events)
    # Print summary of test results
    print("\nTest summary:")
    for ev in events:
        print(ev)


if __name__ == '__main__':
    asyncio.run(main())
