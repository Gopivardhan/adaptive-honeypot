"""Honeypot service orchestrator.

This module provides a function to launch all asynchronous honeypot services
(HTTP, SSH and FTP) and run them concurrently using asyncio. Each service
shares the same :class:`EventLogger` instance so that events are written to
the same SQLite database. The services run until terminated.
"""

from __future__ import annotations

import asyncio
from typing import Optional

from .ftp_honeypot import AsyncFTPHoneypot
from .http_honeypot import AsyncHTTPHoneypot
from .logger import EventLogger
from .ssh_honeypot import AsyncSSHHoneypot


async def run_all_async(
    http_port: int = 8080,
    ssh_port: int = 2222,
    ftp_port: int = 2121,
    db_path: str = "logs/honeypot.db",
) -> None:
    """Asynchronously start all honeypot services.

    The coroutine never returns; it waits for all tasks to complete (which
    happens only on cancellation or an exception). Press Ctrl+C in the
    terminal to stop the services.
    """
    logger = EventLogger(db_path=db_path)
    http_service = AsyncHTTPHoneypot(logger, port=http_port)
    ssh_service = AsyncSSHHoneypot(logger, port=ssh_port)
    ftp_service = AsyncFTPHoneypot(logger, port=ftp_port)
    # Start all servers concurrently
    await asyncio.gather(
        http_service.start(),
        ssh_service.start(),
        ftp_service.start(),
    )


def run_all(
    http_port: int = 8080,
    ssh_port: int = 2222,
    ftp_port: int = 2121,
    db_path: str = "logs/honeypot.db",
) -> None:
    """Blocking entry point to start all services.

    Launches the asyncio event loop and runs the asynchronous server start
    coroutine. Any unhandled exceptions will propagate out of this function.
    """
    try:
        asyncio.run(run_all_async(http_port, ssh_port, ftp_port, db_path))
    except KeyboardInterrupt:
        print("Honeypot shutting down...")


if __name__ == "__main__":
    run_all()
