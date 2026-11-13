"""FTP Deception Service Runner.

Starts, stops, monitors, and runs the isolated FTP honeypot service.
"""

from __future__ import annotations

import argparse
import asyncio
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from services.ftp.server import FTPServer
from shared.config import settings
from shared.logger import get_logger

logger = get_logger("FTPRunner")

PID_FILE = PROJECT_ROOT / "var" / "run" / "ftp.pid"


def is_running() -> tuple[bool, int | None]:
    """Check if background FTP process is running."""
    if not PID_FILE.exists():
        return False, None

    try:
        pid = int(PID_FILE.read_text(encoding="utf-8").strip())
    except (ValueError, OSError):
        return False, None

    if sys.platform == "win32":
        try:
            output = subprocess.check_output(
                ["tasklist", "/FI", f"PID eq {pid}", "/FO", "CSV", "/NH"],
                text=True,
                stderr=subprocess.DEVNULL,
            )
            if str(pid) in output:
                return True, pid
        except Exception:
            return False, pid
    else:
        try:
            os.kill(pid, 0)
            return True, pid
        except OSError:
            return False, pid

    return False, pid


def run_foreground(host: str = settings.FTP_LISTEN_HOST, port: int = settings.FTP_LISTEN_PORT) -> None:
    """Run FTP server in foreground."""
    PID_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(PID_FILE, "w", encoding="utf-8") as f:
        f.write(str(os.getpid()))

    server = FTPServer(host=host, port=port)
    try:
        asyncio.run(server.serve_forever())
    except KeyboardInterrupt:
        logger.info("FTP server shutting down...")
    finally:
        if PID_FILE.exists():
            try:
                PID_FILE.unlink()
            except OSError:
                pass


def start_daemon(host: str = settings.FTP_LISTEN_HOST, port: int = settings.FTP_LISTEN_PORT) -> None:
    """Start FTP server as background daemon process."""
    running, pid = is_running()
    if running:
        logger.warning("FTP honeypot is already running with PID %d", pid)
        return

    logger.info("Starting FTP honeypot daemon on %s:%d...", host, port)
    PID_FILE.parent.mkdir(parents=True, exist_ok=True)

    cmd = [
        sys.executable,
        str(Path(__file__).resolve()),
        "run",
        "--host",
        host,
        "--port",
        str(port),
    ]

    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if sys.platform == "win32" else 0,
    )

    with open(PID_FILE, "w", encoding="utf-8") as f:
        f.write(str(proc.pid))

    time.sleep(1.5)
    running, pid = is_running()
    if running:
        logger.info("FTP honeypot daemon successfully started (PID: %d)", pid)
    else:
        logger.error("FTP honeypot failed to start.")


def stop_daemon() -> None:
    """Stop the running background FTP daemon."""
    running, pid = is_running()
    if not running:
        logger.info("FTP honeypot is not running.")
        if PID_FILE.exists():
            PID_FILE.unlink()
        return

    logger.info("Stopping FTP honeypot (PID: %d)...", pid)
    try:
        if sys.platform == "win32":
            subprocess.run(["taskkill", "/F", "/PID", str(pid)], check=False, stdout=subprocess.DEVNULL)
        else:
            os.kill(pid, signal.SIGTERM)
    except Exception as exc:
        logger.error("Error stopping FTP process: %s", exc)

    if PID_FILE.exists():
        try:
            PID_FILE.unlink()
        except OSError:
            pass
    logger.info("FTP honeypot stopped.")


def status() -> None:
    """Display FTP server status."""
    running, pid = is_running()
    if running:
        print(f"Status: RUNNING (PID: {pid})")
        print(f"Asset ID: {settings.FTP_ASSET_ID}")
        print(f"Endpoint: {settings.FTP_LISTEN_HOST}:{settings.FTP_LISTEN_PORT}")
        print(f"Decoy Root: {settings.FTP_DECOY_DIR}")
        print(f"JSON Log: {settings.FTP_JSON_LOG}")
    else:
        print("Status: STOPPED")


def main() -> None:
    parser = argparse.ArgumentParser(description="FTP Deception Service Manager")
    parser.add_argument("action", choices=["run", "start", "stop", "restart", "status"], help="Action to perform")
    parser.add_argument("--host", default=settings.FTP_LISTEN_HOST, help="Host interface to bind")
    parser.add_argument("--port", type=int, default=settings.FTP_LISTEN_PORT, help="Port to listen on")

    args = parser.parse_args()

    if args.action == "run":
        run_foreground(args.host, args.port)
    elif args.action == "start":
        start_daemon(args.host, args.port)
    elif args.action == "stop":
        stop_daemon()
    elif args.action == "restart":
        stop_daemon()
        time.sleep(1)
        start_daemon(args.host, args.port)
    elif args.action == "status":
        status()


if __name__ == "__main__":
    main()
