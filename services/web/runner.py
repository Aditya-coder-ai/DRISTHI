"""Web Admin Portal Deception Service Runner.

Starts, stops, monitors, and runs the Apex Web Admin honeypot service via Uvicorn.
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
import time
from pathlib import Path

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import uvicorn
from shared.config import settings
from shared.logger import get_logger

logger = get_logger("WebRunner")

PID_FILE = PROJECT_ROOT / "var" / "run" / "web.pid"


def is_running() -> tuple[bool, int | None]:
    """Check if background Web process is running."""
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


def run_foreground(host: str = settings.WEB_LISTEN_HOST, port: int = settings.WEB_LISTEN_PORT) -> None:
    """Run Web Admin portal in foreground using Uvicorn."""
    PID_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(PID_FILE, "w", encoding="utf-8") as f:
        f.write(str(os.getpid()))

    logger.info("Starting Web Admin Deception Portal on %s:%d (PID %d)...", host, port, os.getpid())
    try:
        uvicorn.run(
            "services.web.app:app",
            host=host,
            port=port,
            log_level=settings.LOG_LEVEL.lower(),
            access_log=False,
        )
    except KeyboardInterrupt:
        logger.info("Web portal shutting down...")
    finally:
        if PID_FILE.exists():
            try:
                PID_FILE.unlink()
            except OSError:
                pass


def start_daemon(host: str = settings.WEB_LISTEN_HOST, port: int = settings.WEB_LISTEN_PORT) -> None:
    """Start Web Admin portal as background process."""
    running, pid = is_running()
    if running:
        logger.warning("Web Admin honeypot is already running with PID %d", pid)
        return

    logger.info("Starting Web Admin honeypot daemon on %s:%d...", host, port)
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

    log_file = PROJECT_ROOT / "var" / "log" / "web" / "uvicorn_daemon.log"
    log_file.parent.mkdir(parents=True, exist_ok=True)
    with open(log_file, "a", encoding="utf-8") as out:
        proc = subprocess.Popen(
            cmd,
            stdout=out,
            stderr=subprocess.STDOUT,
            cwd=str(PROJECT_ROOT),
        )

    # Wait briefly and verify PID
    time.sleep(1.0)
    if proc.poll() is None:
        with open(PID_FILE, "w", encoding="utf-8") as f:
            f.write(str(proc.pid))
        logger.info("Web Admin portal started successfully (PID: %d)", proc.pid)
    else:
        logger.error("Failed to start Web Admin portal. Check %s for details.", log_file)


def stop_daemon() -> None:
    """Stop the running Web Admin honeypot."""
    running, pid = is_running()
    if not running or pid is None:
        logger.info("Web Admin honeypot is not running.")
        if PID_FILE.exists():
            PID_FILE.unlink()
        return

    logger.info("Stopping Web Admin portal (PID %d)...", pid)
    if sys.platform == "win32":
        try:
            subprocess.run(["taskkill", "/F", "/T", "/PID", str(pid)], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception as exc:
            logger.warning("Failed to kill process %d: %s", pid, exc)
    else:
        try:
            os.kill(pid, 15)
            time.sleep(1.0)
            if is_running()[0]:
                os.kill(pid, 9)
        except OSError:
            pass

    if PID_FILE.exists():
        try:
            PID_FILE.unlink()
        except OSError:
            pass
    logger.info("Web Admin portal stopped.")


def status() -> None:
    """Display the current Web Admin portal status."""
    running, pid = is_running()
    if running:
        print(f"STATUS: RUNNING (PID: {pid})")
        print(f"URL:    http://{settings.WEB_LISTEN_HOST}:{settings.WEB_LISTEN_PORT}/login")
    else:
        print("STATUS: STOPPED")


def main() -> None:
    parser = argparse.ArgumentParser(description="Apex Web Admin Deception Service Runner")
    subparsers = parser.add_subparsers(dest="action", required=True)

    run_parser = subparsers.add_parser("run", help="Run server in foreground")
    run_parser.add_argument("--host", default=settings.WEB_LISTEN_HOST, help="Listen host")
    run_parser.add_argument("--port", type=int, default=settings.WEB_LISTEN_PORT, help="Listen port")

    start_parser = subparsers.add_parser("start", help="Start server as background daemon")
    start_parser.add_argument("--host", default=settings.WEB_LISTEN_HOST, help="Listen host")
    start_parser.add_argument("--port", type=int, default=settings.WEB_LISTEN_PORT, help="Listen port")

    subparsers.add_parser("stop", help="Stop running server daemon")
    subparsers.add_parser("status", help="Check server running status")

    args = parser.parse_args()

    if args.action == "run":
        run_foreground(host=args.host, port=args.port)
    elif args.action == "start":
        start_daemon(host=args.host, port=args.port)
    elif args.action == "stop":
        stop_daemon()
    elif args.action == "status":
        status()


if __name__ == "__main__":
    main()
