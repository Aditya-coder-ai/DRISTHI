"""Database Deception Service Runner.

Starts, stops, monitors, and runs simulated PostgreSQL and MySQL honeypot services.
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

from shared.config import settings
from shared.logger import get_logger
from services.database.postgres_server import PostgresServer
from services.database.mysql_server import MySQLServer
from services.database.db_event_adapter import DatabaseEventAdapter
from collector.event_collector import global_collector

logger = get_logger("DBRunner")
PID_FILE = PROJECT_ROOT / "var" / "run" / "database.pid"


def is_running() -> tuple[bool, int | None]:
    """Check if background Database honeypot process is running."""
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


def dispatch_event(raw: dict) -> None:
    """Normalize and pass event to global collector."""
    event = DatabaseEventAdapter.normalize(raw, asset_id=settings.DB_ASSET_ID)
    if event:
        global_collector.collect(event)


async def _run_async(pg_port: int, mysql_port: int, host: str) -> None:
    pg_server = PostgresServer(host=host, port=pg_port, on_event_callback=dispatch_event)
    mysql_server = MySQLServer(host=host, port=mysql_port, on_event_callback=dispatch_event)

    await pg_server.start()
    await mysql_server.start()

    logger.info("Database honeypots active: PostgreSQL on %s:%d, MySQL on %s:%d", host, pg_port, host, mysql_port)

    stop_event = asyncio.Event()

    def _sig_handler():
        logger.info("Shutdown signal received for database honeypots...")
        stop_event.set()

    loop = asyncio.get_running_loop()
    if sys.platform != "win32":
        for s in (signal.SIGINT, signal.SIGTERM):
            loop.add_signal_handler(s, _sig_handler)

    try:
        await stop_event.wait()
    except asyncio.CancelledError:
        pass
    finally:
        await pg_server.stop()
        await mysql_server.stop()


def run_foreground(
    pg_port: int = settings.DB_PG_LISTEN_PORT,
    mysql_port: int = settings.DB_MYSQL_LISTEN_PORT,
    host: str = settings.DB_PG_LISTEN_HOST,
) -> None:
    """Run database honeypots in foreground."""
    PID_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(PID_FILE, "w", encoding="utf-8") as f:
        f.write(str(os.getpid()))

    try:
        asyncio.run(_run_async(pg_port, mysql_port, host))
    except KeyboardInterrupt:
        logger.info("Database honeypot shutting down...")
    finally:
        if PID_FILE.exists():
            try:
                PID_FILE.unlink()
            except OSError:
                pass


def start_daemon(
    pg_port: int = settings.DB_PG_LISTEN_PORT,
    mysql_port: int = settings.DB_MYSQL_LISTEN_PORT,
    host: str = settings.DB_PG_LISTEN_HOST,
) -> None:
    """Start database honeypot as background process."""
    running, pid = is_running()
    if running:
        logger.warning("Database honeypot is already running with PID %d", pid)
        return

    logger.info("Starting Database honeypot daemon on %s (PG:%d, MySQL:%d)...", host, pg_port, mysql_port)
    PID_FILE.parent.mkdir(parents=True, exist_ok=True)

    cmd = [
        sys.executable,
        str(Path(__file__).resolve()),
        "run",
        "--host",
        host,
        "--pg-port",
        str(pg_port),
        "--mysql-port",
        str(mysql_port),
    ]

    log_file = PROJECT_ROOT / "var" / "log" / "database" / "daemon.log"
    log_file.parent.mkdir(parents=True, exist_ok=True)
    with open(log_file, "a", encoding="utf-8") as out:
        proc = subprocess.Popen(
            cmd,
            stdout=out,
            stderr=subprocess.STDOUT,
            cwd=str(PROJECT_ROOT),
        )

    time.sleep(1.0)
    if proc.poll() is None:
        with open(PID_FILE, "w", encoding="utf-8") as f:
            f.write(str(proc.pid))
        logger.info("Database honeypots started successfully (PID: %d)", proc.pid)
    else:
        logger.error("Failed to start database honeypots. Check %s for details.", log_file)


def stop_daemon() -> None:
    """Stop the running Database honeypot."""
    running, pid = is_running()
    if not running or pid is None:
        logger.info("Database honeypot is not running.")
        if PID_FILE.exists():
            PID_FILE.unlink()
        return

    logger.info("Stopping Database honeypot (PID %d)...", pid)
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
    logger.info("Database honeypot stopped.")


def status() -> None:
    """Display the current Database honeypot status."""
    running, pid = is_running()
    if running:
        print(f"STATUS: RUNNING (PID: {pid})")
        print(f"POSTGRESQL PORT: {settings.DB_PG_LISTEN_PORT}")
        print(f"MYSQL PORT:      {settings.DB_MYSQL_LISTEN_PORT}")
    else:
        print("STATUS: STOPPED")


def main() -> None:
    parser = argparse.ArgumentParser(description="Database Deception Service Runner (PostgreSQL & MySQL)")
    subparsers = parser.add_subparsers(dest="action", required=True)

    run_parser = subparsers.add_parser("run", help="Run database honeypots in foreground")
    run_parser.add_argument("--host", default=settings.DB_PG_LISTEN_HOST, help="Listen host")
    run_parser.add_argument("--pg-port", type=int, default=settings.DB_PG_LISTEN_PORT, help="PostgreSQL port")
    run_parser.add_argument("--mysql-port", type=int, default=settings.DB_MYSQL_LISTEN_PORT, help="MySQL port")

    start_parser = subparsers.add_parser("start", help="Start database honeypots as background daemon")
    start_parser.add_argument("--host", default=settings.DB_PG_LISTEN_HOST, help="Listen host")
    start_parser.add_argument("--pg-port", type=int, default=settings.DB_PG_LISTEN_PORT, help="PostgreSQL port")
    start_parser.add_argument("--mysql-port", type=int, default=settings.DB_MYSQL_LISTEN_PORT, help="MySQL port")

    subparsers.add_parser("stop", help="Stop running server daemon")
    subparsers.add_parser("status", help="Check server running status")

    args = parser.parse_args()

    if args.action == "run":
        run_foreground(pg_port=args.pg_port, mysql_port=args.mysql_port, host=args.host)
    elif args.action == "start":
        start_daemon(pg_port=args.pg_port, mysql_port=args.mysql_port, host=args.host)
    elif args.action == "stop":
        stop_daemon()
    elif args.action == "status":
        status()


if __name__ == "__main__":
    main()
