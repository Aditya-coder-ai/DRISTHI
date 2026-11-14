"""Central Event Forwarding Daemon.

Continuously aggregates security telemetry across all deception assets (SSH, FTP, Web, DB, Canaries),
batches events, transmits them to Person 2's Central Backend API, and manages offline recovery via RetryQueue.
"""

from __future__ import annotations

import argparse
import json
import os
import signal
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from collector.event_collector import global_collector
from collector.forwarder import EventForwarder
from collector.retry_queue import RetryQueue
from shared.config import settings
from shared.logger import get_logger

logger = get_logger("CollectorDaemon")

PID_FILE = settings.DAEMON_PID_FILE
HEALTH_FILE = PROJECT_ROOT / "var" / "run" / "collector_health.json"


class CollectorDaemon:
    """Manages continuous event batching, forwarding, and health metrics."""

    def __init__(
        self,
        forwarder: Optional[EventForwarder] = None,
        retry_queue: Optional[RetryQueue] = None,
        flush_interval: Optional[float] = None,
    ):
        self.retry_queue = retry_queue or RetryQueue()
        self.forwarder = forwarder or EventForwarder(retry_queue=self.retry_queue)
        self.flush_interval = flush_interval or settings.DAEMON_FLUSH_INTERVAL
        self._running = False
        self.start_time = time.time()
        self.last_delivery_time: Optional[str] = None
        self.total_delivered = 0
        self.failed_deliveries = 0

    def update_health_file(self) -> None:
        """Write runtime operational health stats to JSON file."""
        try:
            HEALTH_FILE.parent.mkdir(parents=True, exist_ok=True)
            stats = self.get_stats()
            with open(HEALTH_FILE, "w", encoding="utf-8") as f:
                json.dump(stats, f, indent=2)
        except Exception as exc:
            logger.debug("Failed updating health file: %s", exc)

    def get_stats(self) -> Dict[str, Any]:
        """Return operational health metrics."""
        pending = self.retry_queue.count(status="PENDING")
        dead_letter = self.retry_queue.count(status="DEAD_LETTER")
        uptime = round(time.time() - self.start_time, 1) if self._running else 0

        status = "HEALTHY"
        if dead_letter > 0 or self.failed_deliveries > 5:
            status = "DEGRADED"

        return {
            "status": status,
            "running": self._running,
            "uptime_seconds": uptime,
            "last_successful_delivery": self.last_delivery_time,
            "total_delivered": self.total_delivered,
            "failed_delivery_count": self.failed_deliveries,
            "pending_event_count": pending,
            "dead_letter_count": dead_letter,
            "backend_url": self.forwarder.api_url,
            "updated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        }

    def process_cycle(self) -> int:
        """Single processing cycle: drain collector into retry queue and flush queue."""
        # Drain events from in-memory collector to retry queue
        new_events = global_collector.get_all()
        for evt in new_events:
            self.retry_queue.enqueue(evt)
        if new_events:
            global_collector.clear()

        # Flush retry queue to backend
        flushed = self.forwarder.flush_retry_queue()
        if flushed > 0:
            self.total_delivered += flushed
            self.last_delivery_time = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            self.failed_deliveries = 0
        elif self.retry_queue.count() > 0:
            self.failed_deliveries += 1

        self.update_health_file()
        return flushed

    def run_loop(self) -> None:
        """Run continuous daemon worker loop."""
        self._running = True
        self.start_time = time.time()
        logger.info("Collector daemon loop started (flush_interval=%.1fs)", self.flush_interval)

        try:
            while self._running:
                self.process_cycle()
                time.sleep(self.flush_interval)
        except KeyboardInterrupt:
            logger.info("Collector daemon loop interrupted.")
        finally:
            self._running = False
            self.update_health_file()
            logger.info("Collector daemon loop stopped.")


def is_running() -> tuple[bool, int | None]:
    """Check if background daemon process is alive."""
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


def run_foreground(interval: float = settings.DAEMON_FLUSH_INTERVAL) -> None:
    """Run daemon in foreground."""
    PID_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(PID_FILE, "w", encoding="utf-8") as f:
        f.write(str(os.getpid()))

    daemon = CollectorDaemon(flush_interval=interval)
    try:
        daemon.run_loop()
    finally:
        if PID_FILE.exists():
            try:
                PID_FILE.unlink()
            except OSError:
                pass


def start_daemon(interval: float = settings.DAEMON_FLUSH_INTERVAL) -> None:
    """Start daemon in background."""
    running, pid = is_running()
    if running:
        logger.warning("Collector daemon is already running with PID %d", pid)
        return

    logger.info("Starting collector daemon in background...")
    PID_FILE.parent.mkdir(parents=True, exist_ok=True)

    cmd = [
        sys.executable,
        str(Path(__file__).resolve()),
        "run",
        "--interval",
        str(interval),
    ]

    log_file = PROJECT_ROOT / "var" / "log" / "collector" / "daemon.log"
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
        logger.info("Collector daemon started (PID: %d)", proc.pid)
    else:
        logger.error("Failed to start collector daemon. Check %s for details.", log_file)


def stop_daemon() -> None:
    """Stop running daemon."""
    running, pid = is_running()
    if not running or pid is None:
        logger.info("Collector daemon is not running.")
        if PID_FILE.exists():
            PID_FILE.unlink()
        return

    logger.info("Stopping collector daemon (PID %d)...", pid)
    if sys.platform == "win32":
        try:
            subprocess.run(["taskkill", "/F", "/T", "/PID", str(pid)], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception:
            pass
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
    logger.info("Collector daemon stopped.")


def show_health() -> None:
    """Print health check statistics."""
    running, pid = is_running()
    print("========================================")
    print(" Central Event Collector Daemon Health  ")
    print("========================================")
    print(f"Process Status: {'RUNNING (PID ' + str(pid) + ')' if running else 'STOPPED'}")

    daemon = CollectorDaemon()
    stats = daemon.get_stats()
    if HEALTH_FILE.exists():
        try:
            with open(HEALTH_FILE, "r", encoding="utf-8") as f:
                stats = json.load(f)
        except Exception:
            pass

    for k, v in stats.items():
        print(f"  {k:<28}: {v}")
    print("========================================")


def main() -> None:
    parser = argparse.ArgumentParser(description="Central Event Collector Forwarding Daemon")
    subparsers = parser.add_subparsers(dest="action", required=True)

    run_p = subparsers.add_parser("run", help="Run daemon in foreground")
    run_p.add_argument("--interval", type=float, default=settings.DAEMON_FLUSH_INTERVAL, help="Flush interval in seconds")

    start_p = subparsers.add_parser("start", help="Start daemon in background")
    start_p.add_argument("--interval", type=float, default=settings.DAEMON_FLUSH_INTERVAL, help="Flush interval in seconds")

    subparsers.add_parser("stop", help="Stop daemon")
    subparsers.add_parser("restart", help="Restart daemon")
    subparsers.add_parser("health", help="Display daemon health check")
    subparsers.add_parser("status", help="Display status")
    subparsers.add_parser("flush", help="Trigger single flush cycle")

    args = parser.parse_args()

    if args.action == "run":
        run_foreground(args.interval)
    elif args.action == "start":
        start_daemon(args.interval)
    elif args.action == "stop":
        stop_daemon()
    elif args.action == "restart":
        stop_daemon()
        time.sleep(1.0)
        start_daemon()
    elif args.action in ("health", "status"):
        show_health()
    elif args.action == "flush":
        d = CollectorDaemon()
        count = d.process_cycle()
        print(f"Flushed {count} events.")


if __name__ == "__main__":
    main()

