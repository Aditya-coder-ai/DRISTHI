"""Cowrie SSH Deception Service Runner.

Starts, stops, monitors, and executes the Cowrie SSH honeypot with custom
configurations (hostname: finance-server, honeyfs, userdb, JSON logging).
"""

from __future__ import annotations

import argparse
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

logger = get_logger("SSHRunner")

SSH_DIR = PROJECT_ROOT / "services" / "ssh"
CONFIG_FILE = SSH_DIR / "config" / "cowrie.cfg"
USERDB_FILE = SSH_DIR / "config" / "userdb.txt"
HONEYFS_DIR = SSH_DIR / "honeyfs"
LOG_DIR = PROJECT_ROOT / "var" / "log" / "cowrie"
PID_FILE = PROJECT_ROOT / "var" / "run" / "cowrie.pid"


def prepare_environment(port: int = settings.SSH_LISTEN_PORT, host: str = settings.SSH_LISTEN_HOST) -> dict[str, str]:
    """Ensure required directories exist and return environment variables."""
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    PID_FILE.parent.mkdir(parents=True, exist_ok=True)
    (PROJECT_ROOT / "var" / "lib" / "cowrie").mkdir(parents=True, exist_ok=True)
    (PROJECT_ROOT / "var" / "lib" / "cowrie" / "downloads").mkdir(parents=True, exist_ok=True)
    (PROJECT_ROOT / "var" / "lib" / "cowrie" / "tty").mkdir(parents=True, exist_ok=True)

    # Touch cowrie.json if it doesn't exist
    json_log = LOG_DIR / "cowrie.json"
    if not json_log.exists():
        json_log.touch()

    # Ensure root cowrie.cfg exists and matches configuration
    root_cfg = PROJECT_ROOT / "cowrie.cfg"
    if not root_cfg.exists() and CONFIG_FILE.exists():
        root_cfg.write_text(CONFIG_FILE.read_text(encoding="utf-8"), encoding="utf-8")

    env = os.environ.copy()
    env["PYTHONPATH"] = str(PROJECT_ROOT)
    env["COWRIE_HONEYPOT_HOSTNAME"] = settings.SSH_HOSTNAME
    env["COWRIE_HONEYPOT_CONTENTS_PATH"] = str(HONEYFS_DIR)
    env["COWRIE_HONEYPOT_ETC_PATH"] = str(SSH_DIR / "config")
    env["COWRIE_SHELL_FILESYSTEM"] = str(SSH_DIR / "fs.pickle")
    env["COWRIE_SSH_LISTEN_ENDPOINTS"] = f"tcp:{port}:interface={host}"
    env["COWRIE_SSH_ENABLED"] = "true"
    env["COWRIE_TELNET_ENABLED"] = "false"
    env["COWRIE_OUTPUT_JSONLOG_ENABLED"] = "true"
    env["COWRIE_OUTPUT_JSONLOG_LOGFILE"] = str(json_log)

    # Mutate os.environ in current process
    for k, v in env.items():
        os.environ[k] = v

    return env


def run_cowrie_foreground(port: int = settings.SSH_LISTEN_PORT, host: str = settings.SSH_LISTEN_HOST) -> None:
    """Run Cowrie in foreground using Twisted."""
    logger.info("Initializing Cowrie SSH honeypot on %s:%d (hostname=%s)...", host, port, settings.SSH_HOSTNAME)
    prepare_environment(port, host)

    # Write current PID
    with open(PID_FILE, "w", encoding="utf-8") as f:
        f.write(str(os.getpid()))

    try:
        from twisted.internet import reactor
        from twisted.application import service
        import twisted.plugins.cowrie_plugin as cp

        sm = cp.CowrieServiceMaker()
        top_service = sm.makeService({"help": False})
        top_service.startService()
        logger.info("Cowrie SSH Honeypot listening on %s:%d. Press Ctrl+C to exit.", host, port)
        reactor.run()
    except KeyboardInterrupt:
        logger.info("Shutting down Cowrie SSH service...")
    except Exception as exc:
        logger.error("Error running Cowrie SSH service: %s", exc)
        raise
    finally:
        if PID_FILE.exists():
            try:
                PID_FILE.unlink()
            except OSError:
                pass


def is_running() -> tuple[bool, int | None]:
    """Check if Cowrie background process is currently running."""
    if not PID_FILE.exists():
        return False, None

    try:
        pid = int(PID_FILE.read_text(encoding="utf-8").strip())
    except (ValueError, OSError):
        return False, None

    # Check process existence
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


def start_daemon(port: int = settings.SSH_LISTEN_PORT, host: str = settings.SSH_LISTEN_HOST) -> None:
    """Start Cowrie as a background daemon process."""
    running, pid = is_running()
    if running:
        logger.warning("Cowrie SSH honeypot is already running with PID %d", pid)
        return

    logger.info("Starting Cowrie SSH honeypot daemon on %s:%d...", host, port)
    env = prepare_environment(port, host)

    # Launch subprocess with the same python interpreter
    cmd = [
        sys.executable,
        str(Path(__file__).resolve()),
        "run",
        "--port",
        str(port),
        "--host",
        host,
    ]

    proc = subprocess.Popen(
        cmd,
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if sys.platform == "win32" else 0,
    )

    # Write PID
    with open(PID_FILE, "w", encoding="utf-8") as f:
        f.write(str(proc.pid))

    time.sleep(2)
    running, pid = is_running()
    if running:
        logger.info("Cowrie SSH honeypot successfully started (PID: %d)", pid)
    else:
        logger.error("Cowrie failed to start. Check logs in %s", LOG_DIR)


def stop_daemon() -> None:
    """Stop the background Cowrie daemon."""
    running, pid = is_running()
    if not running:
        logger.info("Cowrie SSH honeypot is not running.")
        if PID_FILE.exists():
            PID_FILE.unlink()
        return

    logger.info("Stopping Cowrie SSH honeypot (PID: %d)...", pid)
    try:
        if sys.platform == "win32":
            subprocess.run(["taskkill", "/F", "/PID", str(pid)], check=False, stdout=subprocess.DEVNULL)
        else:
            os.kill(pid, signal.SIGTERM)
    except Exception as exc:
        logger.error("Error stopping Cowrie process: %s", exc)

    if PID_FILE.exists():
        try:
            PID_FILE.unlink()
        except OSError:
            pass
    logger.info("Cowrie SSH honeypot stopped.")


def status() -> None:
    """Display Cowrie SSH status."""
    running, pid = is_running()
    if running:
        print(f"Status: RUNNING (PID: {pid})")
        print(f"Hostname: {settings.SSH_HOSTNAME}")
        print(f"Endpoint: {settings.SSH_LISTEN_HOST}:{settings.SSH_LISTEN_PORT}")
        print(f"JSON Log: {LOG_DIR / 'cowrie.json'}")
    else:
        print("Status: STOPPED")


def main() -> None:
    parser = argparse.ArgumentParser(description="Cowrie SSH Deception Service Manager")
    parser.add_argument(
        "action",
        choices=["run", "start", "stop", "restart", "status"],
        help="Action to perform",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=settings.SSH_LISTEN_PORT,
        help=f"Port to listen on (default: {settings.SSH_LISTEN_PORT})",
    )
    parser.add_argument(
        "--host",
        type=str,
        default=settings.SSH_LISTEN_HOST,
        help=f"Host interface to bind to (default: {settings.SSH_LISTEN_HOST})",
    )

    args = parser.parse_args()

    if args.action == "run":
        run_cowrie_foreground(args.port, args.host)
    elif args.action == "start":
        start_daemon(args.port, args.host)
    elif args.action == "stop":
        stop_daemon()
    elif args.action == "restart":
        stop_daemon()
        time.sleep(1)
        start_daemon(args.port, args.host)
    elif args.action == "status":
        status()


if __name__ == "__main__":
    main()
