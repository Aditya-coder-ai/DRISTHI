"""Simulated Attacker Interaction Script for SSH Honeypot.

Simulates an adversary interacting with the fake SSH server:
1. Attempting unauthorized login (brute-force failure).
2. Authenticating with discovered bait credentials (finance_admin).
3. Conducting situational awareness and reconnaissance commands in interactive shell.
4. Accessing decoy financial data and lateral movement notes.
5. Verifying generated structured security events.
"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path

# Add project root to path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import paramiko
from collector.normalizer import EventNormalizer
from shared.config import settings
from shared.logger import get_logger

logger = get_logger("SSHAttackSimulator")


def test_failed_authentication(host: str, port: int, user: str = "unauthorized_admin", pwd: str = "WrongPassword123!") -> bool:
    """Simulate an attacker attempting failed credentials."""
    logger.info("Simulating failed login attempt: %s / %s...", user, "*" * len(pwd))
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(
            hostname=host,
            port=port,
            username=user,
            password=pwd,
            timeout=5,
            allow_agent=False,
            look_for_keys=False,
        )
        client.close()
        logger.warning("Unexpected: Failed authentication attempt was accepted.")
        return False
    except paramiko.AuthenticationException:
        logger.info("Expected: Authentication failed for %s.", user)
        return True
    except Exception as exc:
        logger.error("Connection error during failed auth test: %s", exc)
        return False


def test_successful_interaction(host: str, port: int, user: str = "finance_admin", pwd: str = "Finance@2026") -> str:
    """Simulate attacker logging in with bait credentials and executing commands in an interactive shell."""
    logger.info("Simulating authentication with bait credentials: %s...", user)
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    captured_terminal_output = ""

    try:
        client.connect(
            hostname=host,
            port=port,
            username=user,
            password=pwd,
            timeout=10,
            allow_agent=False,
            look_for_keys=False,
        )
        logger.info("Authenticated successfully to decoy server as %s!", user)

        chan = client.invoke_shell()
        time.sleep(1)

        # Read banner
        if chan.recv_ready():
            banner = chan.recv(4096).decode("utf-8", errors="replace")
            captured_terminal_output += banner

        # Recon commands
        commands = [
            "whoami",
            "hostname",
            "uname -a",
            "cat /etc/hosts",
            "cat /home/finance_admin/server_notes.txt",
            "cat /var/financial_data/Q4_payroll_summary.csv",
            "exit",
        ]

        for cmd in commands:
            logger.info("Adversary sending command: %s", cmd)
            chan.send(cmd + "\n")
            time.sleep(0.7)
            while chan.recv_ready():
                chunk = chan.recv(4096).decode("utf-8", errors="replace")
                captured_terminal_output += chunk

        chan.close()
        client.close()
        logger.info("Attacker session closed.")
    except Exception as exc:
        logger.error("Error during authenticated interaction: %s", exc)
        raise

    return captured_terminal_output


def parse_and_display_events(json_log_path: Path) -> int:
    """Read Cowrie JSON logs, normalize them into SecurityEvent objects, and display them."""
    if not json_log_path.exists():
        logger.error("Log file not found: %s", json_log_path)
        return 0

    logger.info("Parsing captured raw events from: %s", json_log_path)
    normalized_events = []

    with open(json_log_path, "r", encoding="utf-8") as f:
        for line in f:
            if not line.strip():
                continue
            event = EventNormalizer.normalize(json.loads(line.strip()))
            if event:
                normalized_events.append(event)

    print("\n" + "=" * 80)
    print(f" NORMALIZED SECURITY EVENTS CAPTURED ({len(normalized_events)} total)")
    print("=" * 80)
    for idx, ev in enumerate(normalized_events, 1):
        print(f"\n[Event #{idx}] ID: {ev.event_id}")
        print(f"  Asset ID   : {ev.asset_id}")
        print(f"  Protocol   : {ev.protocol}")
        print(f"  Event Type : {ev.event_type}")
        print(f"  Source     : {ev.source_ip}:{ev.source_port or 'N/A'}")
        print(f"  Username   : {ev.username or 'N/A'}")
        print(f"  Status     : {ev.status}")
        print(f"  Timestamp  : {ev.timestamp}")
        print(f"  Metadata   : {json.dumps(ev.metadata, indent=4)}")

    print("\n" + "=" * 80 + "\n")
    return len(normalized_events)


def main():
    host = settings.SSH_LISTEN_HOST if settings.SSH_LISTEN_HOST != "0.0.0.0" else "127.0.0.1"
    port = settings.SSH_LISTEN_PORT

    logger.info("Starting SSH Honeypot Attack Simulation targeting %s:%d...", host, port)

    # 1. Test failed auth
    test_failed_authentication(host, port, user="unauthorized_admin", pwd="WrongPassword123!")
    time.sleep(1)

    # 2. Test bait auth & recon
    terminal_output = test_successful_interaction(host, port, user="finance_admin", pwd="Finance@2026")

    print("\n--- Terminal Session Transcript Captured from Honeypot ---")
    print(terminal_output)

    time.sleep(1)

    # 3. Parse and verify normalized events
    log_file = PROJECT_ROOT / "var" / "log" / "cowrie" / "cowrie.json"
    parse_and_display_events(log_file)


if __name__ == "__main__":
    main()
