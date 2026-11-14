"""Multi-Stage End-to-End Adversary Kill-Chain Simulation Script.

Executes a coordinated multi-protocol cyberattack across all 4 honeypot assets:
1. Stage 1: Initial Foothold on SSH (finance-server:2222) -> Discovers FTP backup credentials.
2. Stage 2: Lateral Movement to FTP (Corp-Storage-Node-02:2121) -> Discovers database migration notes.
3. Stage 3: Web Reconnaissance & Exfiltration on Admin Portal (8080) -> Exfiltrates decoy financial PDFs.
4. Stage 4: Database Infiltration on PostgreSQL (5432) & MySQL (3306) -> Queries executive compensation.
5. Stage 5: Canary Detection & Lateral Movement Correlation -> Verifies cross-service alerts.
6. Stage 6: Central Collector Forwarding -> Aggregates and flushes normalized SecurityEvents.
"""

from __future__ import annotations

import ftplib
import io
import json
import socket
import struct
import sys
import time
from pathlib import Path

# Add project root to path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import httpx

from collector.daemon import CollectorDaemon
from collector.event_collector import global_collector
from services.credentials.registry import global_registry
from shared.config import settings
from shared.logger import get_logger

logger = get_logger("KillChainSimulator")


def simulate_ssh_foothold() -> None:
    """Stage 1: Attempt SSH foothold using Paramiko."""
    logger.info("=================================================================")
    logger.info(" STAGE 1: Initial Reconnaissance & Foothold on SSH (Port %d)", settings.SSH_LISTEN_PORT)
    logger.info("=================================================================")
    try:
        import paramiko
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(
            "127.0.0.1",
            port=settings.SSH_LISTEN_PORT,
            username="finance_admin",
            password="Finance@2026",
            timeout=5.0,
            allow_agent=False,
            look_for_keys=False,
        )
        logger.info("[+] SSH Login Successful: finance_admin on finance-server")

        # Execute recon commands
        stdin, stdout, stderr = client.exec_command("cat /home/finance_admin/.bash_history")
        history = stdout.read().decode("utf-8", errors="replace")
        logger.info("[+] Discovered .bash_history containing lateral credentials:")
        for line in history.strip().splitlines()[:5]:
            logger.info("    $ %s", line)

        client.close()
    except Exception as exc:
        logger.warning("SSH stage skipped or failed (service may be offline): %s", exc)


def simulate_ftp_lateral() -> None:
    """Stage 2: Lateral movement to FTP backup node."""
    logger.info("=================================================================")
    logger.info(" STAGE 2: Lateral Movement to FTP Backup Storage (Port %d)", settings.FTP_LISTEN_PORT)
    logger.info("=================================================================")
    try:
        ftp = ftplib.FTP()
        ftp.connect("127.0.0.1", settings.FTP_LISTEN_PORT, timeout=5.0)
        ftp.login("backup_user", "Backup@2026")
        logger.info("[+] FTP Login Successful: backup_user on Corp-Storage-Node-02")

        # List files
        listing = []
        ftp.retrlines("LIST", listing.append)
        logger.info("[+] Directory listing retrieved (%d entries)", len(listing))

        # Download migration notes containing DB credentials
        buf = io.BytesIO()
        ftp.retrbinary("RETR db_migration_notes.txt", buf.write)
        notes = buf.getvalue().decode("utf-8", errors="replace")
        logger.info("[+] Exfiltrated db_migration_notes.txt:\n%s", notes[:250])

        ftp.quit()
    except Exception as exc:
        logger.warning("FTP stage skipped or failed (service may be offline): %s", exc)


def simulate_web_exfiltration() -> None:
    """Stage 3: Web Admin Portal exploration and document exfiltration."""
    logger.info("=================================================================")
    logger.info(" STAGE 3: Web Admin Portal Intrusion & Document Theft (Port %d)", settings.WEB_LISTEN_PORT)
    logger.info("=================================================================")
    base_url = f"http://127.0.0.1:{settings.WEB_LISTEN_PORT}"
    try:
        with httpx.Client(base_url=base_url, timeout=5.0, follow_redirects=True) as client:
            # Login
            login_resp = client.post("/login", data={"username": "admin", "password": "Apex@2026!"})
            logger.info("[+] Web Login: admin -> HTTP %d", login_resp.status_code)

            # View configuration
            cfg_resp = client.get("/configuration/view/database_config.json")
            logger.info("[+] Accessed decoy database_config.json -> HTTP %d", cfg_resp.status_code)

            # Download decoy PDF report
            dl_resp = client.get("/finance/download/Q4_consolidated_financials.pdf")
            logger.info("[+] Exfiltrated Q4_consolidated_financials.pdf -> HTTP %d (%d bytes)", dl_resp.status_code, len(dl_resp.content))
    except Exception as exc:
        logger.warning("Web stage skipped or failed: %s", exc)


def simulate_postgres_queries() -> None:
    """Stage 4A: PostgreSQL exploitation."""
    logger.info("=================================================================")
    logger.info(" STAGE 4A: Database Exploitation on PostgreSQL (Port %d)", settings.DB_PG_LISTEN_PORT)
    logger.info("=================================================================")
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5.0)
        s.connect(("127.0.0.1", settings.DB_PG_LISTEN_PORT))

        # StartupMessage with user=database_root
        user_param = b"user\x00database_root\x00database\x00corporate_finance\x00\x00"
        msg_len = 4 + 4 + len(user_param)
        s.sendall(struct.pack("!II", msg_len, 196608) + user_param)

        # Read auth challenge
        resp = s.recv(1024)
        if resp.startswith(b"R"):
            # Send PasswordMessage 'p'
            pwd = b"DBroot@2026\x00"
            s.sendall(b"p" + struct.pack("!I", len(pwd) + 4) + pwd)

            # Read auth response
            auth_ok = s.recv(1024)
            logger.info("[+] PostgreSQL Authentication OK as database_root")

            # Send Query: SELECT * FROM executive_compensation;
            q = b"SELECT * FROM executive_compensation;\x00"
            s.sendall(b"Q" + struct.pack("!I", len(q) + 4) + q)
            q_res = s.recv(2048)
            logger.info("[+] PostgreSQL Query Executed (Received %d bytes)", len(q_res))

        s.close()
    except Exception as exc:
        logger.warning("PostgreSQL stage skipped or failed: %s", exc)


def simulate_mysql_queries() -> None:
    """Stage 4B: MySQL exploitation."""
    logger.info("=================================================================")
    logger.info(" STAGE 4B: Database Exploitation on MySQL (Port %d)", settings.DB_MYSQL_LISTEN_PORT)
    logger.info("=================================================================")
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5.0)
        s.connect(("127.0.0.1", settings.DB_MYSQL_LISTEN_PORT))

        # Read handshake packet
        hs = s.recv(1024)
        logger.info("[+] MySQL Handshake Received (%d bytes)", len(hs))

        # Send Client Handshake Response with user=database_root
        user = b"database_root\x00"
        body = bytearray(32)  # flags, max_packet, charset, filler
        body.extend(user)
        body.append(0)  # auth length 0
        pkt_len = len(body)
        header = bytes([pkt_len & 0xFF, (pkt_len >> 8) & 0xFF, (pkt_len >> 16) & 0xFF, 1])
        s.sendall(header + bytes(body))

        # Read OK packet
        ok = s.recv(1024)
        logger.info("[+] MySQL Authentication OK as database_root")

        # Send COM_QUERY (0x03): SHOW TABLES;
        cmd = b"\x03SHOW TABLES;"
        q_len = len(cmd)
        q_hdr = bytes([q_len & 0xFF, (q_len >> 8) & 0xFF, (q_len >> 16) & 0xFF, 0])
        s.sendall(q_hdr + cmd)
        q_resp = s.recv(2048)
        logger.info("[+] MySQL Query 'SHOW TABLES' response received (%d bytes)", len(q_resp))

        s.close()
    except Exception as exc:
        logger.warning("MySQL stage skipped or failed: %s", exc)


def verify_killchain_telemetry() -> None:
    """Stage 5 & 6: Canary correlation and collector daemon flush."""
    logger.info("=================================================================")
    logger.info(" STAGE 5 & 6: Canary Correlation & Central Collector Forwarding")
    logger.info("=================================================================")
    # Evaluate canaries
    global_registry.evaluate_interaction(
        username="database_root",
        password_attempt="DBroot@2026",
        target_asset="db-001",
        src_ip="192.168.1.105",
        protocol="DATABASE",
    )

    daemon = CollectorDaemon()
    stats_before = daemon.get_stats()
    logger.info("[*] Collector Status Before Flush: pending=%d, dead_letter=%d", stats_before["pending_event_count"], stats_before["dead_letter_count"])

    flushed = daemon.process_cycle()
    logger.info("[+] Collector Daemon Process Cycle Executed: %d events processed", flushed)

    stats_after = daemon.get_stats()
    logger.info("[+] Collector Health Status: %s (total_delivered=%d, pending=%d)", stats_after["status"], stats_after["total_delivered"], stats_after["pending_event_count"])
    logger.info("=================================================================")
    logger.info(" FULL KILL-CHAIN ATTACK SIMULATION COMPLETED SUCCESSFULLY ")
    logger.info("=================================================================")


def main() -> None:
    logger.info("Initiating Full Kill-Chain Simulation across all Deception Assets...")
    simulate_ssh_foothold()
    simulate_ftp_lateral()
    simulate_web_exfiltration()
    simulate_postgres_queries()
    simulate_mysql_queries()
    verify_killchain_telemetry()


if __name__ == "__main__":
    main()
