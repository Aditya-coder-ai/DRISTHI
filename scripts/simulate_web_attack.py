"""Simulated Adversary Interaction Script for Web Admin Honeypot.

Simulates real-world attacker behaviors against Apex Internal Management System:
1. Automated reconnaissance probes targeting suspicious endpoints (.env, /wp-admin, traversal).
2. Repeated brute-force authentication attempts against administrative accounts (triggering alert).
3. Successful authentication using discovered bait credentials (finance_admin / Finance@2026).
4. Reconnaissance across Employee Directory and Financial Operations.
5. Exfiltration of confidential decoy reports (Q4_consolidated_financials.pdf, payroll_tax_filing_2026.xlsx).
6. Execution of simulated database queries in the SQL management console.
7. Inspection of sensitive infrastructure configurations and bait credentials (database_config.json).
8. Verification of structured security event capture and normalization.
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

import httpx

from shared.config import settings
from shared.logger import get_logger

logger = get_logger("WebAttackSimulator")


def simulate_recon_probes(base_url: str) -> None:
    """Probe common web vulnerability and scanner paths."""
    logger.info("--- Step 1: Simulating Web Reconnaissance Probes ---")
    probe_targets = [
        "/.env",
        "/wp-admin",
        "/phpmyadmin",
        "/config.php",
        "/../../etc/passwd",
    ]
    with httpx.Client(base_url=base_url, timeout=5.0) as client:
        for path in probe_targets:
            try:
                resp = client.get(path)
                logger.info("Probe GET %s -> HTTP %d (Blocked/Logged as expected)", path, resp.status_code)
            except Exception as exc:
                logger.error("Failed probe on %s: %s", path, exc)


def simulate_brute_force(base_url: str) -> None:
    """Simulate password guessing/brute force on login."""
    logger.info("--- Step 2: Simulating Brute-Force Authentication Attack ---")
    attacker_passwords = ["Password123!", "Admin12345", "SuperSecret!", "LetMeIn2026!"]
    with httpx.Client(base_url=base_url, timeout=5.0) as client:
        for pwd in attacker_passwords:
            resp = client.post(
                "/login",
                data={"username": "administrator", "password": pwd},
            )
            logger.info("Brute-force attempt with password '%s' -> HTTP %d", "*" * len(pwd), resp.status_code)
            time.sleep(0.2)


def simulate_bait_login_and_exfiltration(base_url: str) -> None:
    """Authenticate with bait credentials, explore portal, and download decoy files."""
    logger.info("--- Step 3: Authenticating with Bait Credentials (finance_admin) ---")
    with httpx.Client(base_url=base_url, timeout=10.0, follow_redirects=True) as client:
        # Login
        login_resp = client.post(
            "/login",
            data={"username": "finance_admin", "password": "Finance@2026", "remember": "true"},
        )
        logger.info("Login response: HTTP %d (URL: %s)", login_resp.status_code, login_resp.url.path)

        # 4. Access Employees
        logger.info("--- Step 4: Accessing Employee Roster ---")
        emp_resp = client.get("/employees")
        logger.info("GET /employees -> HTTP %d (Content length: %d)", emp_resp.status_code, len(emp_resp.text))

        # 5. Access Finance & Download Decoy Reports
        logger.info("--- Step 5: Accessing Financial Reports & Exfiltrating Decoys ---")
        fin_resp = client.get("/finance")
        logger.info("GET /finance -> HTTP %d", fin_resp.status_code)

        for report in ["Q4_consolidated_financials.pdf", "payroll_tax_filing_2026.xlsx"]:
            dl_resp = client.get(f"/finance/download/{report}")
            logger.info("Exfiltrated Decoy Report %s -> HTTP %d (%d bytes)", report, dl_resp.status_code, len(dl_resp.content))

        # 6. Database Query Console
        logger.info("--- Step 6: Querying Simulated Database Console ---")
        query_resp = client.post(
            "/database/query",
            data={"query": "SELECT * FROM customers WHERE tier = 'Enterprise';"},
        )
        logger.info("POST /database/query -> HTTP %d", query_resp.status_code)

        # 7. System Configuration & Bait File Trigger
        logger.info("--- Step 7: Accessing Infrastructure Config & Bait Credentials ---")
        cfg_resp = client.get("/configuration/view/database_config.json")
        logger.info("GET /configuration/view/database_config.json -> HTTP %d", cfg_resp.status_code)
        if cfg_resp.status_code == 200:
            logger.info("Captured Decoy Database Configuration:\n%s", cfg_resp.text[:200])


def verify_captured_events() -> None:
    """Read the web honeypot event log and print summary statistics."""
    logger.info("--- Step 8: Verifying Captured Web Security Events ---")
    log_path = settings.WEB_JSON_LOG
    if not log_path.exists():
        logger.warning("Web log file not found at %s", log_path)
        return

    events = []
    with open(log_path, "r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                try:
                    events.append(json.loads(line))
                except Exception:
                    pass

    logger.info("Total Web Telemetry Events Captured: %d", len(events))
    event_counts: dict[str, int] = {}
    for e in events:
        eid = e.get("eventid", "unknown")
        event_counts[eid] = event_counts.get(eid, 0) + 1

    for eid, count in event_counts.items():
        logger.info("  - %-25s : %d", eid, count)


def main() -> None:
    base_url = f"http://{settings.WEB_LISTEN_HOST}:{settings.WEB_LISTEN_PORT}"
    if settings.WEB_LISTEN_HOST == "0.0.0.0":
        base_url = f"http://127.0.0.1:{settings.WEB_LISTEN_PORT}"

    logger.info("Starting Web Honeypot Adversary Simulation against %s...", base_url)
    simulate_recon_probes(base_url)
    simulate_brute_force(base_url)
    simulate_bait_login_and_exfiltration(base_url)
    verify_captured_events()
    logger.info("Adversary simulation completed successfully.")


if __name__ == "__main__":
    main()
