"""Integration tests for SSH Deception Honeypot Service."""

import json
import os
import socket
import subprocess
import sys
import time
from pathlib import Path
import pytest
import paramiko

from collector.normalizer import EventNormalizer

PROJECT_ROOT = Path(__file__).resolve().parent.parent
TEST_PORT = 22222
TEST_HOST = "127.0.0.1"


def is_port_open(host: str, port: int) -> bool:
    """Check if TCP port is accepting connections."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(1)
        return s.connect_ex((host, port)) == 0


@pytest.fixture(scope="module")
def running_ssh_honeypot():
    """Fixture to start Cowrie SSH honeypot on TEST_PORT and tear it down after tests."""
    log_file = PROJECT_ROOT / "var" / "log" / "cowrie" / "cowrie.json"
    log_file.parent.mkdir(parents=True, exist_ok=True)
    # Clear log file before test
    if log_file.exists():
        log_file.write_text("", encoding="utf-8")

    env = os.environ.copy()
    env["PYTHONPATH"] = str(PROJECT_ROOT)
    env["COWRIE_HONEYPOT_HOSTNAME"] = "finance-server"
    env["COWRIE_HONEYPOT_CONTENTS_PATH"] = str(PROJECT_ROOT / "services" / "ssh" / "honeyfs")
    env["COWRIE_HONEYPOT_ETC_PATH"] = str(PROJECT_ROOT / "services" / "ssh" / "config")
    env["COWRIE_SHELL_FILESYSTEM"] = str(PROJECT_ROOT / "services" / "ssh" / "fs.pickle")
    env["COWRIE_SSH_LISTEN_ENDPOINTS"] = f"tcp:{TEST_PORT}:interface={TEST_HOST}"
    env["COWRIE_SSH_ENABLED"] = "true"
    env["COWRIE_TELNET_ENABLED"] = "false"
    env["COWRIE_OUTPUT_JSONLOG_ENABLED"] = "true"
    env["COWRIE_OUTPUT_JSONLOG_LOGFILE"] = str(log_file)

    runner_script = PROJECT_ROOT / "services" / "ssh" / "runner.py"

    proc = subprocess.Popen(
        [sys.executable, str(runner_script), "run", "--port", str(TEST_PORT), "--host", TEST_HOST],
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    # Wait for service to bind and accept connections
    max_wait = 15
    start_time = time.time()
    ready = False
    while time.time() - start_time < max_wait:
        if is_port_open(TEST_HOST, TEST_PORT):
            ready = True
            break
        time.sleep(0.5)

    if not ready:
        proc.kill()
        out, err = proc.communicate()
        pytest.fail(f"Cowrie SSH honeypot failed to listen on {TEST_HOST}:{TEST_PORT}. Stderr: {err.decode('utf-8', errors='ignore')}")

    yield proc

    # Teardown: terminate process
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()


def test_ssh_honeyfs_assets_exist():
    """Verify that all honeyfs deception assets exist on disk."""
    honeyfs_dir = PROJECT_ROOT / "services" / "ssh" / "honeyfs"
    assert (honeyfs_dir / "etc" / "hosts").exists()
    assert (honeyfs_dir / "etc" / "hostname").exists()
    assert (honeyfs_dir / "etc" / "issue").exists()
    assert (honeyfs_dir / "etc" / "motd").exists()
    assert (honeyfs_dir / "etc" / "passwd").exists()
    assert (honeyfs_dir / "etc" / "shadow").exists()
    assert (honeyfs_dir / "home" / "finance_admin" / "server_notes.txt").exists()
    assert (honeyfs_dir / "var" / "financial_data" / "Q4_payroll_summary.csv").exists()


def test_ssh_failed_login_and_event_generation(running_ssh_honeypot):
    """Verify that an unauthorized login attempt fails and generates a structured event."""
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    with pytest.raises(paramiko.AuthenticationException):
        client.connect(
            hostname=TEST_HOST,
            port=TEST_PORT,
            username="unauthorized_intruder",
            password="WrongPassword123!",
            timeout=5,
            allow_agent=False,
            look_for_keys=False,
        )

    time.sleep(1)

    log_file = PROJECT_ROOT / "var" / "log" / "cowrie" / "cowrie.json"
    assert log_file.exists()

    events = []
    with open(log_file, "r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                ev = EventNormalizer.normalize(json.loads(line.strip()))
                if ev:
                    events.append(ev)

    failed_events = [e for e in events if e.event_type == "login_failed" and e.username == "unauthorized_intruder"]
    assert len(failed_events) >= 1
    ev = failed_events[0]
    assert ev.asset_id == "ssh-001"
    assert ev.protocol == "SSH"
    assert ev.status == "failed"
    assert ev.metadata["hostname"] == "finance-server"
    assert "WrongPassword123!" not in str(ev.metadata)


def test_ssh_successful_login_and_command_execution(running_ssh_honeypot):
    """Verify bait credential login and command execution generate structured events."""
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    client.connect(
        hostname=TEST_HOST,
        port=TEST_PORT,
        username="finance_admin",
        password="Finance@2026",
        timeout=10,
        allow_agent=False,
        look_for_keys=False,
    )

    chan = client.invoke_shell()
    time.sleep(0.8)
    chan.send("whoami\n")
    time.sleep(0.8)
    chan.send("cat /etc/hostname\n")
    time.sleep(0.8)

    recv_buf = ""
    while chan.recv_ready():
        recv_buf += chan.recv(4096).decode("utf-8", errors="replace")

    chan.close()
    client.close()
    time.sleep(1)

    log_file = PROJECT_ROOT / "var" / "log" / "cowrie" / "cowrie.json"
    events = []
    with open(log_file, "r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                ev = EventNormalizer.normalize(json.loads(line.strip()))
                if ev:
                    events.append(ev)

    success_events = [e for e in events if e.event_type == "login_success" and e.username == "finance_admin"]
    assert len(success_events) >= 1
    assert success_events[0].metadata.get("bait_credential_triggered") is True
    assert success_events[0].metadata.get("alert_priority") == "HIGH"

    cmd_events = [e for e in events if e.event_type == "command_execution"]
    executed_commands = [e.metadata.get("command") for e in cmd_events]
    assert any("whoami" in (c or "") for c in executed_commands)
