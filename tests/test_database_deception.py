"""Unit and Integration Tests for Database Deception Honeypot (PostgreSQL & MySQL)."""

import asyncio
import socket
import struct
import pytest

from collector.event_collector import global_collector
from collector.normalizer import EventNormalizer
from services.database.data.seed_db import get_query_result
from services.database.db_event_adapter import DatabaseEventAdapter
from services.database.postgres_server import PostgresServer
from services.database.mysql_server import MySQLServer
from shared.event_schema import EventStatus, EventType, ProtocolType


@pytest.fixture(autouse=True)
def clean_collector():
    global_collector.clear()
    yield
    global_collector.clear()


def test_seed_db_query_isolation_and_results():
    """Verify in-memory query simulation produces expected records with zero host execution."""
    # Test SHOW DATABASES
    cols, rows = get_query_result("SHOW DATABASES;")
    assert "Database" in cols
    assert any("corporate_finance" in r[0] for r in rows)

    # Test SHOW TABLES
    cols, rows = get_query_result("SHOW TABLES;", current_db="corporate_finance")
    assert any("general_ledger" in r[0] for r in rows)

    # Test SELECT FROM clients
    cols, rows = get_query_result("SELECT * FROM clients;")
    assert "company_name" in cols
    assert any("Apex Global Logistics" in r[1] for r in rows)

    # Test SELECT FROM executive_compensation
    cols, rows = get_query_result("SELECT * FROM executive_compensation;")
    assert "annual_base" in cols
    assert any("Robert Johnson" in r[1] for r in rows)


def test_db_adapter_failed_login():
    """Verify failed database login normalizes with redacted password length."""
    raw = {
        "eventid": "db.login.failed",
        "src_ip": "198.51.100.77",
        "src_port": 54320,
        "username": "attacker",
        "password": "WrongPassword!",
        "database": "corporate_finance",
        "sub_protocol": "PostgreSQL",
    }
    event = DatabaseEventAdapter.normalize(raw, asset_id="db-001")
    assert event is not None
    assert event.protocol == ProtocolType.DATABASE.value
    assert event.event_type == EventType.LOGIN_FAILED.value
    assert event.status == EventStatus.FAILED.value
    assert event.username == "attacker"
    assert event.metadata["password_length"] == len("WrongPassword!")
    assert "WrongPassword!" not in str(event.model_dump())


def test_db_adapter_bait_login_success():
    """Verify successful login with database_root triggers HIGH alert priority."""
    raw = {
        "eventid": "db.login.success",
        "src_ip": "10.0.0.15",
        "username": "database_root",
        "database": "corporate_finance",
        "sub_protocol": "PostgreSQL",
    }
    event = DatabaseEventAdapter.normalize(raw, asset_id="db-001")
    assert event is not None
    assert event.event_type == EventType.LOGIN_SUCCESS.value
    assert event.status == EventStatus.SUCCESS.value
    assert event.metadata.get("bait_credential_triggered") is True
    assert event.metadata.get("alert_priority") == "HIGH"


def test_db_adapter_query_enumeration():
    """Verify enumeration queries normalize to DATABASE_ENUMERATION."""
    raw = {
        "eventid": "db.query.enumeration",
        "src_ip": "10.0.0.15",
        "username": "database_root",
        "query": "SHOW TABLES;",
        "sub_protocol": "MySQL",
    }
    event = DatabaseEventAdapter.normalize(raw, asset_id="db-001")
    assert event is not None
    assert event.event_type == EventType.DATABASE_ENUMERATION.value
    assert event.status == EventStatus.DETECTED.value
    assert event.metadata["attack_vector"] == "Database Schema Discovery / Enumeration"


def test_normalizer_facade_dispatches_database():
    """Verify central EventNormalizer routes DATABASE protocol to DatabaseEventAdapter."""
    raw = {
        "eventid": "db.login.success",
        "src_ip": "10.0.0.15",
        "username": "database_root",
    }
    event = EventNormalizer.normalize(raw, protocol=ProtocolType.DATABASE.value)
    assert event is not None
    assert event.protocol == "DATABASE"
    assert event.username == "database_root"


def test_live_postgres_protocol_flow():
    """Integration test: start PostgresServer on loopback, test SSL probe, auth, query."""
    async def _run():
        test_port = 15432
        collected_events = []

        def on_evt(r):
            evt = DatabaseEventAdapter.normalize(r)
            if evt:
                collected_events.append(evt)

        server = PostgresServer(host="127.0.0.1", port=test_port, on_event_callback=on_evt)
        await server.start()

        try:
            reader, writer = await asyncio.open_connection("127.0.0.1", test_port)

            # 1. SSLRequest probe (length 8, code 80877103)
            writer.write(struct.pack("!II", 8, 80877103))
            await writer.drain()
            ssl_resp = await reader.readexactly(1)
            assert ssl_resp == b"N"  # SSL rejected, forcing plaintext

            # 2. StartupMessage with user=database_root
            user_param = b"user\x00database_root\x00database\x00corporate_finance\x00\x00"
            msg_len = 4 + 4 + len(user_param)
            writer.write(struct.pack("!II", msg_len, 196608) + user_param)
            await writer.drain()

            # 3. Read auth challenge 'R'
            resp = await reader.read(1024)
            assert resp.startswith(b"R")

            # 4. Send PasswordMessage 'p'
            pwd = b"DBroot@2026\x00"
            writer.write(b"p" + struct.pack("!I", len(pwd) + 4) + pwd)
            await writer.drain()

            # 5. Read auth OK + params + ready for query
            auth_ok = await reader.read(2048)
            assert b"R" in auth_ok
            assert b"Z" in auth_ok

            # 6. Execute Query
            q = b"SELECT * FROM general_ledger;\x00"
            writer.write(b"Q" + struct.pack("!I", len(q) + 4) + q)
            await writer.drain()
            q_resp = await reader.read(2048)
            assert b"T" in q_resp  # RowDescription
            assert b"D" in q_resp  # DataRow
            assert b"C" in q_resp  # CommandComplete

            # 7. Terminate
            writer.write(b"X\x00\x00\x00\x04")
            await writer.drain()
            writer.close()
            await writer.wait_closed()

        finally:
            await server.stop()

        assert any(e.event_type == EventType.LOGIN_SUCCESS.value for e in collected_events)
        assert any(e.event_type == EventType.QUERY_EXECUTION.value for e in collected_events)

    asyncio.run(_run())


def test_live_mysql_protocol_flow():
    """Integration test: start MySQLServer on loopback, test handshake, auth, query."""
    async def _run():
        test_port = 13306
        collected_events = []

        def on_evt(r):
            evt = DatabaseEventAdapter.normalize(r)
            if evt:
                collected_events.append(evt)

        server = MySQLServer(host="127.0.0.1", port=test_port, on_event_callback=on_evt)
        await server.start()

        try:
            reader, writer = await asyncio.open_connection("127.0.0.1", test_port)

            # 1. Read Initial Handshake
            hs = await reader.read(1024)
            assert b"8.0.35-Apex-Cluster" in hs

            # 2. Send Handshake Response with user=database_root
            user = b"database_root\x00"
            body = bytearray(32)
            body.extend(user)
            body.append(0)  # auth length 0
            pkt_len = len(body)
            header = bytes([pkt_len & 0xFF, (pkt_len >> 8) & 0xFF, (pkt_len >> 16) & 0xFF, 1])
            writer.write(header + bytes(body))
            await writer.drain()

            # 3. Read OK packet
            ok = await reader.read(1024)
            assert len(ok) >= 4

            # 4. Send COM_QUERY (0x03): SHOW TABLES;
            cmd = b"\x03SHOW TABLES;"
            q_len = len(cmd)
            q_hdr = bytes([q_len & 0xFF, (q_len >> 8) & 0xFF, (q_len >> 16) & 0xFF, 0])
            writer.write(q_hdr + cmd)
            await writer.drain()
            q_resp = await reader.read(2048)
            assert len(q_resp) > 0

            # 5. Send COM_QUIT
            quit_cmd = bytes([1, 0, 0, 0, 0x01])
            writer.write(quit_cmd)
            await writer.drain()
            writer.close()
            await writer.wait_closed()

        finally:
            await server.stop()

        assert any(e.event_type == EventType.LOGIN_SUCCESS.value for e in collected_events)
        assert any(e.event_type == EventType.DATABASE_ENUMERATION.value for e in collected_events)

    asyncio.run(_run())
