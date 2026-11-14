"""Asynchronous PostgreSQL Honeypot Protocol Server (PostgreSQL v3.0 Wire Protocol).

Simulates a real PostgreSQL database server on port 5432 with safe, in-memory query responses.
Captures connections, authentication attempts, database selection, and query executions.
Strictly isolated: does not connect to or expose any real database.
"""

from __future__ import annotations

import asyncio
import os
import struct
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

from shared.config import settings
from shared.logger import get_logger
from services.database.data.seed_db import get_query_result

logger = get_logger("PostgresHoneypot")

# Default bait credentials matching deception platform
DEFAULT_BAIT_USERS = {
    "database_root": "DBroot@2026",
    "postgres": "postgres123",
    "finance_admin": "Finance@2026",
    "backup_user": "Backup@2026",
    "admin": "Apex@2026!",
}


class PostgresServer:
    """Simulated PostgreSQL honeypot server running on pure Python asyncio."""

    def __init__(
        self,
        host: str = settings.DB_PG_LISTEN_HOST,
        port: int = settings.DB_PG_LISTEN_PORT,
        on_event_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
    ):
        self.host = host
        self.port = port
        self.on_event = on_event_callback
        self.server: Optional[asyncio.Server] = None
        self._running = False

    def emit_telemetry(self, raw_event: Dict[str, Any]) -> None:
        """Log raw event to file and dispatch to collector callback."""
        raw_event.setdefault("timestamp", datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"))
        raw_event.setdefault("protocol", "POSTGRESQL")
        raw_event.setdefault("asset_id", settings.DB_ASSET_ID)

        # Write to log
        try:
            settings.DB_LOG_DIR.mkdir(parents=True, exist_ok=True)
            with open(settings.DB_JSON_LOG, "a", encoding="utf-8") as f:
                import json
                f.write(json.dumps(raw_event) + "\n")
        except Exception as exc:
            logger.error("Failed to write database log: %s", exc)

        if self.on_event:
            try:
                self.on_event(raw_event)
            except Exception as exc:
                logger.error("Error in database on_event callback: %s", exc)

    async def handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        """Handle individual client PostgreSQL session."""
        peer = writer.get_extra_info("peername")
        src_ip = peer[0] if peer else "127.0.0.1"
        src_port = peer[1] if peer else 0
        session_id = f"pg_sess_{int(time.time() * 1000)}"
        start_time = time.time()

        username: Optional[str] = None
        database: str = "corporate_finance"

        logger.info("PostgreSQL client connected from %s:%d (session=%s)", src_ip, src_port, session_id)
        self.emit_telemetry({
            "eventid": "db.session.connect",
            "src_ip": src_ip,
            "src_port": src_port,
            "session_id": session_id,
            "sub_protocol": "PostgreSQL",
        })

        try:
            # 1. Read Initial Packet Header (4 bytes length)
            header = await reader.readexactly(4)
            msg_len = struct.unpack("!I", header)[0]
            body_len = msg_len - 4
            body = await reader.readexactly(body_len)

            # Check if SSLRequest (code 80877103)
            if msg_len == 8 and struct.unpack("!I", body)[0] == 80877103:
                # Reject SSL by sending 'N', forcing client to fallback to plaintext
                writer.write(b"N")
                await writer.drain()

                # Read actual StartupMessage
                header = await reader.readexactly(4)
                msg_len = struct.unpack("!I", header)[0]
                body = await reader.readexactly(msg_len - 4)

            # Parse StartupMessage parameters
            proto_ver = struct.unpack("!I", body[:4])[0]
            params = {}
            raw_params = body[4:].split(b"\x00")
            for i in range(0, len(raw_params) - 1, 2):
                if raw_params[i]:
                    k = raw_params[i].decode("utf-8", errors="replace")
                    v = raw_params[i + 1].decode("utf-8", errors="replace")
                    params[k] = v

            username = params.get("user", "postgres")
            database = params.get("database", "corporate_finance")

            # 2. Challenge with AuthenticationCleartextPassword (type 'R', code 3)
            writer.write(b"R" + struct.pack("!II", 8, 3))
            await writer.drain()

            # Read PasswordMessage ('p')
            msg_type = await reader.readexactly(1)
            pwd_header = await reader.readexactly(4)
            pwd_len = struct.unpack("!I", pwd_header)[0]
            raw_pwd = await reader.readexactly(pwd_len - 4)
            password = raw_pwd.rstrip(b"\x00").decode("utf-8", errors="replace")

            # Validate authentication against bait credentials
            expected_pwd = DEFAULT_BAIT_USERS.get(username)
            auth_success = expected_pwd is not None and expected_pwd == password

            if not auth_success:
                # Send ErrorResponse ('E')
                err_msg = f"password authentication failed for user \"{username}\"\x00".encode("utf-8")
                err_payload = b"SFATAL\x00C28P01\x00M" + err_msg + b"\x00"
                writer.write(b"E" + struct.pack("!I", len(err_payload) + 4) + err_payload)
                await writer.drain()

                self.emit_telemetry({
                    "eventid": "db.login.failed",
                    "src_ip": src_ip,
                    "src_port": src_port,
                    "session_id": session_id,
                    "username": username,
                    "password_length": len(password),
                    "database": database,
                    "sub_protocol": "PostgreSQL",
                })
                return

            # Auth Success! Send AuthenticationOk (code 0)
            writer.write(b"R" + struct.pack("!II", 8, 0))

            # Send ParameterStatus messages ('S')
            for param_k, param_v in [
                ("server_version", "15.4 (Debian 15.4-1.pgdg110+1)"),
                ("client_encoding", "UTF8"),
                ("server_encoding", "UTF8"),
                ("session_authorization", username),
                ("is_superuser", "on" if username in ("database_root", "postgres") else "off"),
            ]:
                s_bytes = param_k.encode("utf-8") + b"\x00" + param_v.encode("utf-8") + b"\x00"
                writer.write(b"S" + struct.pack("!I", len(s_bytes) + 4) + s_bytes)

            # Send BackendKeyData ('K')
            writer.write(b"K" + struct.pack("!III", 12, 1001, 2002))

            # Send ReadyForQuery ('Z', 'I' = idle)
            writer.write(b"Z" + struct.pack("!I", 5) + b"I")
            await writer.drain()

            self.emit_telemetry({
                "eventid": "db.login.success",
                "src_ip": src_ip,
                "src_port": src_port,
                "session_id": session_id,
                "username": username,
                "database": database,
                "sub_protocol": "PostgreSQL",
            })

            # 3. Main Query Loop
            while self._running:
                try:
                    q_type = await reader.readexactly(1)
                except asyncio.IncompleteReadError:
                    break

                if q_type == b"X":  # Terminate
                    break

                if q_type == b"Q":  # Simple Query
                    q_len = struct.unpack("!I", await reader.readexactly(4))[0]
                    query_bytes = await reader.readexactly(q_len - 4)
                    query_str = query_bytes.rstrip(b"\x00").decode("utf-8", errors="replace").strip()

                    # Check for enumeration
                    is_enum = any(tok in query_str.lower() for tok in [
                        "show", "pg_database", "pg_tables", "information_schema", "\\l", "\\dt"
                    ])

                    # Get simulated dataset
                    cols, rows = get_query_result(query_str, current_db=database)

                    # Send RowDescription ('T')
                    row_desc_body = bytearray()
                    row_desc_body.extend(struct.pack("!H", len(cols)))
                    for col_name in cols:
                        col_bytes = col_name.encode("utf-8") + b"\x00"
                        row_desc_body.extend(col_bytes)
                        # table_oid=0, col_attr=0, type_oid=25(text), type_len=-1, type_mod=-1, format=0
                        row_desc_body.extend(struct.pack("!IHIhiH", 0, 0, 25, -1, -1, 0))

                    writer.write(b"T" + struct.pack("!I", len(row_desc_body) + 4) + row_desc_body)

                    # Send DataRow ('D') messages
                    for row in rows:
                        data_row_body = bytearray()
                        data_row_body.extend(struct.pack("!H", len(row)))
                        for val in row:
                            val_str = str(val).encode("utf-8")
                            data_row_body.extend(struct.pack("!i", len(val_str)))
                            data_row_body.extend(val_str)
                        writer.write(b"D" + struct.pack("!I", len(data_row_body) + 4) + data_row_body)

                    # Send CommandComplete ('C')
                    tag = f"SELECT {len(rows)}\x00".encode("utf-8")
                    writer.write(b"C" + struct.pack("!I", len(tag) + 4) + tag)

                    # Send ReadyForQuery ('Z')
                    writer.write(b"Z" + struct.pack("!I", 5) + b"I")
                    await writer.drain()

                    self.emit_telemetry({
                        "eventid": "db.query.enumeration" if is_enum else "db.query.execution",
                        "src_ip": src_ip,
                        "src_port": src_port,
                        "session_id": session_id,
                        "username": username,
                        "database": database,
                        "query": query_str,
                        "sub_protocol": "PostgreSQL",
                    })

        except (asyncio.IncompleteReadError, ConnectionResetError):
            pass
        except Exception as exc:
            logger.debug("PostgreSQL session %s error: %s", session_id, exc)
        finally:
            duration = round(time.time() - start_time, 2)
            self.emit_telemetry({
                "eventid": "db.session.disconnect",
                "src_ip": src_ip,
                "src_port": src_port,
                "session_id": session_id,
                "username": username,
                "duration_seconds": duration,
                "sub_protocol": "PostgreSQL",
            })
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass
            logger.info("PostgreSQL session %s disconnected (duration=%ss)", session_id, duration)

    async def start(self) -> None:
        """Start listening for incoming PostgreSQL connections."""
        self._running = True
        self.server = await asyncio.start_server(self.handle_client, self.host, self.port)
        logger.info("PostgreSQL Honeypot listening on %s:%d", self.host, self.port)

    async def stop(self) -> None:
        """Stop server."""
        self._running = False
        if self.server:
            self.server.close()
            await self.server.wait_closed()
            logger.info("PostgreSQL Honeypot stopped.")

