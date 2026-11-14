"""Asynchronous MySQL Honeypot Protocol Server (MySQL Client/Server Protocol).

Simulates a real MySQL database server on port 3306 with safe, in-memory query responses.
Captures connection metadata, credentials, database selection, and SQL queries.
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

logger = get_logger("MySQLHoneypot")

# Default bait credentials matching deception platform
DEFAULT_BAIT_USERS = {
    "database_root": "DBroot@2026",
    "root": "root123",
    "finance_admin": "Finance@2026",
    "backup_user": "Backup@2026",
    "admin": "Apex@2026!",
}


def build_mysql_packet(payload: bytes, seq_id: int) -> bytes:
    """Pack payload with 3-byte length and 1-byte sequence ID."""
    pkt_len = len(payload)
    header = bytes([
        pkt_len & 0xFF,
        (pkt_len >> 8) & 0xFF,
        (pkt_len >> 16) & 0xFF,
        seq_id & 0xFF,
    ])
    return header + payload


def lenenc_int(value: int) -> bytes:
    """Encode an integer as a MySQL length-encoded integer."""
    if value < 251:
        return bytes([value])
    elif value < 65536:
        return b"\xfc" + struct.pack("<H", value)
    elif value < 16777216:
        return b"\xfd" + bytes([value & 0xFF, (value >> 8) & 0xFF, (value >> 16) & 0xFF])
    else:
        return b"\xfe" + struct.pack("<Q", value)


def lenenc_str(s: str) -> bytes:
    """Encode a string as a MySQL length-encoded string."""
    encoded = s.encode("utf-8")
    return lenenc_int(len(encoded)) + encoded


class MySQLServer:
    """Simulated MySQL honeypot server running on pure Python asyncio."""

    def __init__(
        self,
        host: str = settings.DB_MYSQL_LISTEN_HOST,
        port: int = settings.DB_MYSQL_LISTEN_PORT,
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
        raw_event.setdefault("protocol", "MYSQL")
        raw_event.setdefault("asset_id", settings.DB_ASSET_ID)

        try:
            settings.DB_LOG_DIR.mkdir(parents=True, exist_ok=True)
            with open(settings.DB_JSON_LOG, "a", encoding="utf-8") as f:
                import json
                f.write(json.dumps(raw_event) + "\n")
        except Exception as exc:
            logger.error("Failed to write MySQL database log: %s", exc)

        if self.on_event:
            try:
                self.on_event(raw_event)
            except Exception as exc:
                logger.error("Error in MySQL on_event callback: %s", exc)

    async def read_packet(self, reader: asyncio.StreamReader) -> Tuple[bytes, int]:
        """Read a single MySQL packet returning (payload, seq_id)."""
        header = await reader.readexactly(4)
        pkt_len = header[0] | (header[1] << 8) | (header[2] << 16)
        seq_id = header[3]
        payload = await reader.readexactly(pkt_len) if pkt_len > 0 else b""
        return payload, seq_id

    async def handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        """Handle individual client MySQL session."""
        peer = writer.get_extra_info("peername")
        src_ip = peer[0] if peer else "127.0.0.1"
        src_port = peer[1] if peer else 0
        session_id = f"mysql_sess_{int(time.time() * 1000)}"
        start_time = time.time()

        username: Optional[str] = None
        database: str = "corporate_finance"

        logger.info("MySQL client connected from %s:%d (session=%s)", src_ip, src_port, session_id)
        self.emit_telemetry({
            "eventid": "db.session.connect",
            "src_ip": src_ip,
            "src_port": src_port,
            "session_id": session_id,
            "sub_protocol": "MySQL",
        })

        try:
            # 1. Send Initial Handshake Packet (seq_id = 0)
            conn_id = 1
            server_version = b"8.0.35-Apex-Cluster\x00"
            salt1 = b"01234567"
            salt2 = b"89abcdef0123\x00"
            capabilities = 0xF7FF  # Client capabilities supported
            charset = 33  # utf8_general_ci
            status_flags = 2  # AUTOCOMMIT

            handshake_payload = bytearray()
            handshake_payload.append(10)  # protocol version 10
            handshake_payload.extend(server_version)
            handshake_payload.extend(struct.pack("<I", conn_id))
            handshake_payload.extend(salt1)
            handshake_payload.append(0)  # filler
            handshake_payload.extend(struct.pack("<H", capabilities & 0xFFFF))
            handshake_payload.append(charset)
            handshake_payload.extend(struct.pack("<H", status_flags))
            handshake_payload.extend(struct.pack("<H", (capabilities >> 16) & 0xFFFF))
            handshake_payload.append(21)  # auth_plugin_data_len
            handshake_payload.extend(b"\x00" * 10)  # reserved
            handshake_payload.extend(salt2)
            handshake_payload.extend(b"mysql_native_password\x00")

            writer.write(build_mysql_packet(bytes(handshake_payload), seq_id=0))
            await writer.drain()

            # 2. Read Client Handshake Response
            resp_payload, resp_seq = await self.read_packet(reader)
            if len(resp_payload) < 32:
                return

            # Parse client response
            # First 4 bytes client flags, 4 bytes max packet, 1 byte charset, 23 bytes filler
            offset = 32
            # Find null-terminated username
            user_end = resp_payload.find(b"\x00", offset)
            if user_end != -1:
                username = resp_payload[offset:user_end].decode("utf-8", errors="replace")
                offset = user_end + 1

            # Auth response length
            auth_len = 0
            if offset < len(resp_payload):
                auth_len = resp_payload[offset]
                offset += 1 + auth_len

            # Database name if CLIENT_CONNECT_WITH_DB
            if offset < len(resp_payload):
                db_end = resp_payload.find(b"\x00", offset)
                if db_end != -1:
                    db_str = resp_payload[offset:db_end].decode("utf-8", errors="replace").strip()
                    if db_str:
                        database = db_str

            # Authenticate: Allow known bait accounts or password validation
            # For deception purposes, if username is a known bait account, we accept or challenge
            auth_success = username in DEFAULT_BAIT_USERS

            if not auth_success:
                # Send ERR_Packet
                err_payload = b"\xff" + struct.pack("<H", 1045) + b"#28000" + f"Access denied for user '{username}'@'{src_ip}'".encode("utf-8")
                writer.write(build_mysql_packet(err_payload, seq_id=resp_seq + 1))
                await writer.drain()

                self.emit_telemetry({
                    "eventid": "db.login.failed",
                    "src_ip": src_ip,
                    "src_port": src_port,
                    "session_id": session_id,
                    "username": username,
                    "password_length": auth_len,
                    "database": database,
                    "sub_protocol": "MySQL",
                })
                return

            # Send OK_Packet (seq_id = 2)
            ok_payload = bytes([0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00])
            writer.write(build_mysql_packet(ok_payload, seq_id=resp_seq + 1))
            await writer.drain()

            self.emit_telemetry({
                "eventid": "db.login.success",
                "src_ip": src_ip,
                "src_port": src_port,
                "session_id": session_id,
                "username": username,
                "database": database,
                "sub_protocol": "MySQL",
            })

            # 3. Command Execution Loop
            while self._running:
                try:
                    cmd_payload, cmd_seq = await self.read_packet(reader)
                except asyncio.IncompleteReadError:
                    break

                if not cmd_payload:
                    break

                cmd_type = cmd_payload[0]
                body = cmd_payload[1:]

                if cmd_type == 0x01:  # COM_QUIT
                    break

                elif cmd_type == 0x02:  # COM_INIT_DB
                    database = body.decode("utf-8", errors="replace").strip()
                    writer.write(build_mysql_packet(bytes([0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00]), seq_id=cmd_seq + 1))
                    await writer.drain()

                elif cmd_type == 0x0E:  # COM_PING
                    writer.write(build_mysql_packet(bytes([0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00]), seq_id=cmd_seq + 1))
                    await writer.drain()

                elif cmd_type == 0x03:  # COM_QUERY
                    query_str = body.decode("utf-8", errors="replace").strip()
                    is_enum = any(tok in query_str.lower() for tok in [
                        "show", "information_schema", "database()", "schema"
                    ])

                    cols, rows = get_query_result(query_str, current_db=database)

                    # Build MySQL Result Set Packets
                    seq = cmd_seq + 1

                    # 1. Column Count Packet
                    writer.write(build_mysql_packet(lenenc_int(len(cols)), seq_id=seq))
                    seq += 1

                    # 2. Column Definition Packets
                    for col_name in cols:
                        col_def = bytearray()
                        col_def.extend(lenenc_str("def"))  # catalog
                        col_def.extend(lenenc_str(database))  # schema
                        col_def.extend(lenenc_str("table"))  # table
                        col_def.extend(lenenc_str("table"))  # org_table
                        col_def.extend(lenenc_str(col_name))  # name
                        col_def.extend(lenenc_str(col_name))  # org_name
                        col_def.append(0x0C)  # length of fixed fields
                        col_def.extend(struct.pack("<H", 33))  # charset utf8
                        col_def.extend(struct.pack("<I", 255))  # column length
                        col_def.append(0xFD)  # type VAR_STRING
                        col_def.extend(struct.pack("<H", 0))  # flags
                        col_def.append(0)  # decimals
                        col_def.extend(b"\x00\x00")  # filler

                        writer.write(build_mysql_packet(bytes(col_def), seq_id=seq))
                        seq += 1

                    # 3. EOF Packet
                    writer.write(build_mysql_packet(bytes([0xFE, 0x00, 0x00, 0x02, 0x00]), seq_id=seq))
                    seq += 1

                    # 4. Row Packets
                    for r in rows:
                        row_bytes = bytearray()
                        for cell in r:
                            row_bytes.extend(lenenc_str(str(cell)))
                        writer.write(build_mysql_packet(bytes(row_bytes), seq_id=seq))
                        seq += 1

                    # 5. EOF Packet
                    writer.write(build_mysql_packet(bytes([0xFE, 0x00, 0x00, 0x02, 0x00]), seq_id=seq))
                    await writer.drain()

                    self.emit_telemetry({
                        "eventid": "db.query.enumeration" if is_enum else "db.query.execution",
                        "src_ip": src_ip,
                        "src_port": src_port,
                        "session_id": session_id,
                        "username": username,
                        "database": database,
                        "query": query_str,
                        "sub_protocol": "MySQL",
                    })

                else:
                    # Generic OK
                    writer.write(build_mysql_packet(bytes([0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00]), seq_id=cmd_seq + 1))
                    await writer.drain()

        except (asyncio.IncompleteReadError, ConnectionResetError):
            pass
        except Exception as exc:
            logger.debug("MySQL session %s error: %s", session_id, exc)
        finally:
            duration = round(time.time() - start_time, 2)
            self.emit_telemetry({
                "eventid": "db.session.disconnect",
                "src_ip": src_ip,
                "src_port": src_port,
                "session_id": session_id,
                "username": username,
                "duration_seconds": duration,
                "sub_protocol": "MySQL",
            })
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass
            logger.info("MySQL session %s disconnected (duration=%ss)", session_id, duration)

    async def start(self) -> None:
        """Start listening for incoming MySQL connections."""
        self._running = True
        self.server = await asyncio.start_server(self.handle_client, self.host, self.port)
        logger.info("MySQL Honeypot listening on %s:%d", self.host, self.port)

    async def stop(self) -> None:
        """Stop server."""
        self._running = False
        if self.server:
            self.server.close()
            await self.server.wait_closed()
            logger.info("MySQL Honeypot stopped.")
