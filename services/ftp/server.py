"""Asynchronous RFC 959 FTP Honeypot Service.

Simulates an enterprise backup file server (backup-storage.corp.internal).
Provides full passive-mode data transfer (LIST, RETR, STOR), user authentication,
HoneyFS virtual filesystem isolation, and structured event logging.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import time
from typing import Any, Dict, Optional, Tuple

from services.ftp.vfs import VirtualFilesystem
from services.ftp.ftp_event_adapter import FTPEventAdapter
from collector.normalizer import EventNormalizer
from collector.event_collector import global_collector
from shared.config import settings
from shared.logger import get_logger

logger = get_logger("FTPServer")


class FTPClientSession:
    """State management for an individual connected FTP client."""

    def __init__(self, session_id: str, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, vfs: VirtualFilesystem, config: Dict[str, Any]):
        self.session_id = session_id
        self.reader = reader
        self.writer = writer
        self.vfs = vfs
        self.config = config

        peer = writer.get_extra_info("peername")
        self.src_ip = peer[0] if peer else "127.0.0.1"
        self.src_port = peer[1] if peer else 0

        self.start_time = time.time()
        self.authenticated = False
        self.username: Optional[str] = None
        self.is_bait = False
        self.cwd = "/"
        self.commands_processed = 0

        # Passive mode state
        self.pasv_server: Optional[asyncio.Server] = None
        self.pasv_port: Optional[int] = None
        self.pasv_conn_future: Optional[asyncio.Future[Tuple[asyncio.StreamReader, asyncio.StreamWriter]]] = None

    def send_line(self, line: str) -> None:
        """Send an RFC 959 response line terminated by CRLF."""
        if not self.writer.is_closing():
            self.writer.write(f"{line}\r\n".encode("utf-8"))

    async def flush(self) -> None:
        if not self.writer.is_closing():
            await self.writer.drain()


class FTPServer:
    """Controlled, Isolated FTP Deception Server."""

    def __init__(
        self,
        host: str = settings.FTP_LISTEN_HOST,
        port: int = settings.FTP_LISTEN_PORT,
        config_path: Optional[Path] = None,
        decoy_root: Optional[Path] = None,
        log_file: Optional[Path] = None,
    ):
        self.host = host
        self.port = port
        self.config_path = config_path or settings.FTP_CONFIG_FILE
        self.decoy_root = decoy_root or settings.FTP_DECOY_DIR
        self.log_file = log_file or settings.FTP_JSON_LOG

        self.config = self._load_config()
        self.vfs = VirtualFilesystem(
            decoy_root=self.decoy_root,
            uploads_dir=settings.FTP_BASE_DIR / "uploads",
        )
        self.server: Optional[asyncio.Server] = None
        self.running = False

    def _load_config(self) -> Dict[str, Any]:
        if self.config_path and self.config_path.exists():
            try:
                with open(self.config_path, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception as exc:
                logger.error("Failed to load FTP config: %s", exc)
        return {
            "asset_id": "ftp-001",
            "server_name": "Corp-Storage-Node-02",
            "banner": "220 Corp-Storage-Node-02 FTP Backup Gateway (v4.2.1) ready.",
            "allow_anonymous": False,
            "users": {
                "backup_user": {
                    "password": "Backup@2026",
                    "is_bait": True,
                    "home_dir": "/backups/finance",
                }
            },
        }

    def emit_event(self, raw_event: Dict[str, Any]) -> None:
        """Write raw event to log and normalize into global collector."""
        raw_event["asset_id"] = self.config.get("asset_id", "ftp-001")
        raw_event["server_name"] = self.config.get("server_name", "Corp-Storage-Node-02")
        if "timestamp" not in raw_event:
            raw_event["timestamp"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

        # 1. Append to local JSON log
        if self.log_file:
            try:
                self.log_file.parent.mkdir(parents=True, exist_ok=True)
                with open(self.log_file, "a", encoding="utf-8") as f:
                    f.write(json.dumps(raw_event) + "\n")
            except OSError as err:
                logger.error("Failed to append FTP event log: %s", err)

        # 2. Normalize and push to global collector
        normalized = EventNormalizer.normalize(raw_event, protocol="FTP", asset_id=raw_event["asset_id"])
        if normalized:
            global_collector.collect(normalized)

    async def handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        """Handle control connection lifecycle for a single FTP client."""
        session_id = hashlib.md5(f"{time.time()}_{writer.get_extra_info('peername')}".encode()).hexdigest()[:12]
        session = FTPClientSession(session_id, reader, writer, self.vfs, self.config)

        # Log session connect
        self.emit_event({
            "eventid": "ftp.session.connect",
            "session_id": session.session_id,
            "src_ip": session.src_ip,
            "src_port": session.src_port,
        })

        banner = self.config.get("banner", "220 Corp-Storage-Node-02 FTP Backup Gateway (v4.2.1) ready.")
        session.send_line(banner)
        await session.flush()

        try:
            while not reader.at_eof() and not writer.is_closing():
                line_bytes = await reader.readline()
                if not line_bytes:
                    break

                line = line_bytes.decode("utf-8", errors="replace").strip("\r\n")
                if not line:
                    continue

                session.commands_processed += 1
                parts = line.split(" ", 1)
                cmd = parts[0].upper()
                arg = parts[1].strip() if len(parts) > 1 else ""

                should_continue = await self._dispatch_command(session, cmd, arg)
                await session.flush()
                if not should_continue:
                    break
        except Exception as exc:
            logger.debug("Session %s connection error: %s", session.session_id, exc)
        finally:
            self._cleanup_pasv(session)
            if not writer.is_closing():
                try:
                    writer.close()
                    await writer.wait_closed()
                except Exception:
                    pass

            duration = round(time.time() - session.start_time, 2)
            self.emit_event({
                "eventid": "ftp.session.closed",
                "session_id": session.session_id,
                "src_ip": session.src_ip,
                "src_port": session.src_port,
                "username": session.username,
                "duration_seconds": duration,
                "commands_processed": session.commands_processed,
            })

    def _cleanup_pasv(self, session: FTPClientSession) -> None:
        if session.pasv_server:
            try:
                session.pasv_server.close()
            except Exception:
                pass
            session.pasv_server = None
            session.pasv_port = None
        session.pasv_conn_future = None

    async def _setup_passive_mode(self, session: FTPClientSession) -> int:
        """Initialize a dynamic listening socket for passive data transfer."""
        self._cleanup_pasv(session)
        loop = asyncio.get_running_loop()
        session.pasv_conn_future = loop.create_future()

        def on_data_connection(d_reader: asyncio.StreamReader, d_writer: asyncio.StreamWriter):
            if session.pasv_conn_future and not session.pasv_conn_future.done():
                session.pasv_conn_future.set_result((d_reader, d_writer))

        # Bind to loopback or interface with ephemeral port
        pasv_srv = await asyncio.start_server(on_data_connection, host="0.0.0.0", port=0)
        session.pasv_server = pasv_srv
        session.pasv_port = pasv_srv.sockets[0].getsockname()[1]
        return session.pasv_port

    async def _dispatch_command(self, session: FTPClientSession, cmd: str, arg: str) -> bool:
        """Process an individual FTP command according to RFC 959."""

        # 1. USER
        if cmd == "USER":
            session.username = arg
            if arg.lower() == "anonymous" and self.config.get("allow_anonymous", False):
                session.authenticated = True
                session.cwd = "/"
                session.send_line("230 Guest login ok, access restrictions apply.")
                self.emit_event({
                    "eventid": "ftp.login.success",
                    "session_id": session.session_id,
                    "src_ip": session.src_ip,
                    "src_port": session.src_port,
                    "username": "anonymous",
                })
            else:
                session.send_line(f"331 Password required for {arg}.")
            return True

        # 2. PASS
        elif cmd == "PASS":
            user = session.username or ""
            users_cfg = self.config.get("users", {})
            user_info = users_cfg.get(user)

            if user_info and user_info.get("password") == arg:
                session.authenticated = True
                session.is_bait = bool(user_info.get("is_bait", False))
                session.cwd = user_info.get("home_dir", "/")
                session.send_line("230 User logged in, proceed.")
                self.emit_event({
                    "eventid": "ftp.login.success",
                    "session_id": session.session_id,
                    "src_ip": session.src_ip,
                    "src_port": session.src_port,
                    "username": user,
                })
            else:
                session.authenticated = False
                session.send_line("530 Login incorrect.")
                self.emit_event({
                    "eventid": "ftp.login.failed",
                    "session_id": session.session_id,
                    "src_ip": session.src_ip,
                    "src_port": session.src_port,
                    "username": user,
                    "password_length": len(arg),
                })
            return True

        # 3. QUIT
        elif cmd == "QUIT":
            session.send_line("221 Goodbye.")
            return False

        # 4. SYST & FEAT (Allowed pre-login by modern clients)
        elif cmd == "SYST":
            session.send_line("215 UNIX Type: L8")
            return True

        elif cmd == "FEAT":
            session.send_line("211-Features:\r\n PASV\r\n EPSV\r\n SIZE\r\n UTF8\r\n211 End")
            return True

        elif cmd == "NOOP":
            session.send_line("200 NOOP ok.")
            return True

        # Enforce authentication requirement
        if not session.authenticated:
            session.send_line("530 Please login with USER and PASS.")
            self.emit_event({
                "eventid": "ftp.suspicious.request",
                "session_id": session.session_id,
                "src_ip": session.src_ip,
                "command": cmd,
                "argument": arg,
                "reason": "Unauthenticated command execution attempt",
            })
            return True

        # 5. PWD / XPWD
        if cmd in ("PWD", "XPWD"):
            session.send_line(f'257 "{session.cwd}" is current directory.')
            return True

        # 6. CWD / XCWD
        elif cmd in ("CWD", "XCWD"):
            target_virtual = self.vfs.resolve_path(session.cwd, arg)
            node = self.vfs.get_node(target_virtual)

            # Detect directory traversal attempts
            if ".." in arg or ":\\" in arg or ":/" in arg:
                self.emit_event({
                    "eventid": "ftp.suspicious.request",
                    "session_id": session.session_id,
                    "src_ip": session.src_ip,
                    "username": session.username,
                    "command": cmd,
                    "argument": arg,
                    "reason": "Directory traversal attempt detected",
                })

            if node and node.is_dir:
                session.cwd = target_virtual
                session.send_line(f"250 Directory successfully changed to {session.cwd}")
            else:
                session.send_line(f"550 Failed to change directory: {arg}: No such directory.")
            return True

        # 7. CDUP / XCUP
        elif cmd in ("CDUP", "XCUP"):
            session.cwd = self.vfs.resolve_path(session.cwd, "..")
            session.send_line(f"250 Directory successfully changed to {session.cwd}")
            return True

        # 8. TYPE
        elif cmd == "TYPE":
            t_arg = arg.upper()
            if t_arg in ("A", "I"):
                session.send_line(f"200 Type set to {t_arg}.")
            else:
                session.send_line("504 Unsupported type.")
            return True

        # 9. PASV
        elif cmd == "PASV":
            port = await self._setup_passive_mode(session)
            # Advertise 127.0.0.1 for local clients, or server listen host
            host_ip = "127.0.0.1" if session.src_ip.startswith("127.") else self.host
            if host_ip == "0.0.0.0":
                host_ip = "127.0.0.1"
            h_parts = host_ip.split(".")
            p1, p2 = divmod(port, 256)
            session.send_line(f"227 Entering Passive Mode ({h_parts[0]},{h_parts[1]},{h_parts[2]},{h_parts[3]},{p1},{p2}).")
            return True

        # 10. EPSV
        elif cmd == "EPSV":
            port = await self._setup_passive_mode(session)
            session.send_line(f"229 Entering Extended Passive Mode (|||{port}|)")
            return True

        # 11. SIZE
        elif cmd == "SIZE":
            target = self.vfs.resolve_path(session.cwd, arg)
            node = self.vfs.get_node(target)
            if node and not node.is_dir:
                session.send_line(f"213 {getattr(node, 'size', 0)}")
            else:
                session.send_line("550 File not found.")
            return True

        # 12. LIST / NLST
        elif cmd in ("LIST", "NLST"):
            target_path = self.vfs.resolve_path(session.cwd, arg) if arg and not arg.startswith("-") else session.cwd
            items = self.vfs.list_dir(target_path)

            self.emit_event({
                "eventid": "ftp.directory.list",
                "session_id": session.session_id,
                "src_ip": session.src_ip,
                "src_port": session.src_port,
                "username": session.username,
                "path": target_path,
            })

            if items is None:
                session.send_line("550 Directory not found.")
                self._cleanup_pasv(session)
                return True

            if not session.pasv_conn_future:
                session.send_line("425 Use PASV or EPSV first.")
                return True

            session.send_line("150 Here comes the directory listing.")
            await session.flush()

            try:
                d_reader, d_writer = await asyncio.wait_for(session.pasv_conn_future, timeout=10.0)
                listing_lines = []
                for name, node in items:
                    if cmd == "LIST":
                        listing_lines.append(self.vfs.format_unix_listing(name, node))
                    else:
                        listing_lines.append(name)

                data_str = "\r\n".join(listing_lines) + ("\r\n" if listing_lines else "")
                d_writer.write(data_str.encode("utf-8"))
                await d_writer.drain()
                d_writer.close()
                await d_writer.wait_closed()
                session.send_line("226 Directory send OK.")
            except asyncio.TimeoutError:
                session.send_line("425 Data connection timed out.")
            finally:
                self._cleanup_pasv(session)
            return True

        # 13. RETR
        elif cmd == "RETR":
            target = self.vfs.resolve_path(session.cwd, arg)
            file_bytes = self.vfs.read_file(target)

            if ".." in arg or ":\\" in arg or ":/" in arg:
                self.emit_event({
                    "eventid": "ftp.suspicious.request",
                    "session_id": session.session_id,
                    "src_ip": session.src_ip,
                    "username": session.username,
                    "command": cmd,
                    "argument": arg,
                    "reason": "Path traversal file access attempt",
                })

            if file_bytes is None:
                session.send_line(f"550 File not found: {arg}")
                self._cleanup_pasv(session)
                return True

            if not session.pasv_conn_future:
                session.send_line("425 Use PASV or EPSV first.")
                return True

            session.send_line(f"150 Opening BINARY mode data connection for {arg} ({len(file_bytes)} bytes).")
            await session.flush()

            try:
                d_reader, d_writer = await asyncio.wait_for(session.pasv_conn_future, timeout=10.0)
                d_writer.write(file_bytes)
                await d_writer.drain()
                d_writer.close()
                await d_writer.wait_closed()
                session.send_line("226 Transfer complete.")

                self.emit_event({
                    "eventid": "ftp.file.download",
                    "session_id": session.session_id,
                    "src_ip": session.src_ip,
                    "src_port": session.src_port,
                    "username": session.username,
                    "path": target,
                    "filename": Path(target).name,
                    "bytes_transferred": len(file_bytes),
                })
            except asyncio.TimeoutError:
                session.send_line("425 Data connection timed out.")
            finally:
                self._cleanup_pasv(session)
            return True

        # 14. STOR
        elif cmd == "STOR":
            target = self.vfs.resolve_path(session.cwd, arg)
            if not session.pasv_conn_future:
                session.send_line("425 Use PASV or EPSV first.")
                return True

            session.send_line(f"150 Ok to send data for {arg}.")
            await session.flush()

            try:
                d_reader, d_writer = await asyncio.wait_for(session.pasv_conn_future, timeout=10.0)
                incoming_chunks = []
                while not d_reader.at_eof():
                    chunk = await d_reader.read(8192)
                    if not chunk:
                        break
                    incoming_chunks.append(chunk)

                d_writer.close()
                await d_writer.wait_closed()

                uploaded_data = b"".join(incoming_chunks)
                stored = self.vfs.store_file(target, uploaded_data)

                if stored:
                    session.send_line("226 Transfer complete.")
                    self.emit_event({
                        "eventid": "ftp.file.upload",
                        "session_id": session.session_id,
                        "src_ip": session.src_ip,
                        "src_port": session.src_port,
                        "username": session.username,
                        "path": target,
                        "filename": Path(target).name,
                        "bytes_transferred": len(uploaded_data),
                        "sha256": hashlib.sha256(uploaded_data).hexdigest(),
                    })
                else:
                    session.send_line("553 Could not create file.")
            except asyncio.TimeoutError:
                session.send_line("425 Data connection timed out.")
            finally:
                self._cleanup_pasv(session)
            return True

        # 15. DELE, RMD, MKD (Restricted / Read-only Honeypot Protection)
        elif cmd in ("DELE", "RMD", "MKD"):
            session.send_line("550 Permission denied: Read-only backup archive.")
            self.emit_event({
                "eventid": "ftp.suspicious.request",
                "session_id": session.session_id,
                "src_ip": session.src_ip,
                "username": session.username,
                "command": cmd,
                "argument": arg,
                "reason": "Attempted file deletion or directory modification",
            })
            return True

        # Unknown / Unimplemented
        session.send_line(f"502 Command not implemented: {cmd}")
        return True

    async def start(self) -> None:
        """Start listening for FTP connections."""
        self.server = await asyncio.start_server(
            self.handle_client,
            host=self.host,
            port=self.port,
        )
        self.running = True
        logger.info("FTP Deception Server listening on %s:%d (Asset: %s)", self.host, self.port, self.config.get("asset_id"))

    async def stop(self) -> None:
        """Stop the FTP server."""
        if self.server:
            self.server.close()
            await self.server.wait_closed()
        self.running = False
        logger.info("FTP Deception Server stopped.")

    async def serve_forever(self) -> None:
        """Run the server until interrupted."""
        await self.start()
        try:
            async with self.server:
                await self.server.serve_forever()
        except (asyncio.CancelledError, Exception):
            pass
