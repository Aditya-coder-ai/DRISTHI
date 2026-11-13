"""Virtual Filesystem (VFS) for FTP Deception Service.

Provides complete filesystem isolation by serving files exclusively from
a sandboxed in-memory / decoy directory tree. All paths are strictly validated
against a virtual root (/), preventing any directory traversal attacks (.. or drive letters)
from reaching the host operating system.
"""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
from pathlib import Path
import stat
import time
from typing import Dict, List, Optional, Tuple, Union


class VFSNode:
    """Base class for virtual filesystem nodes."""

    def __init__(self, name: str, mtime: Optional[float] = None):
        self.name = name
        self.mtime = mtime or time.time()

    @property
    def is_dir(self) -> bool:
        return False


class VFSFile(VFSNode):
    """Virtual file containing decoy data."""

    def __init__(
        self,
        name: str,
        size: int,
        content: Optional[bytes] = None,
        backing_path: Optional[Path] = None,
        mtime: Optional[float] = None,
    ):
        super().__init__(name, mtime)
        self.size = size
        self._content = content
        self.backing_path = backing_path

    def read_bytes(self) -> bytes:
        if self._content is not None:
            return self._content
        if self.backing_path and self.backing_path.exists():
            return self.backing_path.read_bytes()
        return b""

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.read_bytes()).hexdigest()


class VFSDirectory(VFSNode):
    """Virtual directory holding virtual children nodes."""

    def __init__(self, name: str, mtime: Optional[float] = None):
        super().__init__(name, mtime)
        self.children: Dict[str, Union[VFSFile, VFSDirectory]] = {}

    @property
    def is_dir(self) -> bool:
        return True


class VirtualFilesystem:
    """Strictly sandboxed Virtual Filesystem."""

    def __init__(self, decoy_root: Optional[Path] = None, uploads_dir: Optional[Path] = None):
        self.decoy_root = decoy_root
        self.uploads_dir = uploads_dir
        self.root = VFSDirectory("")
        if decoy_root and decoy_root.exists():
            self._load_decoy_tree(decoy_root, self.root)

    def _load_decoy_tree(self, host_dir: Path, vfs_dir: VFSDirectory) -> None:
        """Recursively mirror decoy files and directories into the virtual tree."""
        try:
            for item in host_dir.iterdir():
                if item.name.startswith("."):
                    continue
                if item.is_dir():
                    sub_dir = VFSDirectory(item.name, mtime=item.stat().st_mtime)
                    vfs_dir.children[item.name] = sub_dir
                    self._load_decoy_tree(item, sub_dir)
                elif item.is_file():
                    v_file = VFSFile(
                        name=item.name,
                        size=item.stat().st_size,
                        backing_path=item,
                        mtime=item.stat().st_mtime,
                    )
                    vfs_dir.children[item.name] = v_file
        except OSError:
            pass

    @staticmethod
    def resolve_path(cwd: str, target: str) -> str:
        """Sanitize and canonically resolve a virtual path.

        Prevents directory traversal attacks by clamping navigation to the virtual root (/).
        Guarantees returned path begins with '/' and contains no '..' or drive references.
        """
        # Normalize backslashes, eliminate null bytes
        cleaned = target.replace("\x00", "").replace("\\", "/")

        # Strip Windows drive letters (e.g. C:, D:)
        if len(cleaned) >= 2 and cleaned[1] == ":" and cleaned[0].isalpha():
            cleaned = cleaned[2:]

        # Absolute or relative to cwd
        if cleaned.startswith("/"):
            parts = [p for p in cleaned.split("/") if p]
        else:
            base_parts = [p for p in cwd.split("/") if p]
            parts = base_parts + [p for p in cleaned.split("/") if p]

        resolved_parts: List[str] = []
        for part in parts:
            if part == "." or not part:
                continue
            elif part == "..":
                if resolved_parts:
                    resolved_parts.pop()
            else:
                resolved_parts.append(part)

        return "/" + "/".join(resolved_parts)

    def get_node(self, path: str) -> Optional[Union[VFSFile, VFSDirectory]]:
        """Retrieve the node at the specified canonical path."""
        canonical = self.resolve_path("/", path)
        if canonical == "/":
            return self.root

        parts = [p for p in canonical.split("/") if p]
        curr: Union[VFSFile, VFSDirectory] = self.root
        for part in parts:
            if not curr.is_dir:
                return None
            assert isinstance(curr, VFSDirectory)
            if part not in curr.children:
                return None
            curr = curr.children[part]
        return curr

    def list_dir(self, path: str) -> Optional[List[Tuple[str, Union[VFSFile, VFSDirectory]]]]:
        """List contents of virtual directory as (name, node) tuples."""
        node = self.get_node(path)
        if not node or not node.is_dir:
            return None
        assert isinstance(node, VFSDirectory)
        return sorted(node.children.items(), key=lambda x: (not x[1].is_dir, x[0].lower()))

    def read_file(self, path: str) -> Optional[bytes]:
        """Read bytes of virtual file."""
        node = self.get_node(path)
        if not node or node.is_dir:
            return None
        assert isinstance(node, VFSFile)
        return node.read_bytes()

    def store_file(self, path: str, data: bytes) -> bool:
        """Store uploaded data into the virtual filesystem in a safe, isolated manner."""
        canonical = self.resolve_path("/", path)
        parent_path = "/" + "/".join([p for p in canonical.split("/") if p][:-1])
        filename = [p for p in canonical.split("/") if p][-1] if [p for p in canonical.split("/") if p] else ""
        if not filename:
            return False

        parent_node = self.get_node(parent_path)
        if not parent_node or not parent_node.is_dir:
            return False
        assert isinstance(parent_node, VFSDirectory)

        # Store in memory
        vfile = VFSFile(name=filename, size=len(data), content=data, mtime=time.time())
        parent_node.children[filename] = vfile

        # Optionally quarantine to disk in uploads directory
        if self.uploads_dir:
            try:
                self.uploads_dir.mkdir(parents=True, exist_ok=True)
                safe_name = f"{int(time.time())}_{hashlib.md5(filename.encode()).hexdigest()[:8]}_{filename}"
                (self.uploads_dir / safe_name).write_bytes(data)
            except OSError:
                pass

        return True

    @staticmethod
    def format_unix_listing(name: str, node: Union[VFSFile, VFSDirectory]) -> str:
        """Format an entry according to RFC 959 / standard Unix ls -la format."""
        dt = datetime.fromtimestamp(node.mtime, tz=timezone.utc)
        # Format: Nov 12 02:00 or Nov 12 2026
        date_str = dt.strftime("%b %d %H:%M")
        if node.is_dir:
            mode = "drwxr-xr-x"
            nlinks = 2
            size = 4096
        else:
            mode = "-rw-r--r--"
            nlinks = 1
            size = getattr(node, "size", len(getattr(node, "_content", b"") or b""))

        return f"{mode}  {nlinks:2d} ftp  backup_user  {size:8d} {date_str} {name}"
