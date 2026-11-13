"""Unit tests for FTP Virtual Filesystem (VFS) Security Isolation."""

from pathlib import Path
import pytest

from services.ftp.vfs import VirtualFilesystem, VFSFile, VFSDirectory
from shared.config import settings

PROJECT_ROOT = Path(__file__).resolve().parent.parent


def test_vfs_path_resolution_security():
    """Verify that path resolution strictly clamps to virtual root and prevents traversal."""
    # Test parent traversal clamping
    assert VirtualFilesystem.resolve_path("/", "../../../") == "/"
    assert VirtualFilesystem.resolve_path("/backups", "../../") == "/"
    assert VirtualFilesystem.resolve_path("/backups/finance", "../") == "/backups"

    # Test Windows drive letter stripping
    assert VirtualFilesystem.resolve_path("/", "C:\\Windows\\System32") == "/Windows/System32"
    assert VirtualFilesystem.resolve_path("/", "D:/confidential/file.txt") == "/confidential/file.txt"

    # Test backslash normalization
    assert VirtualFilesystem.resolve_path("/", "..\\..\\etc\\passwd") == "/etc/passwd"

    # Test null byte sanitization
    assert VirtualFilesystem.resolve_path("/", "file.txt\x00.png") == "/file.txt.png"


def test_vfs_host_filesystem_isolation():
    """Verify that unmapped host files cannot be accessed through the VFS."""
    vfs = VirtualFilesystem(decoy_root=settings.FTP_DECOY_DIR)

    # Attempt to access host files via traversal or absolute paths
    assert vfs.get_node("/etc/passwd") is None
    assert vfs.get_node("/Windows/win.ini") is None
    assert vfs.get_node("/Users") is None
    assert vfs.read_file("/etc/shadow") is None
    assert vfs.read_file("/Windows/System32/drivers/etc/hosts") is None


def test_vfs_decoy_tree_contents():
    """Verify that the decoy directory tree is accurately populated."""
    vfs = VirtualFilesystem(decoy_root=settings.FTP_DECOY_DIR)

    # Root listing
    root_items = vfs.list_dir("/")
    assert root_items is not None
    root_names = [name for name, _ in root_items]
    assert "backups" in root_names
    assert "corporate" in root_names
    assert "README.txt" in root_names

    # Check /backups/finance
    finance_items = vfs.list_dir("/backups/finance")
    assert finance_items is not None
    finance_names = [name for name, _ in finance_items]
    assert "customer_database.sql" in finance_names
    assert "backup.zip" in finance_names
    assert "db_migration_notes.txt" in finance_names

    # Check /corporate
    corp_items = vfs.list_dir("/corporate")
    assert corp_items is not None
    corp_names = [name for name, _ in corp_items]
    assert "employee_records.csv" in corp_names
    assert "financial_report.xlsx" in corp_names


def test_vfs_file_read_and_store():
    """Verify reading and writing decoy files in virtual storage."""
    vfs = VirtualFilesystem(decoy_root=settings.FTP_DECOY_DIR)

    sql_data = vfs.read_file("/backups/finance/customer_database.sql")
    assert sql_data is not None
    assert b"corp_finance_db" in sql_data

    # Test storing an upload in VFS
    test_content = b"echo 'simulated payload'"
    stored = vfs.store_file("/backups/finance/probe.sh", test_content)
    assert stored is True
    assert vfs.read_file("/backups/finance/probe.sh") == test_content

