"""Builds custom fs.pickle overlay for Cowrie SSH Honeypot.

Injects custom decoy directories and files (/home/finance_admin, /var/financial_data)
into Cowrie's virtual Linux filesystem so that simulated shell commands (ls, cat, cd)
properly see and open our bait assets.
"""

from __future__ import annotations

from pathlib import Path
import pickle
import time

from cowrie.core.resources import read_data_bytes
import cowrie.shell.fs as cfs

PROJECT_ROOT = Path(__file__).resolve().parent.parent
HONEYFS_DIR = PROJECT_ROOT / "services" / "ssh" / "honeyfs"
FS_PICKLE_OUT = PROJECT_ROOT / "services" / "ssh" / "fs.pickle"


def build_pickle():
    # Load base Debian/Ubuntu filesystem pickle bundled with Cowrie
    tree = pickle.loads(read_data_bytes("", "fs.pickle"))

    # 1. Inject /home/finance_admin and bait files
    home = next(x for x in tree[7] if x[0] == "home")

    # Remove existing finance_admin if already present
    home[7] = [x for x in home[7] if x[0] != "finance_admin"]

    notes_file = HONEYFS_DIR / "home" / "finance_admin" / "server_notes.txt"
    notes_bytes = notes_file.read_bytes() if notes_file.exists() else b""

    history_file = HONEYFS_DIR / "home" / "finance_admin" / ".bash_history"
    history_bytes = history_file.read_bytes() if history_file.exists() else b""

    now = time.time()
    finance_admin_dir = [
        "finance_admin",
        cfs.T_DIR,
        1001,
        1001,
        4096,
        16877,
        now,
        [
            ["server_notes.txt", cfs.T_FILE, 1001, 1001, len(notes_bytes), 33188, now, notes_bytes, str(notes_file.resolve()), None],
            [".bash_history", cfs.T_FILE, 1001, 1001, len(history_bytes), 33188, now, history_bytes, str(history_file.resolve()), None],
        ],
        None,
        None,
    ]
    home[7].append(finance_admin_dir)

    # 2. Inject /var/financial_data and payroll summary
    var = next(x for x in tree[7] if x[0] == "var")
    var[7] = [x for x in var[7] if x[0] != "financial_data"]

    fin_file = HONEYFS_DIR / "var" / "financial_data" / "Q4_payroll_summary.csv"
    fin_bytes = fin_file.read_bytes() if fin_file.exists() else b""

    fin_dir = [
        "financial_data",
        cfs.T_DIR,
        1001,
        1001,
        4096,
        16877,
        now,
        [
            ["Q4_payroll_summary.csv", cfs.T_FILE, 1001, 1001, len(fin_bytes), 33188, now, fin_bytes, str(fin_file.resolve()), None]
        ],
        None,
        None,
    ]
    var[7].append(fin_dir)

    # Write out modified pickle
    FS_PICKLE_OUT.parent.mkdir(parents=True, exist_ok=True)
    with open(FS_PICKLE_OUT, "wb") as f:
        pickle.dump(tree, f)

    print(f"Custom fs.pickle created successfully at: {FS_PICKLE_OUT} ({FS_PICKLE_OUT.stat().st_size} bytes)")


if __name__ == "__main__":
    build_pickle()
