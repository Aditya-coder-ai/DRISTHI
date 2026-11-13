"""Generates binary decoy assets (backup.zip and financial_report.xlsx)."""

import zipfile
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent

def generate_binaries():
    # 1. backup.zip
    zip_path = PROJECT_ROOT / "services" / "ftp" / "decoy_root" / "backups" / "finance" / "backup.zip"
    zip_path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as z:
        manifest = (
            '{\n'
            '  "archive_id": "BKP-2026-11-12-001",\n'
            '  "system": "finance-server.corp.internal",\n'
            '  "timestamp": "2026-11-12T02:00:00Z",\n'
            '  "encrypted": false,\n'
            '  "contents": ["customer_database.sql", "payroll_tables.dump"]\n'
            '}'
        )
        z.writestr("backup_manifest.json", manifest)
        sql_snap = (
            "-- Schema snapshot for corp_finance_db\n"
            "CREATE TABLE employees (id INT PRIMARY KEY, name VARCHAR(100), salary DECIMAL(10,2));\n"
            "CREATE TABLE customers (id INT PRIMARY KEY, name VARCHAR(100), balance DECIMAL(10,2));\n"
            "CREATE TABLE transactions (id INT PRIMARY KEY, amount DECIMAL(10,2), status VARCHAR(20));\n"
        )
        z.writestr("schema_snapshot.sql", sql_snap)
    print(f"Created backup.zip at {zip_path} ({zip_path.stat().st_size} bytes)")

    # 2. financial_report.xlsx
    xlsx_path = PROJECT_ROOT / "services" / "ftp" / "decoy_root" / "corporate" / "financial_report.xlsx"
    xlsx_path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(xlsx_path, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr(
            "[Content_Types].xml",
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
            '<Default Extension="xml" ContentType="application/xml"/>'
            '</Types>'
        )
        z.writestr(
            "_rels/.rels",
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"/>'
        )
        z.writestr(
            "xl/workbook.xml",
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
            '<sheets><sheet name="Q4_Financials" sheetId="1" r:id="rId1"/></sheets>'
            '</workbook>'
        )
        sheet_data = (
            "Q4 Fiscal Financial Summary - Corp Internal\n"
            "Total Revenue: $14,250,000.00\n"
            "Operating Expenses: $8,920,000.00\n"
            "Net Margin: $5,330,000.00\n"
            "Approved by CFO Robert Johnson\n"
        )
        z.writestr("xl/worksheets/sheet1.xml", sheet_data)
    print(f"Created financial_report.xlsx at {xlsx_path} ({xlsx_path.stat().st_size} bytes)")

if __name__ == "__main__":
    generate_binaries()

