"""Fictional Database Schema and Seed Data for Database Deception Service (db-001).

Imitates Apex Financial Group's relational database cluster (db-cluster.corp.internal:5432/3306).
Contains believable corporate financial records, customer accounts, and planted lateral breadcrumbs.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

DATABASES = [
    "corporate_finance",
    "employee_records",
    "customer_accounts",
    "payroll_2026",
    "transaction_history",
    "information_schema",
]

# Database -> Tables mapping
DATABASE_TABLES: Dict[str, List[str]] = {
    "corporate_finance": ["general_ledger", "budget_allocations", "quarterly_earnings", "tax_reserves"],
    "employee_records": ["personnel", "access_roster", "department_heads", "audit_logins"],
    "customer_accounts": ["clients", "invoices", "credit_limits", "settlement_accounts"],
    "payroll_2026": ["executive_compensation", "direct_deposits", "withholdings_summary"],
    "transaction_history": ["wire_transfers", "ach_batches", "interbank_settlements"],
    "information_schema": ["schemata", "tables", "columns"],
}

# Table Schema Definitions: (column_name, type_name)
TABLE_SCHEMAS: Dict[str, List[Tuple[str, str]]] = {
    "general_ledger": [
        ("entry_id", "INTEGER"),
        ("account_code", "VARCHAR(32)"),
        ("description", "VARCHAR(255)"),
        ("debit", "NUMERIC(14,2)"),
        ("credit", "NUMERIC(14,2)"),
        ("posted_date", "DATE"),
        ("auditor", "VARCHAR(64)"),
    ],
    "clients": [
        ("client_id", "VARCHAR(16)"),
        ("company_name", "VARCHAR(128)"),
        ("account_tier", "VARCHAR(32)"),
        ("primary_contact", "VARCHAR(64)"),
        ("billing_email", "VARCHAR(128)"),
        ("current_balance", "NUMERIC(14,2)"),
        ("assigned_gateway", "VARCHAR(64)"),
    ],
    "personnel": [
        ("emp_id", "VARCHAR(16)"),
        ("full_name", "VARCHAR(64)"),
        ("department", "VARCHAR(64)"),
        ("title", "VARCHAR(64)"),
        ("corporate_email", "VARCHAR(128)"),
        ("status", "VARCHAR(16)"),
    ],
    "executive_compensation": [
        ("record_id", "INTEGER"),
        ("executive_name", "VARCHAR(64)"),
        ("designation", "VARCHAR(64)"),
        ("annual_base", "NUMERIC(14,2)"),
        ("bonus_incentive", "NUMERIC(14,2)"),
        ("disbursement_account", "VARCHAR(64)"),
    ],
    "wire_transfers": [
        ("transfer_id", "VARCHAR(32)"),
        ("source_node", "VARCHAR(64)"),
        ("beneficiary_bank", "VARCHAR(128)"),
        ("amount", "NUMERIC(14,2)"),
        ("currency", "VARCHAR(8)"),
        ("status", "VARCHAR(16)"),
        ("auth_operator", "VARCHAR(64)"),
    ],
}

# Table Rows Data
TABLE_DATA: Dict[str, List[List[Any]]] = {
    "general_ledger": [
        [101, "GL-4010-REV", "Enterprise Retainer Billing - Q4", 0.00, 14250000.00, "2026-10-31", "finance_admin"],
        [102, "GL-5020-OPS", "Cloud & Colocation Infrastructure Hosting", 845000.00, 0.00, "2026-11-01", "finance_admin"],
        [103, "GL-5040-SEC", "Offsite Data Archival & Backup Replication", 124500.00, 0.00, "2026-11-05", "backup_user"],
        [104, "GL-6010-PAY", "Corporate Payroll Monthly Settlement", 2150000.00, 0.00, "2026-11-10", "database_root"],
    ],
    "clients": [
        ["CUST-2001", "Apex Global Logistics", "Enterprise", "Arthur Pendelton", "billing@apex-global.com", 250000.00, "finance-server.corp.internal"],
        ["CUST-2002", "Vanguard Health Systems", "Enterprise", "Dr. Marcus Brody", "finance@vanguard-health.org", 500000.00, "Corp-Storage-Node-02"],
        ["CUST-2003", "Northstar Financial Tech", "Strategic", "Elena Rostova", "accounts@northstar-fin.com", 150000.00, "web-admin.corp.internal"],
        ["CUST-2004", "Quantum Energy Partners", "Commercial", "Gregory Hayes", "ap@quantum-energy.net", 75000.00, "db-cluster.corp.internal"],
    ],
    "personnel": [
        ["EMP-1001", "John Doe", "Finance & Accounting", "Senior Financial Analyst", "jdoe@apexfinancial.corp", "Active"],
        ["EMP-1002", "Jane Smith", "Engineering & DevOps", "Lead Systems Architect", "jsmith@apexfinancial.corp", "Active"],
        ["EMP-1003", "Robert Johnson", "Executive Leadership", "Chief Financial Officer", "rjohnson@apexfinancial.corp", "Active"],
        ["EMP-1004", "Alice Williams", "Information Security", "SecOps Specialist", "awilliams@apexfinancial.corp", "Active"],
        ["EMP-1007", "David Wilson", "Database Systems", "Database Administrator", "dwilson@apexfinancial.corp", "Active"],
    ],
    "executive_compensation": [
        [1, "Robert Johnson", "Chief Financial Officer", 450000.00, 225000.00, "US-CHASE-****4918"],
        [2, "Eleanor Vance", "Chief Executive Officer", 680000.00, 410000.00, "US-BOA-****8821"],
        [3, "Marcus Brody", "Chief Technology Officer", 420000.00, 195000.00, "US-WELLS-****3014"],
    ],
    "wire_transfers": [
        ["WT-2026-9901", "finance-server.corp.internal", "Federal Reserve Settlement Bank", 4250000.00, "USD", "COMPLETED", "finance_admin"],
        ["WT-2026-9902", "web-admin.corp.internal", "Deutsche Clearing House", 1850000.00, "EUR", "COMPLETED", "admin"],
        ["WT-2026-9903", "db-cluster.corp.internal", "Swiss National Escrow", 3100000.00, "CHF", "PENDING", "database_root"],
    ],
}


def get_query_result(query: str, current_db: str = "corporate_finance") -> Tuple[List[str], List[List[Any]]]:
    """Simulate SQL execution and return (columns, rows).
    
    Guarantees 100% isolation: does not execute any command on host.
    """
    q = query.strip().rstrip(";").lower()

    # SHOW DATABASES / \l
    if "show databases" in q or "show schemas" in q or "pg_database" in q:
        cols = ["Database"]
        rows = [[d] for d in DATABASES]
        return cols, rows

    # SHOW TABLES / \dt
    if "show tables" in q or "information_schema.tables" in q or "pg_tables" in q:
        tables = DATABASE_TABLES.get(current_db, ["general_ledger", "clients", "personnel"])
        cols = [f"Tables_in_{current_db}"]
        rows = [[t] for t in tables]
        return cols, rows

    # SELECT version() / @@version
    if "version" in q:
        cols = ["version"]
        rows = [["PostgreSQL 15.4 (Debian 15.4-1.pgdg110+1) / MySQL 8.0.35-Apex-Cluster on x86_64"]]
        return cols, rows

    # Table matching
    for tbl, cols_spec in TABLE_SCHEMAS.items():
        if tbl in q:
            columns = [c[0] for c in cols_spec]
            rows = TABLE_DATA.get(tbl, [])
            return columns, rows

    # Default fallback response
    return ["status", "response"], [["OK", "Query parsed successfully. 0 rows affected."]]

