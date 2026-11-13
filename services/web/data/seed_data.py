"""Seed business data and decoy configurations for Apex Financial Group Admin Portal."""

from __future__ import annotations

from typing import Any, Dict, List

COMPANY_NAME = "Apex Financial Group"
PORTAL_TITLE = "Apex Internal Management System"

EMPLOYEES: List[Dict[str, Any]] = [
    {
        "id": "EMP-1001",
        "name": "John Doe",
        "department": "Finance & Accounting",
        "designation": "Senior Financial Analyst",
        "email": "jdoe@apexfinancial.corp",
        "status": "Active",
        "joined": "2021-03-15",
    },
    {
        "id": "EMP-1002",
        "name": "Jane Smith",
        "department": "Engineering & DevOps",
        "designation": "Lead Systems Architect",
        "email": "jsmith@apexfinancial.corp",
        "status": "Active",
        "joined": "2019-07-01",
    },
    {
        "id": "EMP-1003",
        "name": "Robert Johnson",
        "department": "Executive Leadership",
        "designation": "Chief Financial Officer",
        "email": "rjohnson@apexfinancial.corp",
        "status": "Active",
        "joined": "2017-01-10",
    },
    {
        "id": "EMP-1004",
        "name": "Alice Williams",
        "department": "Information Security",
        "designation": "SecOps Specialist",
        "email": "awilliams@apexfinancial.corp",
        "status": "Active",
        "joined": "2022-11-20",
    },
    {
        "id": "EMP-1005",
        "name": "Michael Brown",
        "department": "Finance & Accounting",
        "designation": "Payroll Clerk",
        "email": "mbrown@apexfinancial.corp",
        "status": "Active",
        "joined": "2023-05-18",
    },
    {
        "id": "EMP-1006",
        "name": "Sarah Davis",
        "department": "Human Resources",
        "designation": "VP People Operations",
        "email": "sdavis@apexfinancial.corp",
        "status": "Active",
        "joined": "2018-09-12",
    },
    {
        "id": "EMP-1007",
        "name": "David Wilson",
        "department": "Database Systems",
        "designation": "Database Administrator",
        "email": "dwilson@apexfinancial.corp",
        "status": "Active",
        "joined": "2020-02-01",
    },
]

CUSTOMERS: List[Dict[str, Any]] = [
    {
        "id": "CUST-2001",
        "name": "Apex Global Logistics",
        "tier": "Enterprise",
        "email": "billing@apex-global.com",
        "balance": 250000.00,
        "tax_id": "US-EIN-9481920",
        "status": "Good Standing",
    },
    {
        "id": "CUST-2002",
        "name": "Vanguard Health Systems",
        "tier": "Enterprise",
        "email": "finance@vanguard-health.org",
        "balance": 500000.00,
        "tax_id": "US-EIN-8820194",
        "status": "Good Standing",
    },
    {
        "id": "CUST-2003",
        "name": "Northstar Financial Tech",
        "tier": "Strategic",
        "email": "accounts@northstar-fin.com",
        "balance": 150000.00,
        "tax_id": "US-EIN-7729103",
        "status": "Review Required",
    },
    {
        "id": "CUST-2004",
        "name": "Quantum Energy Partners",
        "tier": "Commercial",
        "email": "ap@quantum-energy.net",
        "balance": 75000.00,
        "tax_id": "US-EIN-6629184",
        "status": "Good Standing",
    },
    {
        "id": "CUST-2005",
        "name": "Horizon Media Networks",
        "tier": "Strategic",
        "email": "accounting@horizon-media.tv",
        "balance": 120000.00,
        "tax_id": "US-EIN-5520194",
        "status": "Pending Renewal",
    },
]

INVOICES: List[Dict[str, Any]] = [
    {
        "id": "INV-2026-001",
        "customer": "Apex Global Logistics",
        "amount": "$124,500.00",
        "status": "Paid",
        "date": "2026-10-31",
    },
    {
        "id": "INV-2026-002",
        "customer": "Vanguard Health Systems",
        "amount": "$289,000.00",
        "status": "Pending",
        "date": "2026-11-15",
    },
    {
        "id": "INV-2026-003",
        "customer": "Northstar Financial Tech",
        "amount": "$45,000.00",
        "status": "Paid",
        "date": "2026-11-20",
    },
    {
        "id": "INV-2026-004",
        "customer": "Quantum Energy Partners",
        "amount": "$18,700.00",
        "status": "Overdue",
        "date": "2026-10-15",
    },
    {
        "id": "INV-2026-005",
        "customer": "Horizon Media Networks",
        "amount": "$67,000.00",
        "status": "Pending",
        "date": "2026-12-01",
    },
]

RECENT_ACTIVITIES: List[Dict[str, str]] = [
    {
        "timestamp": "2026-11-13 09:20 UTC",
        "event": "Nightly offsite backup completed",
        "node": "backup-storage (10.0.1.30:2121)",
        "user": "backup_user",
    },
    {
        "timestamp": "2026-11-13 08:45 UTC",
        "event": "Database replication health verify (OK)",
        "node": "db-cluster (10.0.1.25:5432)",
        "user": "system",
    },
    {
        "timestamp": "2026-11-13 07:15 UTC",
        "event": "SSH secure shell audit logged",
        "node": "finance-server (10.0.1.15:2222)",
        "user": "finance_admin",
    },
    {
        "timestamp": "2026-11-13 06:30 UTC",
        "event": "Admin Portal session authenticated",
        "node": "web-admin (10.0.1.20:8080)",
        "user": "admin",
    },
]

SYSTEM_NODES: List[Dict[str, str]] = [
    {
        "name": "Finance Production Gateway",
        "hostname": "finance-server.corp.internal",
        "ip": "10.0.1.15:2222",
        "service": "SSH / SFTP",
        "status": "ONLINE",
    },
    {
        "name": "Offsite Backup Storage",
        "hostname": "backup-storage.corp.internal",
        "ip": "10.0.1.30:2121",
        "service": "FTP / TLS",
        "status": "ONLINE",
    },
    {
        "name": "Primary Relational Cluster",
        "hostname": "db-cluster.corp.internal",
        "ip": "10.0.1.25:5432",
        "service": "PostgreSQL / MySQL",
        "status": "ONLINE",
    },
    {
        "name": "Internal Management Portal",
        "hostname": "web-admin.corp.internal",
        "ip": "10.0.1.20:8080",
        "service": "FastAPI Web App",
        "status": "ONLINE",
    },
]

DECOY_CONFIGURATIONS: Dict[str, Dict[str, Any]] = {
    "database_config.json": {
        "content_type": "application/json",
        "description": "Production database cluster connection profile",
        "raw": (
            '{\n'
            '  "database_cluster": {\n'
            '    "host": "10.0.1.25",\n'
            '    "port": 5432,\n'
            '    "database": "corp_finance_db",\n'
            '    "primary_user": "database_root",\n'
            '    "password": "DBroot@2026",\n'
            '    "ssl_mode": "require",\n'
            '    "pool_size": 25,\n'
            '    "max_overflow": 10\n'
            '  }\n'
            '}'
        ),
        "bait_user": "database_root",
        "bait_pass": "DBroot@2026",
    },
    "backup_config.json": {
        "content_type": "application/json",
        "description": "Automated offsite backup daemon synchronization configuration",
        "raw": (
            '{\n'
            '  "offsite_backup": {\n'
            '    "service_url": "ftp://10.0.1.30:2121",\n'
            '    "auth_user": "backup_user",\n'
            '    "auth_token": "Backup@2026",\n'
            '    "retention_days": 30,\n'
            '    "target_directory": "/backups/finance",\n'
            '    "schedule": "0 2 * * *"\n'
            '  }\n'
            '}'
        ),
        "bait_user": "backup_user",
        "bait_pass": "Backup@2026",
    },
    "application.env.example": {
        "content_type": "text/plain",
        "description": "Application environment variable baseline template",
        "raw": (
            '# =====================================================================\n'
            '# APEX INTERNAL MANAGEMENT SYSTEM - PRODUCTION CONFIGURATION TEMPLATE\n'
            '# =====================================================================\n'
            'ENVIRONMENT=production\n'
            'PORTAL_PORT=8080\n'
            'PORTAL_SECRET_KEY=apex-prod-sec-key-948192-do-not-share\n'
            'DATABASE_URL=postgresql://database_root:DBroot@2026@10.0.1.25:5432/corp_finance_db\n'
            'FTP_BACKUP_STORAGE=ftp://backup_user:Backup@2026@10.0.1.30:2121/backups/finance\n'
            'SSH_JUMP_HOST=finance_admin@10.0.1.15:2222\n'
            'LOG_LEVEL=INFO\n'
        ),
        "bait_user": "finance_admin",
        "bait_pass": "Finance@2026",
    },
}

DECOY_REPORTS: Dict[str, Dict[str, Any]] = {
    "Q4_consolidated_financials.pdf": {
        "content_type": "application/pdf",
        "filename": "Q4_consolidated_financials.pdf",
        "size": 18450,
        "content": b"%PDF-1.4\n%Apex Financial Group - Q4 Consolidated Financials (CONFIDENTIAL)\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n3 0 obj\n<< /Type /Page /Parent 2 0 R /Resources <<>> /Contents 4 0 R >>\nendobj\n4 0 obj\n<< /Length 120 >>\nstream\nBT\n/F1 18 Tf\n50 700 Td\n(Apex Financial Group - Q4 Audit Summary - Gross Revenue $14,250,000) Tj\nET\nendstream\nendobj\nxref\n0 5\n0000000000 65535 f\n0000000010 00000 n\n0000000060 00000 n\n0000000120 00000 n\n0000000210 00000 n\ntrailer\n<< /Size 5 /Root 1 0 R >>\nstartxref\n380\n%%EOF\n",
    },
    "payroll_tax_filing_2026.xlsx": {
        "content_type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        "filename": "payroll_tax_filing_2026.xlsx",
        "size": 12400,
        "content": b"PK\x03\x04\x14\x00\x00\x00\x08\x00Decoy Payroll Tax Filing 2026 - Apex Financial Group\nEmployee Withholding Total: $482,190.00\nFederal Tax ID: US-EIN-9481920\nCFO Signoff: Robert Johnson\n",
    },
    "annual_audit_summary.csv": {
        "content_type": "text/csv",
        "filename": "annual_audit_summary.csv",
        "size": 3410,
        "content": (
            "department,allocated_budget,actual_spent,variance,audit_status\n"
            "Executive Leadership,2400000,2150000,-250000,Approved\n"
            "Finance & Accounting,1850000,1820000,-30000,Approved\n"
            "Engineering & DevOps,4500000,4420000,-80000,Approved\n"
            "Information Security,1200000,1180000,-20000,Approved\n"
            "Operations & Support,950000,980000,+30000,Flagged Review\n"
        ).encode("utf-8"),
    },
}
