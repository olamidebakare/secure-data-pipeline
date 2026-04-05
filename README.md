# Secure Data Pipeline Framework

A governance-embedded ETL pipeline framework for handling sensitive data — particularly healthcare (PHI) and financial records — with security and compliance built into every stage.

**Author:** Olamide Bakare | Data Engineer & Data Governance Specialist

## Why This Exists

Healthcare data breaches cost $7.42 million per incident. Most don't start with sophisticated hacking — they start with data engineering decisions: misconfigured databases, unencrypted pipelines, overly permissive access controls.

This framework demonstrates how governance can be built **into** the pipeline rather than bolted on as an afterthought.

## Governance Features

| Feature | Module | What It Does |
|---------|--------|--------------|
| **Encryption** | `encryption.py` | AES-256 encryption for sensitive fields at rest and in transit |
| **Data Masking** | `data_masking.py` | PII detection and field-level masking (redact, hash, partial, generalise) |
| **Access Control** | `access_control.py` | Role-based access with principle of least privilege enforcement |
| **Audit Logging** | `audit_logger.py` | Every operation logged with who, what, when, where, and why |

## How It Works

```
Source Data
    │
    ▼
[1. EXTRACT] ──── Audit log: source, timestamp, record count
    │
    ▼
[2. PII SCAN] ──── Detect unprotected sensitive fields
    │
    ▼
[3. ENCRYPT] ──── AES-256 encryption on sensitive fields
    │
    ▼
[4. MASK] ──────── Create masked version for non-production use
    │
    ▼
[5. ACCESS CHECK] ── Verify role permissions before delivery
    │
    ▼
[6. LOAD] ──────── Encrypted → secure storage
                    Masked → analytics database
    │
    ▼
[AUDIT SUMMARY] ── Complete trail of all operations
```

## Quick Start

```bash
# Clone the repo
git clone https://github.com/olamidebakare/secure-data-pipeline.git
cd secure-data-pipeline

# Run the full pipeline demo
python run_pipeline.py

# Run individual modules
python -m pipeline.encryption
python -m pipeline.data_masking
python -m pipeline.access_control
python -m pipeline.audit_logger

# Run tests
python -m pytest tests/
```

## Project Structure

```
secure-data-pipeline/
├── pipeline/
│   ├── __init__.py              # Package initialisation
│   ├── encryption.py            # AES-256 data encryption
│   ├── data_masking.py          # PII detection & field masking
│   ├── access_control.py        # Role-based access control (RBAC)
│   └── audit_logger.py          # Comprehensive audit logging
├── tests/
│   └── test_pipeline.py         # Unit tests for all modules
├── config/
│   └── governance_config.yaml   # Governance rules configuration
├── docs/
│   └── governance_architecture.md
├── run_pipeline.py              # Full pipeline demonstration
├── requirements.txt
└── README.md
```

## Masking Strategies

| Strategy | Input | Output | Use Case |
|----------|-------|--------|----------|
| `redact` | `Type 2 Diabetes` | `***REDACTED***` | Remove sensitive values entirely |
| `hash` | `sarah@nhs.net` | `a4f8c2e91b3d7...` | Irreversible pseudonymisation |
| `partial` | `Sarah Johnson` | `Sa***********` | Show enough to identify, not enough to exploit |
| `generalise` | `1990-06-15` | `1990-XX-XX` | Reduce precision while maintaining utility |

## Access Levels

| Level | Name | Description |
|-------|------|-------------|
| 1 | `READ_AGGREGATED` | Summary/dashboard data only |
| 2 | `READ_MASKED` | Full records with PII masked |
| 3 | `READ_FULL` | Complete records including PII |
| 4 | `WRITE` | Can modify data |
| 5 | `ADMIN` | Full access including schema changes |

## Regulatory Alignment

This framework is designed with awareness of:
- **GDPR** (UK & EU) — data minimisation, purpose limitation, right to erasure
- **HIPAA** (US) — protected health information safeguards
- **CCPA/CPRA** (California) — consumer data access and deletion rights
- **NIST Privacy Framework** — organisational privacy risk management

## Author

**Olamide Bakare** — Data Engineer & Data Governance Specialist

- [LinkedIn](https://www.linkedin.com/in/olamide-bakare/)
- [GitHub](https://github.com/olamidebakare)
- [Website](https://olamidebakare.github.io)

*This project is part of an ongoing body of work exploring the intersection of data engineering, data governance, and privacy compliance.*
