# Governance Architecture

## Design Principles

This pipeline is built on five core data governance principles:

### 1. Least Privilege
Every role gets the minimum access needed. A dashboard viewer doesn't see patient names. An analyst sees masked data. Only clinicians see full records. Access is denied by default and granted explicitly.

### 2. Encryption by Default
Sensitive data is encrypted before it leaves the pipeline. If storage is compromised, the data is unreadable without the decryption key. Keys are never stored alongside data.

### 3. Data Minimisation
Pipelines carry only the fields the destination needs. If a dashboard shows department-level totals, patient-level PII never enters that pipeline. Less data in transit = smaller attack surface.

### 4. Complete Auditability
Every operation is logged: who accessed what, when, and why. This creates an unbroken chain of accountability from source to destination, enabling rapid incident response and regulatory compliance.

### 5. Privacy by Design
Governance controls are not added after the pipeline is built. They are part of the pipeline architecture itself. Masking, encryption, and access checks happen at every stage — extract, transform, and load.

## Regulatory Mapping

| Governance Feature | GDPR Article | HIPAA Safeguard | NIST Function |
|---|---|---|---|
| Encryption | Art. 32 (Security) | Technical Safeguard §164.312(a) | Protect (PR.DS) |
| Access Control | Art. 25 (Privacy by Design) | Technical Safeguard §164.312(a) | Protect (PR.AC) |
| Data Masking | Art. 5 (Data Minimisation) | Administrative Safeguard §164.308 | Protect (PR.DS) |
| Audit Logging | Art. 30 (Records of Processing) | Technical Safeguard §164.312(b) | Detect (DE.AE) |
| PII Detection | Art. 35 (Impact Assessment) | Administrative Safeguard §164.308 | Identify (ID.RA) |
