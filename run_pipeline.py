"""
Secure Data Pipeline — Full Demonstration
Demonstrates a complete ETL pipeline with governance controls at every stage.

Author: Olamide Bakare | Data Engineer & Data Governance Specialist
"""

from pipeline.encryption import DataEncryptor
from pipeline.data_masking import DataMasker
from pipeline.access_control import AccessController, AccessLevel
from pipeline.audit_logger import AuditLogger


def main():
    print("=" * 70)
    print("  SECURE DATA PIPELINE — GOVERNANCE-EMBEDDED ETL DEMONSTRATION")
    print("  Author: Olamide Bakare | Data Engineer & Data Governance Specialist")
    print("=" * 70)

    # Initialise governance components
    encryptor = DataEncryptor()
    masker = DataMasker()
    access_ctrl = AccessController()
    audit = AuditLogger(pipeline_name="healthcare_patient_etl")

    # =========================================================
    # STEP 1: CONFIGURE GOVERNANCE RULES
    # =========================================================
    print("\n[STEP 1] Configuring governance rules...")

    # Define roles (principle of least privilege)
    access_ctrl.create_role("dashboard_viewer", AccessLevel.READ_AGGREGATED,
                           allowed_fields=["department", "visit_count"],
                           description="Dashboard users — aggregated data only")
    access_ctrl.create_role("analyst", AccessLevel.READ_MASKED,
                           description="Analysts — PII masked")
    access_ctrl.create_role("clinician", AccessLevel.READ_FULL,
                           description="Clinical staff — full patient data")
    access_ctrl.create_role("data_engineer", AccessLevel.ADMIN,
                           description="Pipeline admin — full access")

    # Define resource policy
    access_ctrl.set_resource_policy("patient_records",
                                   min_access_level=AccessLevel.READ_MASKED,
                                   sensitive_fields=["name", "date_of_birth",
                                                    "diagnosis", "email", "phone"])

    # Configure masking rules for non-production environments
    masker.add_rule("name", "partial", visible_chars=2)
    masker.add_rule("date_of_birth", "generalise")
    masker.add_rule("email", "hash", salt="pipeline-2025")
    masker.add_rule("diagnosis", "redact")
    masker.add_rule("phone", "partial", visible_chars=4)

    sensitive_fields = ["name", "date_of_birth", "diagnosis", "email", "phone"]
    print("  ✓ Roles defined (4 levels)")
    print("  ✓ Resource policies set")
    print("  ✓ Masking rules configured")

    # =========================================================
    # STEP 2: EXTRACT — Simulate data extraction
    # =========================================================
    print("\n[STEP 2] Extracting data from source system...")

    source_data = [
        {"patient_id": "PT-001", "name": "Sarah Johnson", "date_of_birth": "1990-06-15",
         "email": "sarah.j@nhs.net", "phone": "+44 7700 900123",
         "diagnosis": "Type 2 Diabetes", "department": "Endocrinology",
         "visit_date": "2025-04-01"},
        {"patient_id": "PT-002", "name": "Michael Chen", "date_of_birth": "1978-11-22",
         "email": "m.chen@nhs.net", "phone": "+44 7700 900456",
         "diagnosis": "Chronic Kidney Disease", "department": "Nephrology",
         "visit_date": "2025-03-28"},
        {"patient_id": "PT-003", "name": "Amina Okafor", "date_of_birth": "1995-03-08",
         "email": "a.okafor@nhs.net", "phone": "+44 7700 900789",
         "diagnosis": "Asthma - Moderate Persistent", "department": "Pulmonology",
         "visit_date": "2025-04-03"},
    ]

    audit.log_extract("hospital_db.patient_records", len(source_data), user="etl_service")
    print(f"  ✓ Extracted {len(source_data)} records from source")

    # =========================================================
    # STEP 3: PII DETECTION — Scan for unprotected sensitive data
    # =========================================================
    print("\n[STEP 3] Scanning for PII...")

    pii_scan = masker.detect_pii(source_data[0])
    print(f"  ⚠ Found {len(pii_scan)} potential PII fields:")
    for p in pii_scan:
        print(f"    → {p['field']}: {p['reason']}")

    # =========================================================
    # STEP 4: ENCRYPT — Encrypt sensitive fields for storage
    # =========================================================
    print("\n[STEP 4] Encrypting sensitive fields for secure storage...")

    encrypted_data = []
    for record in source_data:
        encrypted_record = encryptor.encrypt_dict_fields(record, sensitive_fields)
        encrypted_data.append(encrypted_record)

    audit.log_encryption(sensitive_fields, len(encrypted_data))
    print(f"  ✓ Encrypted {len(sensitive_fields)} fields across {len(encrypted_data)} records")
    print(f"  Sample encrypted name: {encrypted_data[0]['name'][:30]}...")

    # =========================================================
    # STEP 5: MASK — Create masked version for analytics
    # =========================================================
    print("\n[STEP 5] Creating masked dataset for analytics team...")

    masked_data = masker.mask_dataset(source_data)
    audit.log_masking(
        list(masker._masking_rules.keys()),
        {k: v["strategy"] for k, v in masker._masking_rules.items()},
        len(masked_data)
    )
    print(f"  ✓ Masked {len(masker._masking_rules)} fields across {len(masked_data)} records")
    print(f"\n  Sample masked record:")
    for k, v in masked_data[0].items():
        print(f"    {k}: {v}")

    # =========================================================
    # STEP 6: ACCESS CONTROL — Verify permissions before delivery
    # =========================================================
    print("\n[STEP 6] Verifying access permissions...")

    all_fields = list(source_data[0].keys())
    roles_to_test = ["dashboard_viewer", "analyst", "clinician", "data_engineer"]

    for role in roles_to_test:
        result = access_ctrl.check_access(role, "patient_records", all_fields)
        status = "✓ GRANTED" if result["granted"] else "✗ DENIED"
        denied = f" (denied: {result['denied_fields']})" if result["denied_fields"] else ""
        print(f"  {status} — {role}{denied}")
        audit.log_access_check(role, "patient_records", result["granted"], result["reason"])

    # =========================================================
    # STEP 7: LOAD — Simulate loading to destination
    # =========================================================
    print("\n[STEP 7] Loading data to destination...")

    # Encrypted version → secure storage
    audit.log_load("secure_warehouse.patient_records_encrypted", len(encrypted_data))
    print(f"  ✓ Loaded {len(encrypted_data)} encrypted records → secure_warehouse")

    # Masked version → analytics database
    audit.log_load("analytics_db.patient_records_masked", len(masked_data))
    print(f"  ✓ Loaded {len(masked_data)} masked records → analytics_db")

    # =========================================================
    # STEP 8: AUDIT SUMMARY
    # =========================================================
    print("\n" + "=" * 70)
    print("  PIPELINE AUDIT SUMMARY")
    print("=" * 70)
    audit.print_log()

    summary = audit.get_summary()
    print(f"\n  Total operations: {summary['total_entries']}")
    print(f"  Records processed: {summary['total_records_processed']}")
    print(f"  Operations breakdown: {summary['operations']}")
    print(f"  Status breakdown: {summary['statuses']}")

    print("\n" + "=" * 70)
    print("  PIPELINE COMPLETE — ALL GOVERNANCE CONTROLS APPLIED")
    print("=" * 70)


if __name__ == "__main__":
    main()
