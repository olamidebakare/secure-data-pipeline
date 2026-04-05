"""
Unit tests for the Secure Data Pipeline Framework.

Author: Olamide Bakare | Data Engineer & Data Governance Specialist
"""

import unittest
from pipeline.encryption import DataEncryptor
from pipeline.data_masking import DataMasker
from pipeline.access_control import AccessController, AccessLevel
from pipeline.audit_logger import AuditLogger


class TestEncryption(unittest.TestCase):
    """Tests for the encryption module."""

    def setUp(self):
        self.encryptor = DataEncryptor()

    def test_encrypt_decrypt_roundtrip(self):
        """Encrypted data should decrypt back to original."""
        original = "Sarah Johnson"
        encrypted = self.encryptor.encrypt_value(original, "name")
        decrypted = self.encryptor.decrypt_value(encrypted, "name")
        self.assertEqual(original, decrypted)

    def test_encrypted_differs_from_original(self):
        """Encrypted value should not equal the original."""
        original = "Sensitive Data"
        encrypted = self.encryptor.encrypt_value(original, "field")
        self.assertNotEqual(original, encrypted)

    def test_encrypt_none_returns_none(self):
        """None values should pass through unchanged."""
        result = self.encryptor.encrypt_value(None, "field")
        self.assertIsNone(result)

    def test_encrypt_empty_returns_empty(self):
        """Empty strings should pass through unchanged."""
        result = self.encryptor.encrypt_value("", "field")
        self.assertEqual(result, "")

    def test_encrypt_dict_fields(self):
        """Only specified fields should be encrypted."""
        record = {"name": "Jane", "age": "30", "city": "London"}
        encrypted = self.encryptor.encrypt_dict_fields(record, ["name"])
        self.assertNotEqual(encrypted["name"], "Jane")
        self.assertEqual(encrypted["age"], "30")
        self.assertEqual(encrypted["city"], "London")

    def test_audit_log_records_operations(self):
        """Encryption operations should be logged."""
        self.encryptor.encrypt_value("test", "test_field")
        log = self.encryptor.get_audit_log()
        self.assertEqual(len(log), 1)
        self.assertEqual(log[0]["operation"], "encrypt")
        self.assertEqual(log[0]["field"], "test_field")


class TestDataMasking(unittest.TestCase):
    """Tests for the data masking module."""

    def setUp(self):
        self.masker = DataMasker()

    def test_redact_strategy(self):
        """Redact should replace value entirely."""
        result = self.masker.mask_value("Sensitive Info", "redact")
        self.assertEqual(result, "***REDACTED***")

    def test_hash_strategy(self):
        """Hash should produce a fixed-length string."""
        result = self.masker.mask_value("test@email.com", "hash")
        self.assertEqual(len(result), 16)

    def test_partial_strategy(self):
        """Partial should show first N characters."""
        result = self.masker.mask_value("Sarah Johnson", "partial", visible_chars=3)
        self.assertEqual(result[:3], "Sar")
        self.assertTrue(result[3:].count("*") > 0)

    def test_generalise_date(self):
        """Generalise should mask month and day of dates."""
        result = self.masker.mask_value("1990-06-15", "generalise")
        self.assertEqual(result, "1990-XX-XX")

    def test_pii_detection_finds_email(self):
        """PII scanner should detect email patterns."""
        record = {"contact": "test@example.com", "id": "123"}
        pii = self.masker.detect_pii(record)
        email_found = any(p["field"] == "contact" for p in pii)
        self.assertTrue(email_found)

    def test_pii_detection_finds_name_field(self):
        """PII scanner should flag fields with 'name' in the key."""
        record = {"full_name": "Jane Doe", "department": "HR"}
        pii = self.masker.detect_pii(record)
        name_found = any(p["field"] == "full_name" for p in pii)
        self.assertTrue(name_found)


class TestAccessControl(unittest.TestCase):
    """Tests for the access control module."""

    def setUp(self):
        self.ac = AccessController()
        self.ac.create_role("viewer", AccessLevel.READ_AGGREGATED,
                          allowed_fields=["department", "count"])
        self.ac.create_role("analyst", AccessLevel.READ_MASKED)
        self.ac.create_role("admin", AccessLevel.ADMIN)
        self.ac.set_resource_policy("patients", AccessLevel.READ_MASKED,
                                   sensitive_fields=["name", "diagnosis"])

    def test_insufficient_access_denied(self):
        """Viewer should be denied access to masked-level resources."""
        result = self.ac.check_access("viewer", "patients", ["department"])
        self.assertFalse(result["granted"])

    def test_sufficient_access_granted(self):
        """Analyst should have access to non-sensitive fields."""
        result = self.ac.check_access("analyst", "patients", ["department", "visit_date"])
        self.assertTrue(result["granted"])

    def test_sensitive_fields_denied_for_masked_role(self):
        """Analyst should be denied access to sensitive fields."""
        result = self.ac.check_access("analyst", "patients", ["name", "diagnosis"])
        self.assertFalse(result["granted"])
        self.assertIn("name", result["denied_fields"])

    def test_admin_access_all(self):
        """Admin should have access to everything."""
        result = self.ac.check_access("admin", "patients", ["name", "diagnosis", "department"])
        self.assertTrue(result["granted"])

    def test_unknown_role_denied(self):
        """Unknown roles should be denied."""
        result = self.ac.check_access("hacker", "patients", ["name"])
        self.assertFalse(result["granted"])

    def test_access_log_populated(self):
        """Access checks should be logged."""
        self.ac.check_access("analyst", "patients", ["department"])
        log = self.ac.get_access_log()
        self.assertGreater(len(log), 0)


class TestAuditLogger(unittest.TestCase):
    """Tests for the audit logger module."""

    def setUp(self):
        self.logger = AuditLogger(pipeline_name="test_pipeline")

    def test_log_extract(self):
        """Extract operations should be logged."""
        self.logger.log_extract("source_db", 100)
        entries = self.logger.get_entries(operation="extract")
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]["records_affected"], 100)

    def test_log_error(self):
        """Errors should be logged with failure status."""
        self.logger.log_error("transform", "Column not found")
        entries = self.logger.get_entries(status="failure")
        self.assertEqual(len(entries), 1)

    def test_summary_counts(self):
        """Summary should accurately count operations."""
        self.logger.log_extract("src", 50)
        self.logger.log_transform("clean", 50)
        self.logger.log_load("dest", 50)
        summary = self.logger.get_summary()
        self.assertEqual(summary["total_entries"], 3)
        self.assertEqual(summary["total_records_processed"], 150)

    def test_filter_by_operation(self):
        """Should filter entries by operation type."""
        self.logger.log_extract("src", 10)
        self.logger.log_load("dest", 10)
        extracts = self.logger.get_entries(operation="extract")
        self.assertEqual(len(extracts), 1)


if __name__ == "__main__":
    unittest.main()
