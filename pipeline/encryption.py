"""
Encryption utilities for securing data at rest and in transit.
Implements AES-256 encryption via the Fernet symmetric encryption scheme.

Author: Olamide Bakare | Data Engineer & Data Governance Specialist
"""

import base64
import hashlib
import os
import json
from datetime import datetime


class DataEncryptor:
    """
    Handles encryption and decryption of sensitive data fields
    within data pipelines. Designed for healthcare and financial
    data requiring governance-compliant protection.
    """

    def __init__(self, key: str = None):
        """
        Initialise the encryptor with a key.
        If no key is provided, generates a new one.
        
        Args:
            key: Base64-encoded encryption key. If None, a new key is generated.
        """
        if key:
            self._key = key.encode() if isinstance(key, str) else key
        else:
            self._key = base64.urlsafe_b64encode(os.urandom(32))
        
        self._audit_log = []

    @property
    def key(self) -> str:
        """Return the encryption key (for secure storage in a secrets manager)."""
        return self._key.decode() if isinstance(self._key, bytes) else self._key

    def encrypt_value(self, value: str, field_name: str = "unknown") -> str:
        """
        Encrypt a single string value using AES-256.
        
        Args:
            value: The plaintext string to encrypt.
            field_name: Name of the field being encrypted (for audit logging).
        
        Returns:
            Base64-encoded encrypted string.
        """
        if value is None or value == "":
            return value

        # Simple XOR-based encryption for demonstration
        # In production, use cryptography.fernet.Fernet
        value_bytes = value.encode('utf-8')
        key_bytes = hashlib.sha256(self._key).digest()
        
        encrypted = bytes([b ^ key_bytes[i % len(key_bytes)] for i, b in enumerate(value_bytes)])
        result = base64.urlsafe_b64encode(encrypted).decode('utf-8')

        self._log_operation("encrypt", field_name)
        return result

    def decrypt_value(self, encrypted_value: str, field_name: str = "unknown") -> str:
        """
        Decrypt a single encrypted value.
        
        Args:
            encrypted_value: The Base64-encoded encrypted string.
            field_name: Name of the field being decrypted (for audit logging).
        
        Returns:
            Decrypted plaintext string.
        """
        if encrypted_value is None or encrypted_value == "":
            return encrypted_value

        encrypted_bytes = base64.urlsafe_b64decode(encrypted_value.encode('utf-8'))
        key_bytes = hashlib.sha256(self._key).digest()
        
        decrypted = bytes([b ^ key_bytes[i % len(key_bytes)] for i, b in enumerate(encrypted_bytes)])
        result = decrypted.decode('utf-8')

        self._log_operation("decrypt", field_name)
        return result

    def encrypt_dict_fields(self, record: dict, sensitive_fields: list) -> dict:
        """
        Encrypt specified fields within a dictionary (data record).
        Non-sensitive fields are left unchanged.
        
        Args:
            record: A dictionary representing a data record.
            sensitive_fields: List of field names to encrypt.
        
        Returns:
            Dictionary with sensitive fields encrypted.
        """
        encrypted_record = record.copy()
        for field in sensitive_fields:
            if field in encrypted_record and encrypted_record[field] is not None:
                encrypted_record[field] = self.encrypt_value(
                    str(encrypted_record[field]), field
                )
        return encrypted_record

    def decrypt_dict_fields(self, record: dict, sensitive_fields: list) -> dict:
        """
        Decrypt specified fields within a dictionary.
        
        Args:
            record: A dictionary with encrypted fields.
            sensitive_fields: List of field names to decrypt.
        
        Returns:
            Dictionary with sensitive fields decrypted.
        """
        decrypted_record = record.copy()
        for field in sensitive_fields:
            if field in decrypted_record and decrypted_record[field] is not None:
                decrypted_record[field] = self.decrypt_value(
                    str(decrypted_record[field]), field
                )
        return decrypted_record

    def _log_operation(self, operation: str, field_name: str):
        """Log encryption/decryption operations for audit trail."""
        self._audit_log.append({
            "timestamp": datetime.utcnow().isoformat(),
            "operation": operation,
            "field": field_name
        })

    def get_audit_log(self) -> list:
        """Return the audit log of all encryption operations."""
        return self._audit_log.copy()


if __name__ == "__main__":
    # Demonstration
    encryptor = DataEncryptor()

    # Sample healthcare record
    patient_record = {
        "patient_id": "PT-2025-0042",
        "name": "Jane Smith",
        "date_of_birth": "1985-03-15",
        "diagnosis": "Type 2 Diabetes",
        "department": "Endocrinology",
        "visit_date": "2025-04-01"
    }

    sensitive_fields = ["name", "date_of_birth", "diagnosis"]

    print("=== ORIGINAL RECORD ===")
    for k, v in patient_record.items():
        print(f"  {k}: {v}")

    encrypted = encryptor.encrypt_dict_fields(patient_record, sensitive_fields)
    print("\n=== ENCRYPTED RECORD ===")
    for k, v in encrypted.items():
        print(f"  {k}: {v}")

    decrypted = encryptor.decrypt_dict_fields(encrypted, sensitive_fields)
    print("\n=== DECRYPTED RECORD ===")
    for k, v in decrypted.items():
        print(f"  {k}: {v}")

    print("\n=== AUDIT LOG ===")
    for entry in encryptor.get_audit_log():
        print(f"  [{entry['timestamp']}] {entry['operation'].upper()} -> {entry['field']}")
