"""
Data masking utilities for protecting PII in non-production environments.
Implements field-level masking strategies for healthcare and financial data.

Author: Olamide Bakare | Data Engineer & Data Governance Specialist
"""

import re
import hashlib
from datetime import datetime


class DataMasker:
    """
    Masks personally identifiable information (PII) and sensitive data
    using configurable strategies. Essential for data governance compliance
    when data needs to be used in development, testing, or analytics
    environments where full access to real data is not appropriate.
    """

    STRATEGIES = ["redact", "hash", "partial", "generalise"]

    def __init__(self):
        self._audit_log = []
        self._masking_rules = {}

    def add_rule(self, field_name: str, strategy: str, **kwargs):
        """
        Define a masking rule for a specific field.
        
        Args:
            field_name: The name of the field to mask.
            strategy: One of 'redact', 'hash', 'partial', 'generalise'.
            **kwargs: Additional parameters for the strategy.
        """
        if strategy not in self.STRATEGIES:
            raise ValueError(f"Unknown strategy: {strategy}. Use one of {self.STRATEGIES}")
        
        self._masking_rules[field_name] = {"strategy": strategy, **kwargs}

    def mask_value(self, value: str, strategy: str, **kwargs) -> str:
        """
        Apply a masking strategy to a single value.
        
        Args:
            value: The original value to mask.
            strategy: The masking strategy to apply.
        
        Returns:
            The masked value.
        """
        if value is None or value == "":
            return value

        value_str = str(value)

        if strategy == "redact":
            return "***REDACTED***"

        elif strategy == "hash":
            salt = kwargs.get("salt", "governance")
            return hashlib.sha256(f"{salt}:{value_str}".encode()).hexdigest()[:16]

        elif strategy == "partial":
            visible_chars = kwargs.get("visible_chars", 2)
            if len(value_str) <= visible_chars:
                return "*" * len(value_str)
            return value_str[:visible_chars] + "*" * (len(value_str) - visible_chars)

        elif strategy == "generalise":
            # For dates: keep only the year
            if re.match(r'\d{4}-\d{2}-\d{2}', value_str):
                return value_str[:4] + "-XX-XX"
            # For numbers: round to nearest range
            try:
                num = float(value_str)
                if num < 1000:
                    return f"{int(num // 10) * 10}-{int(num // 10) * 10 + 9}"
                return f"{int(num // 100) * 100}-{int(num // 100) * 100 + 99}"
            except ValueError:
                return value_str[:3] + "..."

        return value_str

    def mask_record(self, record: dict) -> dict:
        """
        Apply all configured masking rules to a data record.
        
        Args:
            record: A dictionary representing a data record.
        
        Returns:
            Dictionary with sensitive fields masked according to rules.
        """
        masked = record.copy()
        for field_name, rule in self._masking_rules.items():
            if field_name in masked and masked[field_name] is not None:
                original_type = type(masked[field_name])
                masked[field_name] = self.mask_value(
                    str(masked[field_name]),
                    rule["strategy"],
                    **{k: v for k, v in rule.items() if k != "strategy"}
                )
                self._log_operation(field_name, rule["strategy"])
        return masked

    def mask_dataset(self, records: list) -> list:
        """
        Apply masking rules to an entire dataset.
        
        Args:
            records: List of dictionaries (data records).
        
        Returns:
            List of masked records.
        """
        return [self.mask_record(record) for record in records]

    def detect_pii(self, record: dict) -> list:
        """
        Scan a record for potential PII fields based on common patterns.
        Returns a list of field names that may contain PII.
        
        This is a governance utility — helps identify fields that
        SHOULD have masking rules but don't yet.
        """
        pii_patterns = {
            "email": r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
            "phone": r'[\+]?[\d\s\-\(\)]{10,}',
            "ssn": r'\d{3}-\d{2}-\d{4}',
            "date_of_birth": r'\d{4}-\d{2}-\d{2}',
            "credit_card": r'\d{4}[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{4}',
            "postcode": r'[A-Z]{1,2}\d[A-Z\d]?\s*\d[A-Z]{2}',
        }

        potential_pii = []
        for field_name, value in record.items():
            if value is None:
                continue
            value_str = str(value)
            
            # Check field name for PII indicators
            pii_keywords = ["name", "email", "phone", "address", "birth", "ssn",
                          "passport", "license", "salary", "diagnosis", "medical"]
            if any(keyword in field_name.lower() for keyword in pii_keywords):
                potential_pii.append({
                    "field": field_name,
                    "reason": "Field name contains PII keyword",
                    "suggestion": "Add masking rule"
                })
                continue

            # Check value patterns
            for pattern_name, pattern in pii_patterns.items():
                if re.search(pattern, value_str):
                    potential_pii.append({
                        "field": field_name,
                        "reason": f"Value matches {pattern_name} pattern",
                        "suggestion": "Add masking rule"
                    })
                    break

        return potential_pii

    def _log_operation(self, field_name: str, strategy: str):
        """Log masking operations for audit trail."""
        self._audit_log.append({
            "timestamp": datetime.utcnow().isoformat(),
            "operation": "mask",
            "field": field_name,
            "strategy": strategy
        })

    def get_audit_log(self) -> list:
        """Return the audit log of all masking operations."""
        return self._audit_log.copy()


if __name__ == "__main__":
    masker = DataMasker()

    # Configure masking rules
    masker.add_rule("name", "partial", visible_chars=2)
    masker.add_rule("date_of_birth", "generalise")
    masker.add_rule("email", "hash", salt="governance-2025")
    masker.add_rule("diagnosis", "redact")
    masker.add_rule("phone", "partial", visible_chars=4)

    # Sample dataset
    records = [
        {
            "patient_id": "PT-001",
            "name": "Sarah Johnson",
            "date_of_birth": "1990-06-15",
            "email": "sarah.j@hospital.com",
            "phone": "+44 7700 900123",
            "diagnosis": "Hypertension Stage 2",
            "department": "Cardiology"
        },
        {
            "patient_id": "PT-002",
            "name": "Michael Chen",
            "date_of_birth": "1978-11-22",
            "email": "m.chen@hospital.com",
            "phone": "+44 7700 900456",
            "diagnosis": "Chronic Kidney Disease",
            "department": "Nephrology"
        }
    ]

    print("=== ORIGINAL DATA ===")
    for r in records:
        print(f"  {r}")

    print("\n=== PII DETECTION SCAN ===")
    pii_found = masker.detect_pii(records[0])
    for p in pii_found:
        print(f"  {p['field']}: {p['reason']} -> {p['suggestion']}")

    masked = masker.mask_dataset(records)
    print("\n=== MASKED DATA ===")
    for r in masked:
        print(f"  {r}")

    print("\n=== AUDIT LOG ===")
    for entry in masker.get_audit_log():
        print(f"  [{entry['timestamp']}] {entry['operation'].upper()} {entry['field']} ({entry['strategy']})")
