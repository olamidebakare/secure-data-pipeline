"""
Comprehensive audit logging for all data pipeline operations.
Every data movement, transformation, and access is recorded.

Author: Olamide Bakare | Data Engineer & Data Governance Specialist
"""

import json
import os
from datetime import datetime


class AuditLogger:
    """
    Records all data pipeline operations for governance compliance.
    
    Audit logs answer the critical governance questions:
    - WHO accessed the data?
    - WHAT data was accessed or modified?
    - WHEN did it happen?
    - WHERE did the data move to?
    - WHY (what operation was performed)?
    """

    def __init__(self, log_file: str = "audit_log.json", pipeline_name: str = "default"):
        self._log_file = log_file
        self._pipeline_name = pipeline_name
        self._entries = []

    def log(self, operation: str, details: dict, user: str = "system",
            status: str = "success", records_affected: int = 0):
        """
        Record a pipeline operation.
        
        Args:
            operation: Type of operation (extract, transform, load, encrypt, mask, access_check).
            details: Dictionary of operation-specific details.
            user: The user or service performing the operation.
            status: 'success', 'failure', or 'warning'.
            records_affected: Number of records affected by the operation.
        """
        entry = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "pipeline": self._pipeline_name,
            "operation": operation,
            "user": user,
            "status": status,
            "records_affected": records_affected,
            "details": details
        }
        self._entries.append(entry)

    def log_extract(self, source: str, record_count: int, user: str = "system"):
        """Log a data extraction operation."""
        self.log("extract", {
            "source": source,
            "action": "Data extracted from source"
        }, user=user, records_affected=record_count)

    def log_transform(self, transformation: str, record_count: int, 
                      fields_affected: list = None, user: str = "system"):
        """Log a data transformation operation."""
        self.log("transform", {
            "transformation": transformation,
            "fields_affected": fields_affected or [],
            "action": "Data transformed"
        }, user=user, records_affected=record_count)

    def log_load(self, destination: str, record_count: int, user: str = "system"):
        """Log a data load operation."""
        self.log("load", {
            "destination": destination,
            "action": "Data loaded to destination"
        }, user=user, records_affected=record_count)

    def log_encryption(self, fields: list, record_count: int, user: str = "system"):
        """Log an encryption operation."""
        self.log("encrypt", {
            "encrypted_fields": fields,
            "action": "Sensitive fields encrypted"
        }, user=user, records_affected=record_count)

    def log_masking(self, fields: list, strategies: dict, record_count: int, 
                    user: str = "system"):
        """Log a data masking operation."""
        self.log("mask", {
            "masked_fields": fields,
            "strategies": strategies,
            "action": "PII fields masked"
        }, user=user, records_affected=record_count)

    def log_access_check(self, role: str, resource: str, granted: bool, 
                         reason: str = ""):
        """Log an access control check."""
        self.log("access_check", {
            "role": role,
            "resource": resource,
            "granted": granted,
            "reason": reason,
            "action": "Access check performed"
        }, user=role, status="success" if granted else "denied")

    def log_error(self, operation: str, error_message: str, user: str = "system"):
        """Log a pipeline error."""
        self.log(operation, {
            "error": error_message,
            "action": "Error occurred"
        }, user=user, status="failure")

    def get_entries(self, operation: str = None, status: str = None) -> list:
        """
        Retrieve audit log entries with optional filtering.
        
        Args:
            operation: Filter by operation type.
            status: Filter by status.
        
        Returns:
            List of matching log entries.
        """
        entries = self._entries.copy()
        if operation:
            entries = [e for e in entries if e["operation"] == operation]
        if status:
            entries = [e for e in entries if e["status"] == status]
        return entries

    def get_summary(self) -> dict:
        """Return a summary of all logged operations."""
        summary = {
            "total_entries": len(self._entries),
            "pipeline": self._pipeline_name,
            "operations": {},
            "statuses": {},
            "total_records_processed": 0
        }
        for entry in self._entries:
            op = entry["operation"]
            st = entry["status"]
            summary["operations"][op] = summary["operations"].get(op, 0) + 1
            summary["statuses"][st] = summary["statuses"].get(st, 0) + 1
            summary["total_records_processed"] += entry.get("records_affected", 0)
        return summary

    def save(self):
        """Save the audit log to a JSON file."""
        with open(self._log_file, 'w') as f:
            json.dump(self._entries, f, indent=2)

    def print_log(self):
        """Print a human-readable version of the audit log."""
        for entry in self._entries:
            status_icon = "✓" if entry["status"] == "success" else "✗" if entry["status"] == "failure" else "⚠"
            print(f"  {status_icon} [{entry['timestamp']}] {entry['operation'].upper():15} | "
                  f"{entry['user']:20} | {entry['details'].get('action', '')} "
                  f"({entry['records_affected']} records)")


if __name__ == "__main__":
    logger = AuditLogger(pipeline_name="healthcare_etl")

    # Simulate a pipeline run
    logger.log_extract("hospital_database.patient_records", 1500, user="etl_service")
    logger.log_transform("data_cleaning", 1500, fields_affected=["phone", "postcode"])
    logger.log_encryption(["name", "date_of_birth", "diagnosis"], 1500)
    logger.log_masking(["email", "phone"], {"email": "hash", "phone": "partial"}, 1500)
    logger.log_access_check("analyst", "patient_records", True, "Access level sufficient")
    logger.log_access_check("dashboard_viewer", "patient_records", False, "Insufficient access level")
    logger.log_load("analytics_warehouse.patient_summary", 1500, user="etl_service")

    print("=== AUDIT LOG ===")
    logger.print_log()

    print("\n=== SUMMARY ===")
    summary = logger.get_summary()
    for k, v in summary.items():
        print(f"  {k}: {v}")
