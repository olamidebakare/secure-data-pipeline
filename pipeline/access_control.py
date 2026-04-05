"""
Role-based access control (RBAC) for data pipeline operations.
Enforces the principle of least privilege at the data layer.

Author: Olamide Bakare | Data Engineer & Data Governance Specialist
"""

from datetime import datetime
from enum import Enum


class AccessLevel(Enum):
    """Access levels following the principle of least privilege."""
    NONE = 0
    READ_AGGREGATED = 1    # Can only see aggregated/summary data
    READ_MASKED = 2        # Can see data with PII masked
    READ_FULL = 3          # Can see all data including PII
    WRITE = 4              # Can modify data
    ADMIN = 5              # Full access including schema changes


class AccessController:
    """
    Manages role-based access to data pipeline resources.
    
    Every data access is checked against the user's role and logged.
    This ensures governance compliance and creates an audit trail
    for regulatory requirements (GDPR, HIPAA, etc.).
    """

    def __init__(self):
        self._roles = {}
        self._resource_policies = {}
        self._access_log = []

    def create_role(self, role_name: str, access_level: AccessLevel, 
                    allowed_fields: list = None, description: str = ""):
        """
        Define a role with specific access permissions.
        
        Args:
            role_name: Name of the role (e.g., 'analyst', 'clinician', 'admin').
            access_level: The AccessLevel enum value.
            allowed_fields: List of field names this role can access. None = all fields.
            description: Human-readable description of the role.
        """
        self._roles[role_name] = {
            "access_level": access_level,
            "allowed_fields": allowed_fields,
            "description": description,
            "created_at": datetime.utcnow().isoformat()
        }

    def set_resource_policy(self, resource_name: str, 
                           min_access_level: AccessLevel,
                           sensitive_fields: list = None):
        """
        Define access policy for a data resource (table, view, dataset).
        
        Args:
            resource_name: Name of the data resource.
            min_access_level: Minimum access level required.
            sensitive_fields: Fields within this resource that require elevated access.
        """
        self._resource_policies[resource_name] = {
            "min_access_level": min_access_level,
            "sensitive_fields": sensitive_fields or [],
            "created_at": datetime.utcnow().isoformat()
        }

    def check_access(self, role_name: str, resource_name: str, 
                     requested_fields: list = None, operation: str = "read") -> dict:
        """
        Check whether a role has access to a resource.
        
        Args:
            role_name: The role requesting access.
            resource_name: The resource being accessed.
            requested_fields: Specific fields being requested.
            operation: Type of operation ('read', 'write', 'delete').
        
        Returns:
            Dictionary with 'granted' (bool), 'accessible_fields' (list),
            'denied_fields' (list), and 'reason' (str).
        """
        # Check role exists
        if role_name not in self._roles:
            result = self._deny(f"Role '{role_name}' does not exist")
            self._log_access(role_name, resource_name, operation, False, result["reason"])
            return result

        role = self._roles[role_name]

        # Check resource policy exists
        if resource_name not in self._resource_policies:
            result = self._deny(f"No policy defined for resource '{resource_name}'")
            self._log_access(role_name, resource_name, operation, False, result["reason"])
            return result

        policy = self._resource_policies[resource_name]

        # Check access level
        if role["access_level"].value < policy["min_access_level"].value:
            result = self._deny(
                f"Role '{role_name}' has access level {role['access_level'].name} "
                f"but resource requires {policy['min_access_level'].name}"
            )
            self._log_access(role_name, resource_name, operation, False, result["reason"])
            return result

        # Check write permission
        if operation in ("write", "delete") and role["access_level"].value < AccessLevel.WRITE.value:
            result = self._deny(f"Role '{role_name}' does not have write/delete permission")
            self._log_access(role_name, resource_name, operation, False, result["reason"])
            return result

        # Determine accessible fields
        requested = requested_fields or []
        sensitive = policy.get("sensitive_fields", [])
        role_fields = role.get("allowed_fields")

        accessible = []
        denied = []

        for field in requested:
            # If field is sensitive, need READ_FULL or higher
            if field in sensitive and role["access_level"].value < AccessLevel.READ_FULL.value:
                denied.append(field)
            # If role has field restrictions, check them
            elif role_fields is not None and field not in role_fields:
                denied.append(field)
            else:
                accessible.append(field)

        granted = len(denied) == 0
        reason = "Access granted" if granted else f"Denied access to fields: {denied}"

        self._log_access(role_name, resource_name, operation, granted, reason)

        return {
            "granted": granted,
            "accessible_fields": accessible,
            "denied_fields": denied,
            "reason": reason,
            "access_level": role["access_level"].name
        }

    def filter_record(self, record: dict, role_name: str, resource_name: str) -> dict:
        """
        Filter a data record based on the role's access permissions.
        Removes fields the role is not authorised to see.
        
        Args:
            record: The full data record.
            role_name: The role requesting the data.
            resource_name: The resource the data belongs to.
        
        Returns:
            Filtered record with only authorised fields.
        """
        all_fields = list(record.keys())
        access_result = self.check_access(role_name, resource_name, all_fields)
        
        return {k: v for k, v in record.items() if k in access_result["accessible_fields"]}

    def _deny(self, reason: str) -> dict:
        return {"granted": False, "accessible_fields": [], "denied_fields": [], "reason": reason}

    def _log_access(self, role: str, resource: str, operation: str, 
                    granted: bool, reason: str):
        self._access_log.append({
            "timestamp": datetime.utcnow().isoformat(),
            "role": role,
            "resource": resource,
            "operation": operation,
            "granted": granted,
            "reason": reason
        })

    def get_access_log(self) -> list:
        """Return the complete access audit log."""
        return self._access_log.copy()

    def get_role_summary(self) -> dict:
        """Return a summary of all defined roles."""
        return {
            name: {
                "access_level": role["access_level"].name,
                "allowed_fields": role["allowed_fields"],
                "description": role["description"]
            }
            for name, role in self._roles.items()
        }


if __name__ == "__main__":
    ac = AccessController()

    # Define roles (principle of least privilege)
    ac.create_role("dashboard_viewer", AccessLevel.READ_AGGREGATED,
                   allowed_fields=["department", "visit_count", "avg_wait_time"],
                   description="Can only view aggregated dashboard metrics")
    ac.create_role("analyst", AccessLevel.READ_MASKED,
                   description="Can view data with PII masked")
    ac.create_role("clinician", AccessLevel.READ_FULL,
                   description="Can view full patient records including PII")
    ac.create_role("data_engineer", AccessLevel.ADMIN,
                   description="Full access for pipeline maintenance")

    # Define resource policy
    ac.set_resource_policy("patient_records",
                          min_access_level=AccessLevel.READ_MASKED,
                          sensitive_fields=["name", "date_of_birth", "diagnosis", "email"])

    # Test record
    record = {
        "patient_id": "PT-001",
        "name": "Sarah Johnson",
        "date_of_birth": "1990-06-15",
        "diagnosis": "Hypertension",
        "department": "Cardiology",
        "visit_date": "2025-04-01"
    }

    print("=== ROLE DEFINITIONS ===")
    for name, summary in ac.get_role_summary().items():
        print(f"  {name}: {summary['access_level']} - {summary['description']}")

    # Test each role
    for role in ["dashboard_viewer", "analyst", "clinician", "data_engineer"]:
        print(f"\n=== ACCESS CHECK: {role.upper()} ===")
        result = ac.check_access(role, "patient_records", list(record.keys()))
        print(f"  Granted: {result['granted']}")
        print(f"  Accessible: {result['accessible_fields']}")
        print(f"  Denied: {result['denied_fields']}")
        print(f"  Reason: {result['reason']}")

    print("\n=== ACCESS AUDIT LOG ===")
    for entry in ac.get_access_log():
        status = "GRANTED" if entry["granted"] else "DENIED"
        print(f"  [{entry['timestamp']}] {status} | {entry['role']} -> {entry['resource']} ({entry['operation']})")
