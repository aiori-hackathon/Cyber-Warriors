"""
Scope Manager module for AIORI-3 PS-011.
Enforces strict boundaries:
- Up to 20 lab domains and 10 hosts.
- Validates user inputs and prevents duplicates.
- Rejects any scan request for targets outside the approved scope.
- Prevents unrestricted internet scanning.
"""

import re
import ipaddress
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Tuple

from database import get_db_connection
from config import MAX_APPROVED_DOMAINS, MAX_APPROVED_HOSTS


class ScopeViolationError(Exception):
    """Raised when an attempt is made to scan or probe an unapproved target."""
    pass


class ScopeLimitExceededError(Exception):
    """Raised when the number of approved assets exceeds the lab limit."""
    pass


class ScopeManager:
    DOMAIN_REGEX = re.compile(
        r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63})+$"
    )

    @classmethod
    def validate_asset_input(cls, asset_type: str, value: str) -> Tuple[bool, Optional[str]]:
        """Validates asset input format."""
        value = value.strip().lower()
        if not value:
            return False, "Asset value cannot be empty."

        if asset_type == "domain":
            # Allow .internal, .local, or standard TLDs for lab testing
            if not cls.DOMAIN_REGEX.match(value) and not value.endswith(".internal"):
                return False, f"Invalid domain format: '{value}'. Expected standard domain name."
        elif asset_type == "host":
            if re.match(r"^\d+\.\d+\.\d+\.\d+$", value):
                try:
                    ipaddress.ip_address(value)
                except ValueError:
                    return False, f"Invalid IPv4 address: '{value}'. Octets out of range."
            else:
                try:
                    ipaddress.ip_address(value)
                except ValueError:
                    if value != "localhost" and not cls.DOMAIN_REGEX.match(value):
                        return False, f"Invalid host format: '{value}'. Must be a valid IPv4/IPv6 address or hostname."
        else:
            return False, f"Invalid asset type: '{asset_type}'. Must be 'domain' or 'host'."

        return True, None

    @classmethod
    def get_counts(cls) -> Dict[str, int]:
        """Returns counts of approved and total assets."""
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM assets WHERE asset_type = 'domain' AND is_approved = 1")
        approved_domains = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(*) FROM assets WHERE asset_type = 'host' AND is_approved = 1")
        approved_hosts = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(*) FROM assets WHERE asset_type = 'domain'")
        total_domains = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(*) FROM assets WHERE asset_type = 'host'")
        total_hosts = cursor.fetchone()[0]
        conn.close()
        return {
            "approved_domains": approved_domains,
            "approved_hosts": approved_hosts,
            "total_domains": total_domains,
            "total_hosts": total_hosts,
            "max_domains": MAX_APPROVED_DOMAINS,
            "max_hosts": MAX_APPROVED_HOSTS
        }

    @classmethod
    def add_asset(cls, name: str, asset_type: str, value: str, ip_address: Optional[str] = None, notes: str = "") -> Tuple[bool, str]:
        """Adds a new asset ensuring validation, uniqueness, and capacity boundaries."""
        value = value.strip().lower()
        name = name.strip() or value
        
        is_valid, err = cls.validate_asset_input(asset_type, value)
        if not is_valid:
            return False, err

        counts = cls.get_counts()
        if asset_type == "domain" and counts["approved_domains"] >= MAX_APPROVED_DOMAINS:
            return False, f"Cannot add domain. Maximum limit of {MAX_APPROVED_DOMAINS} approved lab domains reached."
        if asset_type == "host" and counts["approved_hosts"] >= MAX_APPROVED_HOSTS:
            return False, f"Cannot add host. Maximum limit of {MAX_APPROVED_HOSTS} approved lab hosts reached."

        conn = get_db_connection()
        cursor = conn.cursor()
        now = datetime.now(timezone.utc).isoformat()
        try:
            cursor.execute("""
                INSERT INTO assets (name, asset_type, value, ip_address, is_approved, notes, created_at, updated_at)
                VALUES (?, ?, ?, ?, 1, ?, ?, ?)
            """, (name, asset_type, value, ip_address, notes, now, now))
            conn.commit()
            return True, f"Asset '{value}' successfully added to approved scope."
        except sqlite3.IntegrityError:
            return False, f"Asset with value '{value}' already exists in inventory."
        finally:
            conn.close()

    @classmethod
    def delete_asset(cls, asset_id: int) -> Tuple[bool, str]:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("DELETE FROM assets WHERE id = ?", (asset_id,))
        rows = cursor.rowcount
        conn.commit()
        conn.close()
        if rows > 0:
            return True, "Asset removed from inventory."
        return False, "Asset not found."

    @classmethod
    def toggle_approval(cls, asset_id: int) -> Tuple[bool, str]:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT is_approved, asset_type FROM assets WHERE id = ?", (asset_id,))
        row = cursor.fetchone()
        if not row:
            conn.close()
            return False, "Asset not found."

        current_status = row["is_approved"]
        new_status = 0 if current_status == 1 else 1

        # Check limits if approving
        if new_status == 1:
            counts = cls.get_counts()
            if row["asset_type"] == "domain" and counts["approved_domains"] >= MAX_APPROVED_DOMAINS:
                conn.close()
                return False, f"Limit reached: Maximum {MAX_APPROVED_DOMAINS} approved domains."
            if row["asset_type"] == "host" and counts["approved_hosts"] >= MAX_APPROVED_HOSTS:
                conn.close()
                return False, f"Limit reached: Maximum {MAX_APPROVED_HOSTS} approved hosts."

        cursor.execute("UPDATE assets SET is_approved = ?, updated_at = ? WHERE id = ?",
                       (new_status, datetime.now(timezone.utc).isoformat(), asset_id))
        conn.commit()
        conn.close()
        return True, "Approval status updated."

    @classmethod
    def get_all_assets(cls, filter_type: Optional[str] = None) -> List[Dict[str, Any]]:
        conn = get_db_connection()
        cursor = conn.cursor()
        if filter_type:
            cursor.execute("SELECT * FROM assets WHERE asset_type = ? ORDER BY is_approved DESC, id ASC", (filter_type,))
        else:
            cursor.execute("SELECT * FROM assets ORDER BY asset_type DESC, is_approved DESC, id ASC")
        rows = [dict(r) for r in cursor.fetchall()]
        conn.close()
        return rows

    @classmethod
    def get_approved_targets(self) -> Dict[str, List[Dict[str, Any]]]:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM assets WHERE asset_type = 'domain' AND is_approved = 1 LIMIT ?", (MAX_APPROVED_DOMAINS,))
        domains = [dict(r) for r in cursor.fetchall()]
        cursor.execute("SELECT * FROM assets WHERE asset_type = 'host' AND is_approved = 1 LIMIT ?", (MAX_APPROVED_HOSTS,))
        hosts = [dict(r) for r in cursor.fetchall()]
        conn.close()
        return {"domains": domains, "hosts": hosts}

    @classmethod
    def verify_target_in_scope(cls, target_value: str, target_type: str = "domain"):
        """
        Strict server-side validation. Rejects scanning if target is not approved in database.
        """
        target_value = target_value.strip().lower()
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM assets WHERE value = ? AND is_approved = 1", (target_value,))
        res = cursor.fetchone()
        conn.close()
        if not res:
            raise ScopeViolationError(
                f"[SCOPE REJECTION] Target '{target_value}' is NOT in the approved lab scope! "
                f"PS-011 strictly mandates scanning only organiser-approved targets."
            )
