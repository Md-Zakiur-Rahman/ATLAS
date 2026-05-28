import bcrypt
from datetime import datetime

from database.db_manager import supabase
from config.logging_config import get_logger

class VaultAuthManager:
    def __init__(self):
        pass
        self.logger = get_logger(__name__)
    # =====================================================
    # Create vault PIN
    # =====================================================

    def create_vault_pin(self, email: str, pin: str):
        if len(pin) != 6 or not pin.isdigit():
            raise ValueError("Vault PIN must be exactly 6 digits.")

        pin_hash = bcrypt.hashpw(
            pin.encode(),
            bcrypt.gensalt()
        ).decode()

        existing = (
            supabase.table("vault_profiles")
            .select("*")
            .eq("user_email", email)
            .execute()
        )

        if existing.data:
            raise ValueError("Vault PIN already exists.")

        response = (
            supabase.table("vault_profiles")
            .insert({
                "user_email": email,
                "pin_hash": pin_hash,
                "vault_locked": False,
                "failed_attempts": 0,
                "last_threat_level": "LOW",
            })
            .execute()
        )

        return response.data

    # =====================================================
    # Verify vault PIN
    # =====================================================

    def verify_vault_pin(self, email: str, pin: str) -> bool:
        result = (
            supabase.table("vault_profiles")
            .select("*")
            .eq("user_email", email)
            .execute()
        )

        if not result.data:
            return False

        profile = result.data[0]

        stored_hash = profile["pin_hash"]

        valid = bcrypt.checkpw(
            pin.encode(),
            stored_hash.encode()
        )

        if valid:
            (
                supabase.table("vault_profiles")
                .update({
                    "failed_attempts": 0,
                    "last_unlock": datetime.utcnow().isoformat(),
                    "vault_locked": False,
                })
                .eq("user_email", email)
                .execute()
            )

            return True

        failed = profile.get("failed_attempts", 0) + 1

        update_payload = {"failed_attempts": failed}
        if failed >= 5:
            update_payload.update({
                "vault_locked": True,
                "last_lock": datetime.utcnow().isoformat(),
                "last_lock_reason": "FAILED_PIN_THRESHOLD",
                "last_threat_level": "HIGH",
            })
            self.logger.critical("Vault auto-locked for %s due to excessive failed PIN attempts.", email)

        supabase.table("vault_profiles").update(update_payload).eq("user_email", email).execute()

        return False

    # =====================================================
    # Lock vault
    # =====================================================

    def lock_vault(
        self,
        email: str,
        reason: str,
        severity: str = "CRITICAL"
    ):
        (
            supabase.table("vault_profiles")
            .update({
                "vault_locked": True,
                "last_lock": datetime.utcnow().isoformat(),
                "last_lock_reason": reason,
                "last_threat_level": severity,
            })
            .eq("user_email", email)
            .execute()
        )
        self.logger.warning("Vault locked for %s — reason: %s severity: %s", email, reason, severity)
    # =====================================================
    # Get vault state
    # =====================================================

    def get_vault_state(self, email: str):
        result = (
            supabase.table("vault_profiles")
            .select("*")
            .eq("user_email", email)
            .execute()
        )

        if not result.data:
            return None

        return result.data[0]


vault_auth_manager = VaultAuthManager()