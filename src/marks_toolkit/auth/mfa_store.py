from abc import ABC, abstractmethod


class MFAStore(ABC):

    # -------------------------
    # TOTP
    # -------------------------

    @abstractmethod
    def get_totp(self, user_id):
        pass

    @abstractmethod
    def create_totp(
        self,
        user_id,
        encrypted_secret,
    ):
        pass

    @abstractmethod
    def enable_totp(self, user_id):
        pass

    @abstractmethod
    def delete_totp(self, user_id):
        pass

    @abstractmethod
    def claim_totp_step(
        self,
        user_id,
        step,
    ):
        """
        Atomically claim a TOTP timestep for a user.

        Return True only if this timestep is newer than every
        previously accepted timestep.

        Return False if the timestep has already been used or
        is older than the last accepted timestep.
        """
        raise NotImplementedError

    # -------------------------
    # Passkeys
    # -------------------------

    @abstractmethod
    def list_passkeys(self, user_id):
        pass

    @abstractmethod
    def find_passkey_by_credential_id(
        self,
        credential_id,
    ):
        pass

    @abstractmethod
    def create_passkey(
        self,
        user_id,
        credential_id,
        public_key,
        sign_count,
        name=None,
    ):
        pass

    @abstractmethod
    def update_passkey_sign_count(
        self,
        passkey,
        sign_count,
    ):
        pass

    @abstractmethod
    def delete_passkey(
        self,
        user_id,
        passkey_id,
    ):
        pass

    # -------------------------
    # Recovery codes
    # -------------------------

    @abstractmethod
    def replace_recovery_codes(
        self,
        user_id,
        code_hashes,
    ):
        pass

    @abstractmethod
    def list_unused_recovery_codes(
        self,
        user_id,
    ):
        pass

    @abstractmethod
    def mark_recovery_code_used(
        self,
        recovery_code,
    ):
        pass

    @abstractmethod
    def consume_recovery_code(
        self,
        user_id,
        code_hash,
    ):
        """
        Atomically consume one unused recovery code.

        Return True only if an unused matching code existed
        and this call successfully marked it used.

        Return False if the code does not exist or was
        already consumed by another request.
        """
        raise NotImplementedError
    
    # -------------------------
    # Account MFA status
    # -------------------------

    @abstractmethod
    def has_enabled_mfa(self, user_id):
        pass