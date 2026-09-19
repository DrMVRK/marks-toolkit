class AuthState:
    def __init__(
            self, 
            config, 
            user_store, 
            password_service,
            identity_service,
            registration_service,
            login_service,
            csrf_service,
            reset_token_service,
            password_reset_service,
            mailer,
            risk_service,
            captcha_provider,
            throttle_service,
            security_store,
            audit_logger,
            password_change_service,
            mfa_store,
            secret_encryption_service,
            recovery_code_service,
            totp_service,
            recovery_code_manager,
            mfa_challenge_service,
            passkey_store=None,
            webauthn_challenge_store=None,
            passkey_service=None,
    ):
        
        self.config = config
        self.user_store = user_store
        self.password_service = password_service
        self.identity_service = identity_service
        self.registration_service = registration_service
        self.login_service = login_service
        self.csrf_service = csrf_service
        self.reset_token_service = reset_token_service
        self.password_reset_service = password_reset_service
        self.mailer = mailer
        self.risk_service = risk_service
        self.captcha_provider = captcha_provider
        self.throttle_service = throttle_service
        self.security_store = security_store
        self.audit_logger = audit_logger
        self.password_change_service = password_change_service
        self.mfa_store = mfa_store
        self.secret_encryption_service = secret_encryption_service
        self.recovery_code_service =  recovery_code_service
        self.totp_service = totp_service
        self.recovery_code_manager = recovery_code_manager 
        self.mfa_challenge_service = mfa_challenge_service
        self.passkey_store = passkey_store
        self.webauthn_challenge_store = webauthn_challenge_store
        self.passkey_service = passkey_service
        