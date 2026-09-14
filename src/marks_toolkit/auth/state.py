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