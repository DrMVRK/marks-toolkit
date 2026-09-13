class AuthState:
    def __init__(
            self, 
            config, 
            user_store, 
            password_service,
            identity_service,
            registration_service,
            login_service,
            csrf_service
    ):
        
        self.config = config
        self.user_store = user_store
        self.password_service = password_service
        self.identity_service = identity_service
        self.registration_service = registration_service
        self.login_service = login_service
        self.csrf_service = csrf_service