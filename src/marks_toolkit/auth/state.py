class AuthState:
    def __init__(
            self, 
            config, 
            user_store, 
            password_service,
            identity_service
    ):
        
        self.config = config
        self.user_store = user_store
        self.password_service = password_service
        self.identity_service = identity_service