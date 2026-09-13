from .config import AuthConfig
from .routes import auth_bp
from .state import AuthState
from .user_store import UserStore
from .passwords import PasswordService
from .identity import IdentityService


class AuthKit:
    def __init__(self):
        pass

    def init_app(self, app, user_store):
        if not isinstance(user_store, UserStore):
            raise TypeError("user_store must be an instance of UserStore")

        config = AuthConfig(app)
        identity_service = IdentityService()
        
        password_service = PasswordService(
            min_length = config.password_min_length,
            max_length = config.password_max_length
        )

        state = AuthState(
            config = config, 
            user_store=user_store,
            password_service=password_service,
            identity_service=identity_service
        )

        app.extensions["marks_auth"] = state
        
        app.register_blueprint(
            auth_bp,
            url_prefix=config.url_prefix
        )