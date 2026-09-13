from .config import AuthConfig
from .routes import auth_bp
from .state import AuthState
from .user_store import UserStore
from .passwords import PasswordService
from .identity import IdentityService
from .registration import RegistrationService
from .login import LoginService
from .csrf import CSRFService

from flask_login import LoginManager


class AuthKit:
    def __init__(self):
        self.login_manager = LoginManager()

    def init_app(self, app, user_store):
        if not isinstance(user_store, UserStore):
            raise TypeError("user_store must be an instance of UserStore")

        config = AuthConfig(app)
        identity_service = IdentityService()
        csrf_service = CSRFService()

        self.login_manager.init_app(app)

        app.config["REMEMBER_COOKIE_DURATION"] = config.remember_duration
        app.config.setdefault("REMEMBER_COOKIE_HTTPONLY", True)
        app.config.setdefault("REMEMBER_COOKIE_SAMESITE", "Lax")

        @self.login_manager.user_loader
        def load_user(auth_id):
            return user_store.find_by_auth_id(auth_id)
        
        password_service = PasswordService(
            min_length = config.password_min_length,
            max_length = config.password_max_length
        )

        registration_service = RegistrationService(
            identity_service=identity_service,
            password_service=password_service,
            user_store=user_store
        )

        login_service = LoginService(
            user_store=user_store,
            password_service=password_service
        )

        state = AuthState(
            config = config, 
            user_store=user_store,
            password_service=password_service,
            identity_service=identity_service,
            registration_service=registration_service,
            login_service=login_service,
            csrf_service=csrf_service
        )

        app.extensions["marks_auth"] = state
        
        app.register_blueprint(
            auth_bp,
            url_prefix=config.url_prefix
        )