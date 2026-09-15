from .config import AuthConfig
from .routes import auth_bp
from .state import AuthState
from .user_store import UserStore
from .passwords import PasswordService
from .identity import IdentityService
from .registration import RegistrationService
from .login import LoginService
from .csrf import CSRFService
from .reset_tokens import ResetTokenService
from .password_reset import PasswordResetService
from .mailer import ConsoleMailer
from .risk import RiskService
from .throttle import ThrottleService
from .security_store import (
    MemorySecurityStore,
    RedisSecurityStore,
)
from .audit import StandardAuditLogger
from .password_change import PasswordChangeService
from .secret_encryption import SecretEncryptionService
from .recovery_codes import RecoveryCodeService
from .totp import TotpService
from .recovery_code_manager import RecoveryCodeManager
from .mfa_challenge import (
    MFAChallengeService
)

from flask_login import LoginManager
from werkzeug.middleware.proxy_fix import ProxyFix


class AuthKit:
    def __init__(self):
        self.login_manager = LoginManager()

    def init_app(
        self,
        app,
        user_store,
        mailer=None,
        captcha_provider=None,
        mfa_store=None,
    ):
        if not isinstance(user_store, UserStore):
            raise TypeError(
                "user_store must be an instance of UserStore"
            )

        if mailer is None:
            mailer = ConsoleMailer()

        config = AuthConfig(app)

        # -------------------------------------------------
        # Required base configuration
        # -------------------------------------------------

        if not app.config.get("SECRET_KEY"):
            raise RuntimeError(
                "MARKS AuthKit requires Flask SECRET_KEY "
                "to be configured."
            )

        if not config.reset_url:
            raise RuntimeError(
                "MARKS AuthKit requires "
                "MARKS_AUTH_RESET_URL to be configured."
            )

        if captcha_provider is None:
            raise RuntimeError(
                "MARKS AuthKit requires an explicit "
                "CAPTCHA provider."
            )

        # -------------------------------------------------
        # Proxy handling
        # -------------------------------------------------

        if config.proxy_fix_enabled:
            app.wsgi_app = ProxyFix(
                app.wsgi_app,
                x_for=config.proxy_fix_x_for,
                x_proto=config.proxy_fix_x_proto,
            )

        # -------------------------------------------------
        # Core services
        # -------------------------------------------------

        identity_service = IdentityService()
        csrf_service = CSRFService()

        password_service = PasswordService(
            min_length=config.password_min_length,
            max_length=config.password_max_length,
        )

        mfa_challenge_service = (
            MFAChallengeService(
                ttl_seconds=(
                    config.mfa_challenge_ttl
                )
            )
        )

        # -------------------------------------------------
        # MFA services
        # -------------------------------------------------

        secret_encryption_service = None
        recovery_code_service = None
        totp_service = None
        recovery_code_manager = None

        if config.mfa_enabled:
            if mfa_store is None:
                raise RuntimeError(
                    "MFA is enabled but no MFAStore "
                    "was provided."
                )

            if not config.mfa_encryption_key:
                raise RuntimeError(
                    "MFA is enabled but "
                    "MARKS_AUTH_MFA_ENCRYPTION_KEY "
                    "is not configured."
                )

            if not config.recovery_code_key:
                raise RuntimeError(
                    "MFA is enabled but "
                    "MARKS_AUTH_RECOVERY_CODE_KEY "
                    "is not configured."
                )

            secret_encryption_service = (
                SecretEncryptionService(
                    config.mfa_encryption_key
                )
            )

            recovery_code_service = (
                RecoveryCodeService(
                    config.recovery_code_key
                )
            )

            recovery_code_manager = (
                RecoveryCodeManager(
                    mfa_store=mfa_store,
                    recovery_code_service=(
                        recovery_code_service
                    ),
                    password_service=password_service,
                )
            )

            totp_service = TotpService(
                mfa_store=mfa_store,
                encryption_service=(
                    secret_encryption_service
                ),
                issuer_name=config.totp_issuer,
            )

        # -------------------------------------------------
        # Flask-Login
        # -------------------------------------------------

        self.login_manager.init_app(app)

        self.login_manager.session_protection = (
            config.session_protection
        )

        app.config["REMEMBER_COOKIE_DURATION"] = (
            config.remember_duration
        )

        app.config["REMEMBER_COOKIE_HTTPONLY"] = True
        app.config["REMEMBER_COOKIE_SAMESITE"] = (
            config.cookie_samesite
        )
        app.config["REMEMBER_COOKIE_SECURE"] = (
            config.cookie_secure
        )

        app.config["SESSION_COOKIE_HTTPONLY"] = True
        app.config["SESSION_COOKIE_SAMESITE"] = (
            config.cookie_samesite
        )
        app.config["SESSION_COOKIE_SECURE"] = (
            config.cookie_secure
        )

        @self.login_manager.user_loader
        def load_user(auth_id):
            return user_store.find_by_auth_id(
                auth_id
            )

        @self.login_manager.unauthorized_handler
        def unauthorized():
            return {
                "ok": False,
                "error": {
                    "code": "AUTH_REQUIRED",
                    "message": (
                        "Authentication is required."
                    ),
                },
            }, 401

        # -------------------------------------------------
        # Authentication services
        # -------------------------------------------------

        registration_service = (
            RegistrationService(
                identity_service=identity_service,
                password_service=password_service,
                user_store=user_store,
            )
        )

        login_service = LoginService(
            user_store=user_store,
            password_service=password_service,
            identity_service=identity_service,
        )

        reset_token_service = (
            ResetTokenService(
                secret_key=app.config["SECRET_KEY"],
                max_age=config.reset_token_ttl,
            )
        )

        password_reset_service = (
            PasswordResetService(
                user_store=user_store,
                identity_service=identity_service,
                password_service=password_service,
                reset_token_service=(
                    reset_token_service
                ),
                mailer=mailer,
            )
        )

        password_change_service = (
            PasswordChangeService(
                user_store=user_store,
                password_service=password_service,
            )
        )

        # -------------------------------------------------
        # Shared security state
        # -------------------------------------------------

        if (
            config.security_store_backend
            == "memory"
        ):
            security_store = (
                MemorySecurityStore()
            )

        elif (
            config.security_store_backend
            == "redis"
        ):
            if not config.redis_url:
                raise RuntimeError(
                    "MARKS_AUTH_REDIS_URL is required "
                    "when using the Redis security store."
                )

            security_store = (
                RedisSecurityStore(
                    redis_url=config.redis_url
                )
            )

        else:
            raise RuntimeError(
                "Unsupported "
                "MARKS_AUTH_SECURITY_STORE: "
                f"{config.security_store_backend}"
            )

        risk_service = RiskService(
            security_store=security_store,
            captcha_threshold=(
                config.login_captcha_threshold
            ),
            block_threshold=(
                config.login_block_threshold
            ),
            failure_window_seconds=(
                config.login_failure_window
            ),
        )

        throttle_service = (
            ThrottleService(
                security_store=security_store
            )
        )

        audit_logger = StandardAuditLogger()

        # -------------------------------------------------
        # Shared application state
        # -------------------------------------------------

        state = AuthState(
            config=config,
            user_store=user_store,
            password_service=password_service,
            identity_service=identity_service,
            registration_service=(
                registration_service
            ),
            login_service=login_service,
            csrf_service=csrf_service,
            reset_token_service=(
                reset_token_service
            ),
            password_reset_service=(
                password_reset_service
            ),
            mailer=mailer,
            risk_service=risk_service,
            captcha_provider=captcha_provider,
            throttle_service=throttle_service,
            security_store=security_store,
            audit_logger=audit_logger,
            password_change_service=(
                password_change_service
            ),
            mfa_store=mfa_store,
            secret_encryption_service=(
                secret_encryption_service
            ),
            recovery_code_service=(
                recovery_code_service
            ),
            totp_service=totp_service,
            recovery_code_manager=(
                recovery_code_manager
            ),
            mfa_challenge_service=(
                mfa_challenge_service
            ),
        )

        app.extensions["marks_auth"] = state

        app.register_blueprint(
            auth_bp,
            url_prefix=config.url_prefix,
        )