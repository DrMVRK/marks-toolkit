# MARKS Toolkit

A reusable Python/Flask authentication and application-security toolkit with a companion React authentication frontend.

The goal of MARKS Toolkit is to provide a set of reusable, security-focused components that can be dropped into future applications without rebuilding authentication, session management, password recovery, MFA, CAPTCHA, throttling, and related infrastructure from scratch.

The toolkit is designed around:

* Reusable services instead of application-specific logic
* Replaceable storage adapters
* Secure defaults
* Explicit configuration
* Separation of backend, persistence, and frontend concerns
* Minimal integration work for host applications
* Testable authentication flows
* Production-oriented architecture without tying the toolkit to one database or frontend design

---

# Current Status

The toolkit currently includes a functional authentication system with:

* User registration
* Email and username identity handling
* Case-insensitive identity lookup
* Argon2 password hashing
* Transparent password rehashing
* Login and logout
* Remember-me sessions
* Session protection
* Authentication ID rotation
* Password changing
* Password reset
* CSRF protection
* Adaptive CAPTCHA
* Login risk tracking
* Request throttling
* Security event auditing
* Redis-backed security-state support
* SQLAlchemy persistence adapters
* TOTP authenticator MFA
* QR-code authenticator enrollment
* Manual authenticator setup keys
* MFA login challenges
* Single-use recovery codes
* Password reauthentication for sensitive MFA actions
* Reusable React authentication components
* Reusable MFA settings UI

The automated backend test suite currently contains more than 70 passing authentication and security tests.

Passkey/WebAuthn support is the next major authentication feature planned.

---

# Project Structure

```text
marks-toolkit/
├── pyproject.toml
├── README.md
├── test_app.py
├── test_risk.py
│
├── frontend/
│   └── auth/
│       ├── AuthClient.js
│       ├── AuthProvider.jsx
│       ├── AuthModal.jsx
│       ├── LoginView.jsx
│       ├── RegisterView.jsx
│       ├── ForgotPasswordView.jsx
│       ├── ResetPasswordView.jsx
│       ├── CaptchaChallenge.jsx
│       ├── MFAChallengeView.jsx
│       ├── MFASettings.jsx
│       ├── ReauthDialog.jsx
│       └── auth.css
│
├── frontend-test/
│   └── src/
│       ├── App.jsx
│       └── auth/
│
├── src/
│   └── marks_toolkit/
│       └── auth/
│           ├── __init__.py
│           ├── extensions.py
│           ├── config.py
│           ├── state.py
│           ├── routes.py
│           │
│           ├── user_contract.py
│           ├── user_store.py
│           ├── sqlalchemy_models.py
│           ├── sqlalchemy_store.py
│           │
│           ├── passwords.py
│           ├── identity.py
│           ├── registration.py
│           ├── login.py
│           ├── password_change.py
│           ├── password_reset.py
│           ├── reset_tokens.py
│           │
│           ├── csrf.py
│           ├── decorators.py
│           ├── throttle.py
│           ├── risk.py
│           ├── security_store.py
│           │
│           ├── captcha.py
│           ├── mailer.py
│           ├── audit.py
│           │
│           ├── mfa.py
│           ├── mfa_store.py
│           ├── memory_mfa_store.py
│           ├── sqlalchemy_mfa_store.py
│           ├── secret_encryption.py
│           ├── recovery_codes.py
│           ├── recovery_code_manager.py
│           ├── totp.py
│           └── mfa_challenge.py
│
└── tests/
    ├── conftest.py
    ├── test_registration.py
    ├── test_login.py
    ├── test_login_risk.py
    ├── test_password_reset.py
    ├── test_password_change.py
    ├── test_password_rehash.py
    ├── test_session.py
    ├── test_throttling.py
    ├── test_audit.py
    ├── test_totp.py
    ├── test_totp_disable.py
    ├── test_recovery_codes.py
    ├── test_mfa_login.py
    └── test_mfa_throttling.py
```

---

# Backend Architecture

MARKS Toolkit uses a service-oriented authentication architecture.

The Flask application does not directly contain most authentication logic. Instead, the `AuthKit` extension assembles services and adapters based on the host application's configuration.

Conceptually:

```text
Flask Application
        │
        ▼
     AuthKit
        │
        ├── Configuration
        ├── User Store
        ├── Password Service
        ├── Identity Service
        ├── Registration Service
        ├── Login Service
        ├── Password Reset Service
        ├── Password Change Service
        ├── CSRF Service
        ├── Risk Service
        ├── Throttle Service
        ├── Audit Logger
        ├── CAPTCHA Provider
        │
        └── MFA Services
              ├── MFA Store
              ├── TOTP Service
              ├── Recovery Codes
              ├── Secret Encryption
              └── MFA Challenges
```

Application-specific dependencies are stored in:

```python
app.extensions["marks_auth"]
```

This prevents shared extension objects from accidentally holding state belonging to a specific Flask application.

---

# Installation

Create and activate a virtual environment.

Windows PowerShell:

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
```

Install the project in editable development mode:

```powershell
pip install -e ".[dev]"
```

The project currently depends on libraries including:

```text
Flask
Flask-Login
argon2-cffi
httpx
redis
SQLAlchemy
email-validator
cryptography
pyotp
pytest
```

---

# Basic Flask Integration

A host application creates its normal Flask app and initializes `AuthKit`.

Conceptually:

```python
from flask import Flask
from marks_toolkit.auth import AuthKit

app = Flask(__name__)

app.config["SECRET_KEY"] = "replace-me"

auth = AuthKit()

auth.init_app(
    app,
    user_store=user_store,
    captcha_provider=captcha_provider,
    mfa_store=mfa_store,
)
```

Storage and external-service dependencies are deliberately supplied by the host application rather than hard-coded into the toolkit.

---

# User Store

The authentication system interacts with application users through the `UserStore` contract.

Required capabilities include operations such as:

```text
find_by_identity
find_by_auth_id
email_exists
username_exists
create_user
rotate_auth_id
update_password
update_password_and_rotate_auth_id
```

This allows the authentication system to remain independent from a particular ORM or database schema.

A SQLAlchemy implementation is included.

---

# Authentication IDs

MARKS Toolkit distinguishes between:

```text
Database User ID
```

and:

```text
Authentication ID
```

The database user ID is stable.

The authentication ID can be rotated after sensitive account operations.

This allows existing authentication sessions to become invalid without changing the user's permanent database identity.

Operations such as password resets and password changes can rotate the authentication ID.

---

# Password Security

Passwords are hashed using Argon2.

The password service supports:

* Password validation
* Password hashing
* Password verification
* Hash-upgrade detection
* Transparent rehashing after successful login

If password hashing parameters change later, users can automatically receive a stronger hash the next time they successfully authenticate.

Plaintext passwords are never persisted by the toolkit.

---

# Registration

Registration includes:

* Email validation
* Username validation
* Password-policy enforcement
* Duplicate email detection
* Duplicate username detection
* Normalized identity values
* Case-insensitive identity comparison

Email validation uses `email-validator`.

Network deliverability checks are disabled by default so account creation does not depend on DNS/network validation.

---

# Login

Users can authenticate using their configured identity, such as:

```text
email
username
```

Login supports:

* Password verification
* Remember-me sessions
* Risk evaluation
* CAPTCHA escalation
* Transparent password rehashing
* MFA challenge initiation
* Security auditing

When MFA is not enabled, successful password verification creates the authenticated session immediately.

When MFA is enabled, successful password verification creates an MFA challenge instead.

---

# MFA Login Flow

For an MFA-enabled account:

```text
Username / Email
        +
     Password
        │
        ▼
 Password Verified
        │
        ▼
 MFA Challenge Created
        │
        ├── TOTP Authenticator
        │
        └── Recovery Code
        │
        ▼
 Second Factor Verified
        │
        ▼
 Authenticated Session
```

Entering the correct password alone does not authenticate an MFA-enabled account.

The final Flask-Login session is created only after the second factor succeeds.

---

# TOTP Authenticator MFA

MARKS Toolkit currently supports standards-based TOTP authenticator applications.

Examples include:

* Google Authenticator
* Microsoft Authenticator
* 1Password
* Authy-compatible TOTP clients
* Other applications supporting `otpauth://` TOTP enrollment

Enrollment generates:

* A random TOTP secret
* An `otpauth://` provisioning URI
* A QR code in the React frontend
* A manual Base32 setup key

The user must successfully verify a TOTP code before enrollment becomes active.

---

# TOTP Secret Protection

TOTP secrets cannot be stored using one-way password hashing because the original secret must be available when verifying future codes.

For this reason, TOTP secrets are encrypted using Fernet.

A production application must provide an encryption key externally:

```text
MARKS_AUTH_MFA_ENCRYPTION_KEY
```

The encryption key must not be stored alongside encrypted secrets in the database.

---

# Recovery Codes

Users with MFA enabled can generate emergency recovery codes.

Recovery codes are:

* Randomly generated
* Displayed only when generated
* Stored only as keyed hashes
* Single-use
* Invalidated when a new recovery-code set is generated

The backend uses HMAC-SHA256 with a separate application secret.

Configuration:

```text
MARKS_AUTH_RECOVERY_CODE_KEY
```

Recovery-code hashing and TOTP-secret encryption intentionally use different keys.

---

# MFA Recovery-Code Login

A recovery code can be used instead of a TOTP code during an MFA login challenge.

Once successfully used:

```text
Recovery Code
     │
     ▼
Verified
     │
     ▼
Marked Used
     │
     ▼
Cannot Be Used Again
```

This allows account recovery if the user loses access to their authenticator device.

---

# MFA Reauthentication

Sensitive MFA management operations require the user to confirm their current password.

The reusable React frontend includes `ReauthDialog.jsx` for this purpose.

It is currently used for actions including:

* Generating new recovery codes
* Disabling authenticator MFA

The component is intended to be reusable for other sensitive account operations in the future.

---

# MFA Configuration

Example configuration:

```python
app.config.update(
    MARKS_AUTH_MFA_ENABLED=True,

    MARKS_AUTH_MFA_ENCRYPTION_KEY=...,

    MARKS_AUTH_RECOVERY_CODE_KEY=...,

    MARKS_AUTH_TOTP_ISSUER="My Application",

    MARKS_AUTH_MFA_CHALLENGE_TTL=300,

    MARKS_AUTH_MFA_CHALLENGE_ATTEMPT_LIMIT=5,

    MARKS_AUTH_MFA_CHALLENGE_ATTEMPT_WINDOW=300,
)
```

When MFA is enabled, the application must provide the necessary MFA storage and cryptographic keys.

---

# MFA Storage

The toolkit defines an `MFAStore` abstraction.

Current implementations include:

```text
MemoryMFAStore
SQLAlchemyMFAStore
```

`MemoryMFAStore` is intended for:

* Automated tests
* Development
* Demonstration applications

It is not appropriate for production deployment because all MFA state disappears when the application restarts.

---

# SQLAlchemy MFA Models

SQLAlchemy models currently include structures for:

```text
TOTP enrollment
Recovery codes
Passkeys
```

TOTP and recovery-code flows are implemented.

Passkey persistence structures exist as groundwork for upcoming WebAuthn support, but the full passkey registration/authentication flow is not yet implemented.

MFA records reference the user's permanent database ID rather than the rotating authentication ID.

---

# Password Change

Authenticated users can change their password by supplying:

```text
current password
new password
```

After a successful password change:

1. The new password is hashed.
2. The user's authentication ID is rotated.
3. Existing authentication state is invalidated.
4. The current user is logged out.
5. Fresh authentication is required.

---

# Password Reset

The password-reset system supports:

```text
Forgot Password
      │
      ▼
Request Reset
      │
      ▼
Reset Token
      │
      ▼
Reset URL / Mailer
      │
      ▼
New Password
      │
      ▼
Authentication ID Rotated
```

The toolkit supports a replaceable mailer abstraction.

A console mailer is available for development.

Production applications can provide their own email implementation.

---

# CSRF Protection

State-changing authentication requests require CSRF protection.

The React `AuthClient` automatically manages the authentication API's CSRF token.

The frontend initializes authentication state using endpoints such as:

```text
/auth/config
/auth/csrf
/auth/me
```

---

# CAPTCHA

The toolkit supports adaptive CAPTCHA rather than forcing every user through a challenge.

The login-risk system can require CAPTCHA after suspicious or repeated authentication attempts.

Cloudflare Turnstile support is available through the CAPTCHA provider architecture.

The development test application can use Cloudflare's official Turnstile testing credentials.

---

# Risk Tracking

`RiskService` tracks authentication failures through the configured security store.

Risk state can be used to determine when additional security controls should be required.

For example:

```text
normal login
    │
failed attempts
    │
risk increases
    │
CAPTCHA required
    │
continued failures
    │
authentication blocked / throttled
```

---

# Request Throttling

`ThrottleService` provides reusable rate limiting for security-sensitive endpoints.

Current use cases include:

* Login
* Password reset
* Forgot-password requests
* MFA challenges
* Other sensitive authentication operations

Memory-backed state is available during development.

Redis-backed state is available for persistent/distributed deployments.

---

# Redis Security Store

`RedisSecurityStore` supports shared authentication security state between application processes.

This is important when running multiple workers because in-memory counters are not shared across processes.

Redis support currently includes expiring attempt counters suitable for:

* Risk tracking
* Authentication throttling
* MFA attempt throttling

The adapter exists, although production Redis integration testing remains part of future deployment hardening.

---

# Sessions

The toolkit uses Flask-Login for authenticated session handling.

Configuration includes support for:

* Remember-me cookies
* HTTP-only cookies
* Secure cookies
* SameSite policies
* Strong session protection
* JSON unauthorized responses

Production deployments should enable secure cookies when HTTPS is used.

Example:

```python
app.config.update(
    MARKS_AUTH_COOKIE_SECURE=True
)
```

Development over plain HTTP can disable secure-cookie enforcement.

---

# Reverse Proxy Support

Applications deployed behind Nginx, Cloudflare, or another reverse proxy can enable configurable Werkzeug `ProxyFix` support.

Only trusted proxy hops should be configured.

Incorrect proxy configuration can allow clients to spoof information such as their apparent IP address.

---

# Audit Logging

Authentication activity can be recorded through the audit logging system.

Examples include:

```text
login_success
login_failure
captcha_required
rate_limited
password_changed
mfa_challenge_created
totp_enrollment_started
totp_enabled
totp_disabled
recovery_codes_generated
MFA verification failures
```

Sensitive values are filtered from audit metadata.

Fields such as the following should never be recorded:

```text
password
password_hash
token
captcha_token
TOTP secret
```

The host application remains responsible for configuring the Python logging destination and retention policy.

---

# Frontend Architecture

The reusable React frontend is located under:

```text
frontend/auth/
```

Its purpose is to provide working authentication behavior while allowing future applications to replace or extend the appearance.

The host application should primarily customize:

* Theme
* Colors
* Typography
* Layout
* Branding

rather than rewriting authentication logic.

---

# AuthClient

`AuthClient.js` provides the frontend API layer.

It handles operations including:

```text
configuration loading
CSRF loading
session lookup
login
logout
registration
password reset
MFA challenge completion
```

Requests include browser credentials so Flask sessions remain available.

---

# AuthProvider

`AuthProvider.jsx` exposes reusable authentication state to React components.

Typical values include:

```text
client
config
ready
user
authenticated
handleLogin
logout
```

This prevents host applications from having to independently implement authentication-state management.

---

# AuthModal

Authentication is modal-first.

`AuthModal.jsx` controls views such as:

```text
Login
Register
Forgot Password
Reset Password
MFA Challenge
```

This allows a host application to open authentication from anywhere rather than requiring dedicated login pages.

---

# MFA Challenge View

`MFAChallengeView.jsx` handles second-factor login.

Current supported methods include:

```text
TOTP authenticator code
Recovery code
```

The user remains unauthenticated until one of these methods succeeds.

---

# MFA Settings

`MFASettings.jsx` provides reusable authenticated-account MFA management.

Current functionality includes:

* Display MFA status
* Start TOTP enrollment
* Display QR enrollment code
* Display manual setup key
* Verify TOTP enrollment
* Generate recovery codes
* Display newly generated recovery codes
* Disable TOTP
* Refresh MFA status
* Password reauthentication for sensitive actions

---

# QR Enrollment

The frontend uses:

```text
qrcode.react
```

to generate a QR code from the backend-generated TOTP provisioning URI.

The secret is never sent to a third-party QR-generation service.

QR generation occurs locally in the browser.

A manual setup key remains available as a fallback.

---

# Reauthentication Dialog

`ReauthDialog.jsx` provides a reusable password-confirmation UI for sensitive operations.

This replaces browser-native `window.prompt()` dialogs and allows the authentication experience to remain:

* Styled
* Accessible
* Reusable
* Application controlled

Future uses may include:

* Password changes
* Passkey deletion
* Email changes
* Account deletion
* Other high-risk account changes

---

# Frontend Dependencies

The reusable MFA enrollment UI currently uses:

```bash
npm install qrcode.react
```

The host frontend is responsible for providing React.

---

# Development Test Application

`test_app.py` provides a development environment for manually exercising the authentication toolkit.

It currently uses:

```text
Memory user store
Memory MFA store
Development encryption keys
Development recovery-code key
Cloudflare Turnstile test credentials
Console mailer
```

Example development account:

```text
Email:
mark@example.com

Username:
Mark

Password:
TestingPassword123!
```

These credentials exist only for local development.

---

# Important Development Behavior

The development application uses in-memory persistence.

Restarting Flask resets:

* Users
* MFA enrollments
* Recovery codes
* Some security state

The development application may also generate a new temporary MFA encryption key at startup.

Therefore MFA enrollment should be considered temporary when using `test_app.py`.

Production applications must use persistent storage and stable externally managed keys.

---

# Running the Backend Test App

From the project root:

```powershell
python test_app.py
```

The development Flask server normally runs at:

```text
http://127.0.0.1:5000
```

A basic health endpoint is available at:

```text
/auth/test
```

---

# Running the Frontend Test Harness

From:

```text
frontend-test/
```

install dependencies:

```powershell
npm install
```

then run:

```powershell
npm run dev
```

Vite normally provides the frontend at a local development URL such as:

```text
http://localhost:5173
```

The Vite development proxy forwards `/auth` requests to Flask.

---

# Frontend Test Harness Note

`frontend-test/src/auth/` currently contains development copies of the reusable components from:

```text
frontend/auth/
```

When reusable frontend components are modified, their test-harness copies must also be updated.

This duplication exists for development/testing convenience and may later be replaced with direct package imports.

---

# Testing

Run the backend test suite with:

```powershell
pytest
```

The suite currently covers areas including:

* Registration
* Login
* Identity handling
* Password security
* Password rehashing
* Password reset
* Password changing
* Sessions
* Risk tracking
* Throttling
* Audit logging
* TOTP enrollment
* TOTP disabling
* Recovery codes
* MFA login
* MFA throttling

The current suite contains more than 70 passing tests.

---

# Security Principles

MARKS Toolkit follows several core security rules.

## Never Trust Client Input

All meaningful authorization and validation occurs on the backend.

Frontend checks exist for usability, not security.

---

## Never Store Plaintext Passwords

Passwords are hashed using Argon2.

---

## Never Store Plaintext Recovery Codes

Recovery codes are stored using keyed HMAC hashes.

---

## Encrypt Recoverable Authentication Secrets

TOTP secrets are encrypted because they must later be recovered for verification.

---

## Keep Encryption Keys Outside the Database

Possessing both the encrypted database value and the encryption key defeats the purpose of application-level secret encryption.

---

## Rotate Authentication State After Credential Changes

Password-reset and password-change operations rotate the user's authentication ID.

---

## MFA Password Verification Is Not Authentication

When MFA is enabled, successful password verification creates only a pending MFA challenge.

A login session is created only after the second factor succeeds.

---

## Sensitive MFA Actions Require Reauthentication

Actions such as disabling MFA or regenerating recovery codes require the user's current password.

Additional step-up policies may be added later.

---

## Recovery Codes Are Single Use

Once successfully consumed, a recovery code cannot authenticate again.

---

## Rate Limit Authentication Endpoints

Login, reset, CAPTCHA, and MFA endpoints should always be protected from automated guessing.

---

## Audit Security Events, Not Secrets

Authentication events should be visible to operators without leaking credentials or secret material into logs.

---

# Production Requirements

Before using MARKS Toolkit in a production application, the host application should provide:

* A persistent `UserStore`
* A persistent `MFAStore`
* A production database
* Stable secret keys
* HTTPS
* Secure cookies
* Appropriate reverse-proxy configuration
* Production CAPTCHA credentials
* A production mail provider
* Redis or another persistent security-state store where appropriate
* Central logging
* Database migrations
* Secret-management infrastructure
* Backup and recovery procedures

The in-memory development adapters are not production persistence mechanisms.

---

# Environment / Secret Management

Secrets should be supplied through environment variables or an external secret manager.

Examples include:

```text
FLASK SECRET KEY
MARKS_AUTH_MFA_ENCRYPTION_KEY
MARKS_AUTH_RECOVERY_CODE_KEY
CAPTCHA SECRET
DATABASE CREDENTIALS
REDIS CREDENTIALS
MAIL CREDENTIALS
```

Do not commit production secrets to Git.

---

# Planned Work

The next major areas of development include:

## Passkeys / WebAuthn

Planned functionality includes:

* Passkey registration
* WebAuthn registration challenge
* WebAuthn authentication challenge
* Credential public-key storage
* Signature-counter validation
* Passkey naming
* Passkey removal
* Passkey-based MFA
* Potential passwordless authentication

Initial SQLAlchemy passkey persistence structures already exist.

---

## MFA Hardening

Planned improvements include:

* TOTP replay prevention
* More granular MFA attempt throttling
* Recent-authentication policies
* Additional protection for MFA configuration changes
* Explicit challenge cancellation
* Challenge-state hardening for distributed deployments
* Recovery-code lifecycle policy when the final MFA factor is removed

---

## Persistent Deployment Integration

Planned work includes:

* Production SQLAlchemy integration tests
* Database migrations
* Alembic integration
* Redis integration tests
* Multi-worker deployment testing
* Persistent MFA-store tests

---

## Session Management

Potential future capabilities include:

* Session registry
* View active sessions
* Revoke individual sessions
* Revoke all other sessions
* Device/session metadata
* Security notifications

---

## Frontend Improvements

Planned frontend improvements include:

* Passkey management
* Recovery-code download/copy controls
* Better confirmation dialogs
* Accessibility refinement
* Host-provided branding hooks
* Additional styling primitives
* Packaging reusable frontend components for direct import

---

# Design Goal

The long-term goal is for a new application to require only a relatively small amount of authentication-specific setup.

Instead of rebuilding:

```text
registration
login
password security
password reset
sessions
CSRF
CAPTCHA
rate limiting
MFA
recovery codes
security logging
frontend auth state
auth modals
```

every project should be able to compose those capabilities from MARKS Toolkit and focus primarily on the application's actual business logic.

---

# Development Philosophy

This project intentionally favors:

```text
configuration over hard-coding
interfaces over tight coupling
small services over giant modules
explicit security controls over implicit behavior
persistent IDs over session identifiers
tests over assumptions
reusable components over copy-and-paste application code
```

The toolkit is being developed incrementally, with each authentication capability tested independently before becoming part of the reusable system.
