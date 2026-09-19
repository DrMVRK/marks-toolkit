# MARKS Toolkit

A reusable Python/Flask authentication and application-security toolkit with companion React authentication components.

MARKS Toolkit provides reusable, security-focused authentication building blocks so future applications do not need to rebuild registration, login, password recovery, MFA, passkeys, CAPTCHA, throttling, session security, and related infrastructure from scratch.

---

## Design Goals

MARKS Toolkit favors:

* reusable services instead of application-specific authentication logic
* replaceable persistence and provider adapters
* secure defaults
* explicit configuration
* separation of backend, persistence, and frontend concerns
* testable authentication flows
* minimal host-application integration
* production-oriented architecture without requiring one database or frontend stack
* policy separated from mechanism
* strong authentication primitives regardless of selected policy profile
* dedicated storage abstractions for separate authentication mechanisms

Applications choose which controls they require; AuthKit supplies the secure mechanisms underneath them.

---

## Current Status

Current capabilities include:

* user registration
* email and username identity handling
* case-insensitive identity lookup
* Argon2 password hashing
* transparent password rehashing
* dummy Argon2 verification for unknown or inactive users
* login and logout
* remember-me authentication
* Flask-Login session protection
* authentication-ID rotation
* password changing
* password reset
* CSRF protection
* strict JSON request validation
* adaptive CAPTCHA
* Cloudflare Turnstile support
* CAPTCHA hostname and action validation
* login risk tracking
* request throttling
* security event auditing
* Redis-backed shared security state
* SQLAlchemy persistence adapters
* TOTP authenticator MFA
* QR-code authenticator enrollment
* manual authenticator setup keys
* MFA login challenges
* Redis-backed distributed MFA challenge storage
* atomic MFA challenge consumption
* TOTP replay prevention
* atomic single-use recovery-code consumption
* password reauthentication for sensitive MFA operations
* authentication-state revocation after MFA enable/disable
* `Cache-Control: no-store` for secret-bearing responses
* WebAuthn/passkey registration
* passwordless passkey authentication
* discoverable WebAuthn credentials
* required WebAuthn user verification
* multiple passkeys per account
* passkey naming and deletion
* conditional passkey autofill
* explicit passkey login
* remembered-account passkey UX
* Redis-backed WebAuthn challenge storage
* atomic single-use WebAuthn challenges
* WebAuthn signature-counter validation
* atomic passkey signature-counter persistence
* reusable React authentication components
* reusable MFA settings UI
* reusable passkey-management UI
* reusable password-reauthentication dialog

The automated backend suite currently contains **218 passing authentication and security tests**.

---

## Authentication Architecture

MARKS Toolkit deliberately separates authentication mechanisms that have different security and persistence requirements.

```text
Authentication
├── Password authentication
│
├── Passkey authentication
│   ├── WebAuthn registration
│   ├── WebAuthn login
│   ├── Conditional UI
│   ├── Credential management
│   ├── MemoryPasskeyStore
│   └── SQLAlchemyPasskeyStore
│
└── MFA
    ├── TOTP
    └── Recovery codes
```

Passkeys are not stored through `MFAStore`.

Passkey credentials are managed through the dedicated `PasskeyStore` abstraction because WebAuthn credentials can authenticate a user directly rather than existing only as a second factor.

---

## Project Structure

```text
marks-toolkit/
├── pyproject.toml
├── README.md
├── test_app.py
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
│       ├── PasskeyEnrollment.jsx
│       ├── PasskeyManager.jsx
│       ├── ReauthDialog.jsx
│       └── auth.css
│
├── frontend-test/
│   ├── vite.config.js
│   └── src/
│       ├── App.jsx
│       └── main.jsx
│
├── src/
│   └── marks_toolkit/
│       └── auth/
│           ├── extensions.py
│           ├── config.py
│           ├── state.py
│           ├── routes.py
│           ├── responses.py
│           ├── request_validation.py
│           │
│           ├── user_store.py
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
│           ├── mfa_store.py
│           ├── memory_mfa_store.py
│           ├── sqlalchemy_mfa_store.py
│           ├── secret_encryption.py
│           ├── recovery_codes.py
│           ├── recovery_code_manager.py
│           ├── totp.py
│           ├── mfa_challenge.py
│           ├── mfa_challenge_store.py
│           │
│           ├── passkeys.py
│           ├── passkey_store.py
│           ├── memory_passkey_store.py
│           ├── sqlalchemy_passkey_store.py
│           ├── webauthn_challenge_store.py
│           │
│           ├── sqlalchemy_models.py
│           └── sqlalchemy_schema.py
│
└── tests/
```

---

## Installation

Create a virtual environment and install the project in editable development mode.

### Windows PowerShell

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -e ".[dev]"
```

### macOS/Linux

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

Core dependencies include:

* Flask
* Flask-Login
* Argon2
* HTTPX
* Redis
* SQLAlchemy
* email-validator
* cryptography
* PyOTP
* WebAuthn
* pytest

---

## Basic Flask Integration

```python
from flask import Flask
from marks_toolkit.auth import AuthKit

app = Flask(__name__)

app.config["SECRET_KEY"] = "replace-with-a-secret"

app.config["MARKS_AUTH_RESET_URL"] = (
    "https://example.com/reset-password"
)

auth = AuthKit()

auth.init_app(
    app,
    user_store=user_store,
    mailer=mailer,
    captcha_provider=captcha_provider,
    mfa_store=mfa_store,
    passkey_store=passkey_store,
)
```

Storage and external-service dependencies are supplied by the host application rather than hard-coded into the toolkit.

`mfa_store` is required when MFA features are enabled.

`passkey_store` is required when WebAuthn/passkey authentication is enabled.

---

## Required Security Configuration

### Flask Secret Key

A Flask `SECRET_KEY` is required.

Use a high-entropy value from environment or secret-management infrastructure in production.

### Password Reset URL

A reset URL is required:

```python
app.config["MARKS_AUTH_RESET_URL"] = (
    "https://example.com/reset-password"
)
```

Reset URLs must be absolute, contain a hostname, and must not contain embedded credentials.

HTTPS is required by default.

Plain HTTP is available only through an explicit development/testing opt-in:

```python
app.config[
    "MARKS_AUTH_ALLOW_INSECURE_RESET_URL"
] = True
```

Do not enable this in production.

### Mailer

An explicit mailer is required by default.

The console mailer can be enabled only through an explicit development/testing opt-in:

```python
app.config[
    "MARKS_AUTH_ALLOW_CONSOLE_MAILER"
] = True
```

Production applications should provide a real mailer implementation.

---

## User Store and Authentication IDs

Authentication is abstracted through the `UserStore` contract.

Important operations include:

```text
find_by_identity
find_by_auth_id
find_by_id
email_exists
username_exists
create_user
rotate_auth_id
update_password
update_password_and_rotate_auth_id
```

MARKS Toolkit distinguishes between a permanent database user ID and a rotating authentication ID.

Authentication-ID rotation invalidates old Flask-Login sessions and remember cookies without changing the permanent user identity.

Current operations that rotate authentication state include:

* password change
* password reset
* TOTP enable
* TOTP disable
* sensitive passkey credential-management operations where session refresh is required

Password changes and resets require fresh login afterward.

Some sensitive credential operations rotate authentication state while refreshing the current verified browser into a new session.

---

## Password Security

Passwords are protected with Argon2.

The password service supports:

* password-policy validation
* hashing
* verification
* hash-upgrade detection
* transparent rehashing

Unknown and inactive-user login attempts execute dummy Argon2 verification to reduce timing differences that could reveal account existence.

Plaintext passwords are never persisted by the toolkit.

---

## Request Validation

Authentication routes validate request bodies before business logic runs.

Shared validation helpers enforce:

* JSON object bodies
* required strings
* optional strings
* strict boolean values

Malformed input is rejected before reaching password, identity, CAPTCHA, MFA, or WebAuthn services.

---

## Login Risk and Throttling

`RiskService` tracks failures across independent buckets including:

* identity + IP
* identity-wide
* IP-wide

This makes simple IP or identity rotation less effective at bypassing risk controls.

`ThrottleService` protects sensitive operations including:

* registration
* login
* password actions
* MFA endpoints
* passkey enrollment
* passkey authentication

Malformed throttle identities are normalized rather than allowing malformed request bodies to create uncontrolled key variation.

For distributed deployments, shared state can be stored in Redis.

Redis-backed throttling uses atomic check-and-record behavior with sliding-window semantics.

---

## CAPTCHA

Cloudflare Turnstile support includes:

* server-side Siteverify validation
* fail-closed HTTP and JSON handling
* request timeouts
* token type and length validation
* optional allowed-hostname validation
* optional expected-action validation

Production applications should configure hostname restrictions and expected actions for the real deployment.

Adaptive login risk can require CAPTCHA only after suspicious or repeated authentication failures instead of forcing every user through a challenge.

---

## Sessions and Cookies

MARKS Toolkit uses Flask-Login.

Protections include:

* remember-me authentication
* HTTP-only session and remember cookies
* secure cookies
* SameSite handling
* session protection
* authentication-ID based revocation
* JSON unauthorized responses

Secure cookies are enabled by default.

For localhost development over plain HTTP only:

```python
app.config[
    "MARKS_AUTH_COOKIE_SECURE"
] = False
```

AuthKit will not weaken stronger cookie settings already configured by the host application.

### Remember-Cookie MFA Policy

Remember cookies issued before MFA is enabled are invalidated when the authentication ID rotates during MFA enrollment.

A remember cookie issued after successful password + MFA authentication may restore that authenticated session later without requiring MFA again.

### Passkey Remember Behavior

Passkey authentication does not issue Flask's long-lived remember cookie.

The frontend can optionally remember a single account hint locally so the user can be shown a convenience screen such as:

```text
Welcome back, Mark

Continue with passkey
Use password instead
Sign in with a different account
Forget this account
```

The remembered account hint is not authentication state and provides no server-side authority.

---

## Password Reset

The password-reset flow uses signed, time-limited reset tokens.

A successful reset:

1. validates the reset token
2. updates the password
3. rotates the authentication ID exactly once
4. invalidates old sessions and remember cookies

Reset URLs are assembled safely without unsafe query-string concatenation.

Because the authentication ID rotates on successful reset, the old reset token cannot be successfully reused afterward.

---

# MFA

## MFA Login

For an MFA-enabled user:

```text
Identity + Password
        │
        ▼
Password Verified
        │
        ▼
MFA Challenge Created
        │
        ├── TOTP
        └── Recovery Code
        │
        ▼
Second Factor Verified
        │
        ▼
Authenticated Session
```

Password verification alone does not authenticate an MFA-enabled account.

Pending MFA challenges are stored server-side. The Flask session stores only the challenge ID.

Challenge consumption is atomic, so a completed MFA challenge cannot be reused.

Available challenge stores:

```text
MemoryMFAChallengeStore
RedisMFAChallengeStore
```

The memory store is suitable for tests and single-process development.

When the security-store backend is Redis, AuthKit uses Redis-backed MFA challenge storage so challenge state is shared across workers.

---

## TOTP MFA

TOTP enrollment:

1. requires current-password reauthentication
2. creates a secret and provisioning URI
3. displays QR/manual enrollment data
4. requires successful code verification
5. activates TOTP only after verification

TOTP secrets are encrypted with Fernet and require a stable external key:

```text
MARKS_AUTH_MFA_ENCRYPTION_KEY
```

Successfully accepted TOTP time steps are claimed server-side so the same TOTP code cannot be replayed during its validity window.

---

## Recovery Codes

Recovery codes are:

* randomly generated
* displayed only when generated
* stored as keyed HMAC hashes
* consumed atomically
* single-use
* invalidated when a new set is generated
* invalidated when TOTP is disabled

Configuration:

```text
MARKS_AUTH_RECOVERY_CODE_KEY
```

Recovery-code hashing and TOTP-secret encryption intentionally use separate keys.

---

## Sensitive MFA Operations

Current-password reauthentication is required for:

* beginning TOTP enrollment
* generating recovery codes
* disabling TOTP

Enabling or disabling TOTP rotates the authentication ID so other sessions and remember cookies become invalid.

The current verified browser is refreshed into a new non-remembered authenticated session.

---

## MFA Storage

The toolkit defines an `MFAStore` abstraction.

Current implementations:

```text
MemoryMFAStore
SQLAlchemyMFAStore
```

`MFAStore` is responsible for:

```text
TOTP
Recovery codes
```

Passkeys are intentionally not part of this abstraction.

`MemoryMFAStore` is intended for tests and development.

Production applications using MFA should use persistent MFA storage.

---

# Passkeys / WebAuthn

MARKS Toolkit includes first-class WebAuthn/passkey authentication.

Passkeys can authenticate users directly and are therefore modeled independently from TOTP MFA.

Current WebAuthn functionality includes:

* passkey registration
* passkey login
* passwordless authentication
* discoverable credentials
* required resident-key support
* required user verification
* multiple credentials per account
* platform authenticators such as Windows Hello
* conditional passkey autofill
* explicit passkey-login fallback
* passkey names
* passkey deletion
* remembered-account UI
* authentication challenge expiration
* atomic challenge consumption
* Redis-backed challenge storage
* signature-counter validation
* atomic signature-counter persistence
* synced-passkey zero-counter compatibility

---

## WebAuthn Configuration

Example development configuration:

```python
app.config.update(
    MARKS_AUTH_WEBAUTHN_ENABLED=True,
    MARKS_AUTH_WEBAUTHN_RP_ID="localhost",
    MARKS_AUTH_WEBAUTHN_RP_NAME="MARKS Toolkit Development",
    MARKS_AUTH_WEBAUTHN_ORIGIN="http://localhost:5173",
    MARKS_AUTH_WEBAUTHN_CHALLENGE_TTL=300,
)
```

Production origins should use HTTPS.

Plain HTTP WebAuthn origins are only appropriate for recognized localhost development environments.

The RP ID must be a hostname-style identifier and must not include a URL scheme or path.

---

## Passkey Registration

Passkey enrollment:

1. requires an authenticated user
2. requires current-password reauthentication
3. creates a WebAuthn registration challenge
4. requests a discoverable credential
5. requires user verification
6. verifies the registration ceremony server-side
7. stores the credential public key and metadata
8. supports multiple credentials per account

The WebAuthn user handle is an opaque random identifier rather than an email address or database ID.

Existing credentials are excluded from subsequent registration ceremonies.

---

## Passkey Authentication

Passkey authentication supports two frontend paths.

### Explicit Authentication

The user can choose:

```text
Sign in with a passkey
```

The browser then invokes the authenticator directly.

### Conditional Authentication

Supported browsers may offer saved passkeys automatically from the username field through conditional WebAuthn mediation.

The username field uses:

```text
autocomplete="username webauthn"
```

The explicit passkey button remains available as a fallback.

---

## Passkey Signature Counters

Where authenticators provide non-zero signature counters, MARKS Toolkit verifies that the counter advances.

Stored counter updates use compare-and-set semantics so concurrent workers cannot overwrite newer passkey state with stale values.

Authenticators that legitimately use a zero counter, including some synced multi-device passkeys, remain supported.

---

## Passkey Management

Authenticated users can:

* list registered passkeys
* rename passkeys
* remove passkeys

The management API exposes only safe metadata such as:

* encoded credential identifier
* display name
* creation time
* last-used time
* transports

It does not expose:

* credential public keys
* WebAuthn user handles
* signature counters
* internal database IDs
* user IDs

Passkey deletion requires current-password reauthentication.

---

## Passkey Storage

Passkeys use a dedicated `PasskeyStore` abstraction.

Current implementations:

```text
MemoryPasskeyStore
SQLAlchemyPasskeyStore
```

This separation is intentional:

```text
MFAStore
├── TOTP
└── Recovery codes

PasskeyStore
└── WebAuthn credentials
```

Production applications with WebAuthn enabled must provide persistent passkey storage.

---

## WebAuthn Challenge Storage

Registration and authentication challenges are single-use.

Available implementations include:

```text
MemoryWebAuthnChallengeStore
RedisWebAuthnChallengeStore
```

The Redis implementation performs challenge consumption atomically so separate workers cannot successfully consume the same challenge.

When:

```python
MARKS_AUTH_SECURITY_STORE = "redis"
```

the WebAuthn challenge system also uses Redis.

This keeps security-sensitive challenge state shared across workers in distributed deployments.

---

## Secret-Bearing Responses

Responses exposing sensitive authentication material use:

```text
Cache-Control: no-store
```

This includes flows such as:

* TOTP enrollment secrets
* newly generated recovery codes
* WebAuthn ceremony data where caching would be undesirable

The React frontend also clears sensitive state after relevant flows complete or close.

---

## Redis

Redis-backed security state supports distributed deployments.

Example:

```python
app.config.update(
    MARKS_AUTH_SECURITY_STORE="redis",
    MARKS_AUTH_REDIS_URL="redis://localhost:6379/0",
)
```

Redis can provide shared state for:

* authentication throttling
* risk/security counters
* MFA challenges
* WebAuthn challenges

Production Redis should be protected with appropriate:

* network isolation
* authentication
* monitoring
* backup policy where applicable
* TLS where appropriate

---

## SQLAlchemy Persistence

SQLAlchemy-backed persistence exists for:

* users
* TOTP state
* recovery codes
* passkeys

Passkeys are represented by `AuthPasskeyModel` but are accessed through `SQLAlchemyPasskeyStore`, not `SQLAlchemyMFAStore`.

The toolkit also provides schema helpers for inspecting or creating its authentication tables.

Database migration execution remains the responsibility of the host application.

Host applications may integrate the provided SQLAlchemy metadata into Alembic or another migration workflow.

---

## Reverse Proxy Support

Configurable Werkzeug `ProxyFix` support is available for trusted reverse-proxy deployments.

Configure only the actual number of trusted proxy hops.

Incorrect forwarded-header trust can allow clients to spoof apparent IP addresses or request scheme information.

---

## Audit Logging

Security-relevant authentication events can be logged.

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
passkey_enrollment_started
passkey_enabled
passkey_login_success
passkey_login_failure
passkey_renamed
passkey_deleted
```

Sensitive data such as:

* passwords
* reset tokens
* CAPTCHA tokens
* TOTP secrets
* recovery codes
* cookies
* sessions
* provisioning URIs
* passkey credential secrets

must not be logged.

The host application is responsible for log destination, retention, access control, and centralized collection.

---

# React Frontend

Reusable React components live under:

```text
frontend/auth/
```

They provide:

* authentication API access
* authentication state management
* login view
* registration view
* forgot-password flow
* reset-password flow
* CAPTCHA integration
* MFA challenge handling
* MFA enrollment/settings
* passkey enrollment
* passkey management
* explicit passkey login
* conditional passkey authentication
* remembered-account UI
* reusable password reauthentication
* reusable authentication styling

The frontend uses browser-native WebAuthn APIs.

TOTP QR enrollment uses `qrcode.react` and is generated locally in the browser. The TOTP secret is not sent to a third-party QR service.

---

## Frontend Test Harness

`frontend-test/` is a development application for manually exercising the reusable authentication frontend.

The reusable frontend source of truth is:

```text
frontend/auth/
```

The development harness imports those components directly through the Vite alias:

```text
@marks-auth
```

The toolkit components are therefore no longer copied into a separate test-harness auth directory.

This reduces drift between development testing and the reusable components that host applications actually consume.

---

## Development Test Application

`test_app.py` is intentionally configured as a local development harness.

It may use:

* in-memory users
* in-memory MFA persistence
* in-memory passkey persistence
* in-memory challenge state
* development cryptographic keys
* Turnstile test credentials
* console mailer
* insecure localhost reset URL opt-in
* non-secure localhost cookies
* localhost WebAuthn origin

These development exceptions are explicit so they cannot silently become production defaults.

Example local account:

```text
Email:    mark@example.com
Username: Mark
Password: TestingPassword123!
```

Restarting the development application may reset:

* users
* MFA state
* recovery codes
* passkeys
* in-memory challenge state
* risk counters
* throttle counters

Production applications must use persistent storage and stable externally managed keys.

---

## Running the Development Harness

### Backend

```bash
python test_app.py
```

### Frontend

```bash
cd frontend-test
npm install
npm run dev
```

Use:

```text
http://localhost:5173
```

for WebAuthn development.

Do not substitute `127.0.0.1` when the configured WebAuthn RP ID is:

```text
localhost
```

The Vite development proxy forwards `/auth` requests to Flask.

---

# Testing

Run the backend suite with:

```bash
pytest
```

The current suite contains:

```text
218 passing tests
```

Coverage includes:

* registration
* login
* malformed-input handling
* password hashing and rehashing
* dummy password verification
* password reset
* password changes
* session behavior
* authentication-ID revocation
* remember-cookie MFA policy
* secure-cookie defaults
* reset URL validation
* mailer configuration
* risk tracking
* throttling
* atomic Redis throttle behavior
* sliding-window security-store semantics
* audit logging
* recursive audit-secret filtering
* CAPTCHA behavior
* Turnstile hostname/action validation
* TOTP enrollment
* TOTP replay prevention
* TOTP disabling
* recovery-code generation
* atomic recovery-code consumption
* MFA login
* MFA challenge replay prevention
* MFA throttling
* Redis MFA challenge behavior
* passkey persistence
* passkey registration
* passkey authentication
* passkey login routes
* passkey management
* WebAuthn challenge storage
* Redis WebAuthn challenge behavior
* WebAuthn challenge replay prevention
* WebAuthn signature-counter handling
* concurrent passkey counter protection
* passkey ownership enforcement
* no-store security responses

For frontend changes also run:

```bash
cd frontend-test
npm run build
```

Then manually exercise the affected authentication flow.

Dependency audits can be run with:

```bash
python -m pip_audit
npm audit
```

---

# Security Principles

MARKS Toolkit follows several core rules:

* backend validation is the security boundary
* plaintext passwords are never stored
* unknown-user authentication performs dummy Argon2 work
* recovery codes are never stored in plaintext
* recoverable MFA secrets are encrypted
* cryptographic keys should live outside the database
* authentication IDs rotate after supported credential changes
* password verification does not complete MFA authentication
* sensitive credential-management actions require reauthentication
* accepted TOTP time steps cannot be replayed
* recovery codes are atomically single-use
* MFA challenges are atomically single-use
* WebAuthn challenges are atomically single-use
* passkey signature counters are updated atomically
* distributed security state must be shared across workers
* secret-bearing responses should not be cached
* authentication endpoints require abuse controls
* audit logs must record events, not secrets
* remembered-account hints are never treated as authentication
* passkey ownership checks are enforced server-side
* WebAuthn user verification is required
* security policy and security mechanism remain separate

---

# Production Requirements

Before using MARKS Toolkit in production, provide:

* persistent `UserStore`
* persistent `MFAStore` when MFA is enabled
* persistent `PasskeyStore` when WebAuthn is enabled
* production database
* database migrations
* stable Flask secret key
* stable MFA encryption key when TOTP is enabled
* stable recovery-code HMAC key when recovery codes are enabled
* HTTPS
* secure cookies
* correct reverse-proxy configuration
* production CAPTCHA credentials
* CAPTCHA hostname/action restrictions
* production mail provider
* Redis-backed security state for multi-worker deployments
* centralized logging
* secret-management infrastructure
* backup and recovery procedures

The in-memory adapters are development/testing mechanisms, not production persistence.

---

# Production Deployment Checklist

## Secrets

* [ ] Flask `SECRET_KEY` is high entropy and externally managed
* [ ] `MARKS_AUTH_MFA_ENCRYPTION_KEY` is stable and externally managed when required
* [ ] `MARKS_AUTH_RECOVERY_CODE_KEY` is stable and externally managed when required
* [ ] production CAPTCHA, database, Redis, and mail credentials are externally managed
* [ ] production secrets are not committed to Git

## HTTPS and Cookies

* [ ] HTTPS is enforced
* [ ] secure cookies remain enabled
* [ ] reset URLs use HTTPS
* [ ] WebAuthn origin uses HTTPS
* [ ] WebAuthn RP ID matches the production domain
* [ ] `MARKS_AUTH_ALLOW_INSECURE_RESET_URL` is disabled
* [ ] `MARKS_AUTH_ALLOW_CONSOLE_MAILER` is disabled

## Persistence

* [ ] production user storage is persistent
* [ ] production MFA storage is persistent when MFA is enabled
* [ ] production passkey storage is persistent when WebAuthn is enabled
* [ ] database migrations are applied
* [ ] backup and recovery procedures are tested

## Distributed Deployment

For multiple workers or instances:

* [ ] `MARKS_AUTH_SECURITY_STORE="redis"`
* [ ] all workers share the configured Redis service
* [ ] MFA challenges use shared Redis state
* [ ] WebAuthn challenges use shared Redis state
* [ ] Redis authentication and network controls are configured
* [ ] all workers share the same required cryptographic configuration

## CAPTCHA

* [ ] production Turnstile keys are used
* [ ] allowed-hostname validation is configured
* [ ] expected-action validation is configured where applicable

## WebAuthn

* [ ] production RP ID is correct
* [ ] production RP name is configured
* [ ] production origin exactly matches the frontend origin
* [ ] HTTPS is enforced
* [ ] persistent `PasskeyStore` is configured
* [ ] distributed challenge storage is configured for multi-worker deployments

## Proxying

* [ ] `ProxyFix` is enabled only behind a trusted proxy
* [ ] trusted-hop counts match the real deployment
* [ ] direct untrusted access cannot spoof trusted forwarded headers

## Logging

* [ ] authentication audit logs have a defined destination
* [ ] retention and access policies are defined
* [ ] secrets are excluded
* [ ] operators can detect repeated authentication abuse

---

# Known Limitations

MARKS Toolkit is still under active development.

Current limitations include:

* there is no user-facing active-session/device registry yet
* individual authenticated sessions cannot yet be selectively revoked through a session-management UI
* Redis adapters have automated tests, but production Redis infrastructure should still receive environment-specific integration testing
* database migration tooling remains a host-application responsibility
* React components are distributed as source rather than as a dedicated frontend package
* frontend authentication flows do not yet have the same level of automated component/browser testing as the backend suite

---

# Planned Work

## Session and Device Management

Planned capabilities include:

* active-session registry
* device/session metadata
* view current and historical sessions
* revoke individual sessions
* revoke all other sessions
* device labeling
* security notifications
* session activity timestamps
* integration with authentication-ID revocation

## Frontend Testing

Planned work includes:

* automated login-flow tests
* remembered-account tests
* passkey-management tests
* conditional WebAuthn behavior tests
* authentication modal regression tests
* accessibility testing

## Deployment Integration

Planned hardening includes:

* real Redis integration testing
* multi-worker deployment testing
* broader SQLAlchemy integration testing
* Alembic reference integration
* production deployment examples
* migration/version compatibility guidance

## Frontend Packaging

Potential improvements include:

* dedicated frontend package distribution
* host branding hooks
* additional styling primitives
* dark mode
* accessibility refinement
* recovery-code copy/download controls

---

# Development Philosophy

MARKS Toolkit intentionally favors:

```text
configuration over hard-coding
interfaces over tight coupling
small services over giant modules
explicit security controls over implicit behavior
strong mechanisms across all policy profiles
persistent IDs over session identifiers
dedicated stores for distinct credential types
atomic operations for security-sensitive state
tests over assumptions
reusable components over copy-and-paste application code
```

The toolkit is developed incrementally, with security-sensitive behavior covered by regression tests before being treated as part of the reusable platform.
