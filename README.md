MARKS Toolkit

A reusable Python/Flask authentication and application-security toolkit with companion React authentication components.

MARKS Toolkit provides reusable, security-focused authentication building blocks so future applications do not need to rebuild registration, login, password recovery, MFA, CAPTCHA, throttling, session security, and related infrastructure from scratch.

Design Goals

MARKS Toolkit favors:

reusable services instead of application-specific authentication logic

replaceable persistence and provider adapters

secure defaults

explicit configuration

separation of backend, persistence, and frontend concerns

testable authentication flows

minimal host-application integration

production-oriented architecture without requiring one database or frontend stack

policy separated from mechanism

Applications choose which controls they require; AuthKit supplies the secure mechanisms underneath them.

Current Status

Current capabilities include:

user registration

email and username identity handling

case-insensitive identity lookup

Argon2 password hashing

transparent password rehashing

dummy Argon2 verification for unknown/inactive users

login and logout

remember-me authentication

Flask-Login session protection

authentication-ID rotation

password changing

password reset

CSRF protection

strict JSON request validation

adaptive CAPTCHA

Cloudflare Turnstile support

CAPTCHA hostname and action validation

login risk tracking

request throttling

security event auditing

Redis-backed shared security state

SQLAlchemy persistence adapters

TOTP authenticator MFA

QR-code authenticator enrollment

manual authenticator setup keys

MFA login challenges

Redis-backed distributed MFA challenge storage

atomic MFA challenge consumption

TOTP replay prevention

atomic single-use recovery-code consumption

password reauthentication for sensitive MFA operations

authentication-state revocation after MFA enable/disable

Cache-Control: no-store for secret-bearing MFA responses

reusable React authentication components

reusable MFA settings UI

The automated backend suite currently contains 125 passing authentication and security tests.

Passkey/WebAuthn support is planned as a future capability.

Project Structure

marks-toolkit/
├── pyproject.toml
├── README.md
├── test_app.py
├── frontend/
│   └── auth/
├── frontend-test/
│   └── src/
├── src/
│   └── marks_toolkit/
│       └── auth/
│           ├── extensions.py
│           ├── config.py
│           ├── state.py
│           ├── routes.py
│           ├── responses.py
│           ├── request_validation.py
│           ├── user_store.py
│           ├── sqlalchemy_store.py
│           ├── passwords.py
│           ├── identity.py
│           ├── registration.py
│           ├── login.py
│           ├── password_change.py
│           ├── password_reset.py
│           ├── reset_tokens.py
│           ├── csrf.py
│           ├── decorators.py
│           ├── throttle.py
│           ├── risk.py
│           ├── security_store.py
│           ├── captcha.py
│           ├── mailer.py
│           ├── audit.py
│           ├── mfa_store.py
│           ├── memory_mfa_store.py
│           ├── sqlalchemy_mfa_store.py
│           ├── secret_encryption.py
│           ├── recovery_codes.py
│           ├── recovery_code_manager.py
│           ├── totp.py
│           ├── mfa_challenge.py
│           └── mfa_challenge_store.py
└── tests/

Installation

Create a virtual environment and install the project in editable development mode.

Windows PowerShell:

python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -e ".[dev]"

macOS/Linux:

python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"

Core dependencies include Flask, Flask-Login, Argon2, HTTPX, Redis, SQLAlchemy, email-validator, cryptography, PyOTP, and pytest.

Basic Flask Integration

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
)

Storage and external-service dependencies are supplied by the host application rather than hard-coded into the toolkit.

Required Security Configuration

Flask Secret Key

A Flask SECRET_KEY is required.

Use a high-entropy value from environment or secret-management infrastructure in production.

Password Reset URL

A reset URL is required:

app.config["MARKS_AUTH_RESET_URL"] = (
    "https://example.com/reset-password"
)

Reset URLs must be absolute, contain a hostname, and must not contain embedded credentials.

HTTPS is required by default.

Plain HTTP is available only through an explicit development/testing opt-in:

app.config[
    "MARKS_AUTH_ALLOW_INSECURE_RESET_URL"
] = True

Do not enable this in production.

Mailer

An explicit mailer is required by default.

The console mailer can be enabled only through an explicit development/testing opt-in:

app.config[
    "MARKS_AUTH_ALLOW_CONSOLE_MAILER"
] = True

Production applications should provide a real mailer implementation.

User Store and Authentication IDs

Authentication is abstracted through the UserStore contract.

Important operations include:

find_by_identity
find_by_auth_id
email_exists
username_exists
create_user
rotate_auth_id
update_password
update_password_and_rotate_auth_id

MARKS Toolkit distinguishes between a permanent database user ID and a rotating authentication ID.

Authentication-ID rotation invalidates old Flask-Login sessions and remember cookies without changing the permanent user identity.

Current operations that rotate authentication state include:

password change

password reset

TOTP enable

TOTP disable

Password changes and resets require fresh login afterward.

MFA enable/disable rotates authentication state while preserving the current verified browser session.

Password Security

Passwords are protected with Argon2.

The password service supports validation, hashing, verification, hash-upgrade detection, and transparent rehashing.

Unknown and inactive-user login attempts execute a dummy Argon2 verification to reduce timing differences that could reveal account existence.

Plaintext passwords are never persisted by the toolkit.

Request Validation

Authentication routes validate request bodies before business logic runs.

Shared validation helpers enforce:

JSON object bodies

required strings

optional strings

strict boolean values

Malformed input is rejected before reaching password, identity, CAPTCHA, or MFA services.

Login Risk and Throttling

RiskService tracks failures across three independent buckets:

identity + IP

identity-wide

IP-wide

This makes simple IP or identity rotation less effective at bypassing risk controls.

ThrottleService protects sensitive operations including registration, password actions, and MFA endpoints.

Malformed throttle identities are normalized instead of allowing malformed request bodies to create uncontrolled key variation.

For distributed deployments, shared state can be stored in Redis.

CAPTCHA

Cloudflare Turnstile support includes:

server-side Siteverify validation

failure-closed HTTP and JSON handling

request timeouts

token type/length validation

optional allowed-hostname validation

optional expected-action validation

Production applications should configure hostname restrictions and expected actions for the real deployment.

Adaptive login risk can require CAPTCHA only after suspicious or repeated authentication failures instead of forcing every user through a challenge.

Sessions and Cookies

MARKS Toolkit uses Flask-Login.

Protections include:

remember-me authentication

HTTP-only session and remember cookies

secure cookies

SameSite handling

session protection

authentication-ID based revocation

JSON unauthorized responses

Secure cookies are enabled by default.

For localhost development over plain HTTP only:

app.config[
    "MARKS_AUTH_COOKIE_SECURE"
] = False

AuthKit will not weaken stronger cookie settings already configured by the host application.

Password Reset

The password-reset flow uses signed, time-limited reset tokens.

A successful reset:

validates the reset token

updates the password

rotates the authentication ID exactly once

invalidates old sessions and remember cookies

Reset URLs are assembled safely without unsafe query-string concatenation.

Because the authentication ID rotates on successful reset, the old reset token cannot be successfully reused afterward.

MFA Login

For an MFA-enabled user:

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

Password verification alone does not authenticate an MFA-enabled account.

Pending MFA challenges are stored server-side. The Flask session stores only the challenge ID.

Challenge consumption is atomic, so a completed MFA challenge cannot be reused.

Available challenge stores:

MemoryMFAChallengeStore
RedisMFAChallengeStore

The memory store is suitable for tests and single-process development.

When the security-store backend is Redis, AuthKit also uses Redis-backed MFA challenge storage so challenge state is shared across workers.

TOTP MFA

TOTP enrollment:

requires current-password reauthentication

creates a secret and provisioning URI

displays QR/manual enrollment data

requires successful code verification

activates TOTP only after verification

TOTP secrets are encrypted with Fernet and require a stable external key:

MARKS_AUTH_MFA_ENCRYPTION_KEY

Successfully accepted TOTP time steps are claimed server-side so the same TOTP code cannot be replayed during its validity window.

Recovery Codes

Recovery codes are:

randomly generated

displayed only when generated

stored as keyed HMAC hashes

consumed atomically

single-use

invalidated when a new set is generated

invalidated when TOTP is disabled

Configuration:

MARKS_AUTH_RECOVERY_CODE_KEY

Recovery-code hashing and TOTP-secret encryption intentionally use separate keys.

Sensitive MFA Operations

Current-password reauthentication is required for:

beginning TOTP enrollment

generating recovery codes

disabling TOTP

Enabling or disabling TOTP rotates the authentication ID so other sessions and remember cookies become invalid.

The current verified browser is refreshed into a new non-remembered authenticated session.

Secret-Bearing Responses

Responses that expose sensitive MFA material use:

Cache-Control: no-store

This currently includes:

TOTP enrollment secrets

newly generated recovery codes

The React frontend also clears sensitive state after relevant flows complete or close.

MFA Storage

The toolkit defines an MFAStore abstraction.

Current implementations:

MemoryMFAStore
SQLAlchemyMFAStore

MemoryMFAStore is intended for tests and development.

Production applications should use persistent MFA storage.

SQLAlchemy persistence currently covers TOTP and recovery-code state, with passkey persistence groundwork already present.

Redis

Redis-backed security state supports distributed deployments.

Example:

app.config.update(
    MARKS_AUTH_SECURITY_STORE="redis",
    MARKS_AUTH_REDIS_URL="redis://localhost:6379/0",
)

Redis is used for shared authentication security counters and, with the current configuration model, distributed MFA challenge state.

Production Redis should be protected with appropriate network isolation, credentials, monitoring, and TLS where applicable.

Reverse Proxy Support

Configurable Werkzeug ProxyFix support is available for trusted reverse-proxy deployments.

Configure only the actual number of trusted proxy hops.

Incorrect forwarded-header trust can allow clients to spoof apparent IP addresses or request scheme information.

Audit Logging

Security-relevant authentication events can be logged.

Examples include:

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

Sensitive data such as passwords, reset tokens, CAPTCHA tokens, TOTP secrets, and recovery codes should never be logged.

The host application is responsible for log destination, retention, access control, and centralized collection.

React Frontend

Reusable React components live under:

frontend/auth/

They provide:

authentication API access

auth state management

login/register/forgot-password/reset-password views

MFA challenge handling

MFA enrollment/settings UI

reusable password reauthentication dialog

The frontend test harness mirrors these components under:

frontend-test/src/auth/

When reusable components change, keep the test-harness copies synchronized.

QR enrollment uses qrcode.react and is generated locally in the browser. The TOTP secret is not sent to a third-party QR service.

Development Test Application

test_app.py is intentionally configured as a local development harness.

It may use:

in-memory users

in-memory MFA persistence

development cryptographic keys

Turnstile test credentials

console mailer

insecure localhost reset URL opt-in

non-secure localhost cookies

These development exceptions are explicit so they cannot silently become production defaults.

Example local account:

Email:    mark@example.com
Username: Mark
Password: TestingPassword123!

Restarting the development app may reset users, MFA state, recovery codes, in-memory challenge state, and security counters.

Production applications must use persistent storage and stable externally managed keys.

Running the Development Harness

Backend:

python test_app.py

Frontend:

cd frontend-test
npm install
npm run dev

Vite normally serves the frontend around:

http://localhost:5173

and proxies /auth requests to Flask.

Testing

Run the backend suite with:

pytest

The current suite contains 125 passing tests covering areas including:

registration

login

malformed input handling

password hashing and rehashing

dummy password verification

password reset

password changes

session behavior

authentication-ID revocation

secure-cookie defaults

reset URL validation

mailer configuration

risk tracking

throttling

audit logging

CAPTCHA behavior

Turnstile hostname/action validation

TOTP enrollment

TOTP replay prevention

TOTP disabling

recovery-code generation

atomic recovery-code consumption

MFA login

MFA challenge replay prevention

MFA throttling

Redis MFA challenge behavior

no-store secret responses

For frontend changes also run:

npm run build

and manually exercise the affected flow in the test harness.

Security Principles

MARKS Toolkit follows several core rules:

backend validation is the security boundary

plaintext passwords are never stored

unknown-user authentication performs dummy Argon2 work

recovery codes are never stored in plaintext

recoverable MFA secrets are encrypted

cryptographic keys should live outside the database

authentication IDs rotate after supported credential/MFA changes

password verification does not complete MFA authentication

sensitive MFA actions require reauthentication

accepted TOTP time steps cannot be replayed

recovery codes are atomically single-use

MFA challenges are atomically single-use

distributed security state must be shared across workers

secret-bearing responses should not be cached

authentication endpoints require abuse controls

audit logs must record events, not secrets

Production Requirements

Before using MARKS Toolkit in production, provide:

persistent UserStore

persistent MFAStore

production database

database migrations

stable Flask secret key

stable MFA encryption key

stable recovery-code HMAC key

HTTPS

secure cookies

correct reverse-proxy configuration

production CAPTCHA credentials

CAPTCHA hostname/action restrictions

production mail provider

Redis-backed security state for multi-worker deployments

centralized logging

secret-management infrastructure

backup and recovery procedures

The in-memory adapters are development/testing mechanisms, not production persistence.

Production Deployment Checklist

Secrets

Flask SECRET_KEY is high entropy and externally managed

MARKS_AUTH_MFA_ENCRYPTION_KEY is stable and externally managed

MARKS_AUTH_RECOVERY_CODE_KEY is stable and externally managed

production CAPTCHA, database, Redis, and mail credentials are externally managed

production secrets are not committed to Git

HTTPS and Cookies

HTTPS is enforced

secure cookies remain enabled

reset URLs use HTTPS

MARKS_AUTH_ALLOW_INSECURE_RESET_URL is disabled

MARKS_AUTH_ALLOW_CONSOLE_MAILER is disabled

Persistence

production user storage is persistent

production MFA storage is persistent

database migrations are applied

backup and recovery procedures are tested

Distributed Deployment

For multiple workers or instances:

MARKS_AUTH_SECURITY_STORE="redis"

all workers share the configured Redis service

Redis authentication/network controls are configured

all workers share the same required cryptographic configuration

CAPTCHA

production Turnstile keys are used

allowed-hostname validation is configured

expected-action validation is configured where applicable

Proxying

ProxyFix is enabled only behind a trusted proxy

trusted-hop counts match the real deployment

direct untrusted access cannot spoof trusted forwarded headers

Logging

authentication audit logs have a defined destination

retention and access policies are defined

secrets are excluded

operators can detect repeated authentication abuse

Known Limitations

MARKS Toolkit is still under active development.

Current limitations include:

full WebAuthn/passkey flows are not implemented yet

there is no user-facing active-session/device registry yet

Redis adapters have automated tests, but real production Redis infrastructure should still be integration-tested

database migration tooling remains a host-application responsibility

React components are currently distributed as source rather than as a dedicated frontend package

Planned Work

Passkeys / WebAuthn

Planned work includes:

registration challenges

authentication challenges

credential public-key storage

signature-counter validation

passkey naming/removal

passkey-based MFA

potential passwordless authentication

Session Management

Potential future capabilities:

active-session registry

device/session metadata

revoke individual sessions

revoke all other sessions

security notifications

Deployment Integration

Planned hardening includes:

real Redis integration testing

multi-worker deployment testing

broader SQLAlchemy integration testing

Alembic reference integration

deployment examples

Frontend

Potential improvements include:

passkey management

recovery-code copy/download controls

accessibility refinement

host branding hooks

packaging reusable components for direct import

Development Philosophy

MARKS Toolkit intentionally favors:

configuration over hard-coding
interfaces over tight coupling
small services over giant modules
explicit security controls over implicit behavior
strong mechanisms across all policy profiles
persistent IDs over session identifiers
tests over assumptions
reusable components over copy-and-paste application code

The toolkit is developed incrementally, with security-sensitive behavior covered by regression tests before being treated as part of the reusable platform.