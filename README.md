# MARKS Toolkit

MARKS Toolkit is a reusable application toolkit designed to provide secure, standardized authentication and supporting application infrastructure for Flask and React projects.

The goal is to avoid rebuilding the same authentication plumbing for every application.

Instead of rewriting login, registration, password reset, CAPTCHA, session handling, throttling, frontend auth modals, and related security behavior for every project, MARKS Toolkit provides those systems as reusable modules with configurable policies and replaceable backend adapters.

The toolkit currently focuses primarily on authentication and account-security infrastructure.

---

# Goals

MARKS Toolkit is being built around several core principles:

* Secure by default
* Reusable across applications
* Configuration instead of hard-coded project behavior
* Clear separation between business logic and infrastructure
* Backend-enforced security
* Standardized frontend behavior
* Replaceable storage and provider adapters
* Minimal project-specific implementation
* Host applications should primarily customize configuration, branding, and styling

The long-term goal is for a new project to be able to import working authentication infrastructure with minimal setup.

---

# Current Architecture

The authentication system is structured approximately like this:

```text
React Application
        │
        ▼
AuthProvider
        │
        ▼
AuthModal / Auth Views
        │
        ▼
AuthClient
        │
        ▼
Flask AuthKit Blueprint
        │
        ├── RegistrationService
        ├── LoginService
        ├── PasswordResetService
        ├── PasswordService
        ├── IdentityService
        ├── CSRFService
        ├── RiskService
        ├── ThrottleService
        └── CAPTCHA Provider
                │
                ▼
Infrastructure Adapters
        ├── UserStore
        ├── SecurityStore
        ├── Mailer
        ├── CAPTCHA Provider
        └── Audit Logger
```

The main design principle is that services define application behavior while adapters handle infrastructure.

For example:

```text
LoginService
```

knows how authentication should work.

It does not know whether users are stored in:

```text
PostgreSQL
SQLite
MySQL
Memory
```

That responsibility belongs to the `UserStore`.

---

# Project Structure

The current repository is structured approximately like this:

```text
marks-toolkit/
│
├── pyproject.toml
├── README.md
├── test_app.py
├── test_risk.py
│
├── src/
│   └── marks_toolkit/
│       ├── __init__.py
│       │
│       └── auth/
│           ├── __init__.py
│           ├── extensions.py
│           ├── routes.py
│           ├── config.py
│           ├── state.py
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
│           │
│           ├── responses.py
│           ├── exceptions.py
│           │
│           ├── csrf.py
│           ├── decorators.py
│           │
│           ├── reset_tokens.py
│           ├── password_reset.py
│           │
│           ├── mailer.py
│           ├── captcha.py
│           │
│           ├── risk.py
│           ├── throttle.py
│           ├── security_store.py
│           │
│           └── audit.py
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
│       └── auth.css
│
└── frontend-test/
    └── ...
```

`frontend-test` is currently used as a development harness for testing the reusable React authentication components.

---

# Installation

Clone the repository:

```bash
git clone https://github.com/DrMVRK/marks-toolkit.git
cd marks-toolkit
```

Create a virtual environment.

Windows:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

macOS/Linux:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

Install the toolkit in editable mode:

```bash
python -m pip install --upgrade pip
python -m pip install -e .
```

Editable mode allows changes made inside the toolkit source to immediately affect the installed package.

---

# Dependencies

Runtime dependencies are declared in `pyproject.toml`.

The toolkit currently uses libraries such as:

```text
Flask
Flask-Login
argon2-cffi
httpx
redis
SQLAlchemy
email-validator
itsdangerous
```

The exact dependency list should always be considered authoritative from `pyproject.toml`.

---

# Flask Integration

The primary Flask extension is:

```python
from marks_toolkit.auth import AuthKit
```

Create it:

```python
auth_kit = AuthKit()
```

Then initialize it with the Flask application and a `UserStore` implementation:

```python
auth_kit.init_app(
    app,
    user_store=user_store,
    captcha_provider=captcha_provider
)
```

The toolkit uses Flask's standard extension `init_app()` pattern.

This allows the same toolkit instance to remain reusable while application-specific dependencies are supplied during initialization.

---

# Required Flask Configuration

The toolkit currently requires several configuration values.

At minimum:

```python
app.config["SECRET_KEY"] = "your-secret-key"

app.config["MARKS_AUTH_RESET_URL"] = (
    "https://example.com/reset-password"
)
```

A CAPTCHA provider must also be explicitly supplied.

The toolkit intentionally does not silently fall back to a test CAPTCHA provider.

---

# URL Prefix

Authentication routes are mounted under:

```text
/auth
```

by default.

This can be changed using:

```python
app.config["MARKS_AUTH_URL_PREFIX"] = "/api/auth"
```

---

# Authentication Routes

The toolkit currently provides the following backend routes:

```text
GET  /auth/config
GET  /auth/csrf
GET  /auth/me

POST /auth/register
POST /auth/login
POST /auth/logout

POST /auth/forgot-password
POST /auth/reset-password
```

There is also currently a development test route:

```text
GET /auth/test
```

---

# Standard API Responses

Successful responses use a standardized format.

Example:

```json
{
  "ok": true,
  "message": "Login successful.",
  "data": {
    "username": "Mark"
  }
}
```

Errors use:

```json
{
  "ok": false,
  "error": {
    "code": "INVALID_CREDENTIALS",
    "message": "Invalid login credentials."
  }
}
```

Frontend components should primarily react to stable error codes rather than parsing message strings.

Examples include:

```text
INVALID_CREDENTIALS
INVALID_IDENTITY
IDENTITY_UNAVAILABLE
WEAK_PASSWORD
CSRF_FAILED
CAPTCHA_REQUIRED
RATE_LIMITED
INVALID_RESET_TOKEN
AUTH_REQUIRED
```

---

# UserStore

`UserStore` is the abstraction between the authentication system and persistent user storage.

The host application supplies an implementation.

The interface currently supports operations including:

```text
find_by_identity
find_by_auth_id

email_exists
username_exists

create_user

update_password
rotate_auth_id

update_password_and_rotate_auth_id
```

This allows authentication logic to remain independent of a specific database.

---

# Identity Rules

The toolkit currently defines email and username behavior as follows.

## Username

Usernames are:

* required
* unique across accounts
* compared case-insensitively
* preserved as originally entered for display

For example:

```text
Registered username:

Mark
```

These registrations are considered duplicates:

```text
mark
MARK
MaRk
```

The display username remains:

```text
Mark
```

while the comparison key becomes:

```text
mark
```

---

# Email Rules

Emails are:

* required
* normalized using `email-validator`
* unique across accounts
* compared case-insensitively
* available as login identifiers

Example:

```text
Mark@Example.com
```

and:

```text
mark@example.com
```

resolve to the same identity.

---

# Login Identifiers

Users may log in using either:

```text
username
```

or:

```text
email address
```

Login identity matching is case-insensitive.

The password remains case-sensitive.

---

# Password Storage

Passwords are hashed using Argon2 through `argon2-cffi`.

Passwords are never stored in plaintext.

`PasswordService` handles:

```text
password validation
password hashing
password verification
rehash detection
```

The toolkit also supports transparent password rehashing during successful login.

If Argon2 parameters are strengthened later:

```text
old hash verifies
→ toolkit detects outdated parameters
→ password is rehashed
→ new hash is persisted
→ login continues normally
```

This allows password security settings to improve over time without forcing users to reset their passwords.

---

# Registration

Registration is managed by `RegistrationService`.

The process is approximately:

```text
validate email
→ normalize email

validate username
→ create username comparison key

check email uniqueness
check username uniqueness

validate password
hash password

create user
```

The SQLAlchemy store also uses database-level unique constraints.

This is important because application-level checks alone cannot prevent concurrent registration races.

---

# SQLAlchemy Support

The toolkit includes a SQLAlchemy persistence foundation.

Current components include:

```text
AuthBase
AuthUserModel
SQLAlchemyUserStore
```

The user model stores both display values and canonical lookup keys.

Example:

```text
username:
Mark

username_key:
mark
```

and:

```text
email:
mark@example.com

email_key:
mark@example.com
```

Database uniqueness constraints protect:

```text
auth_id
email_key
username_key
```

---

# Atomic Password Reset Updates

Password reset updates are designed to update:

```text
password hash
+
auth_id
```

as one persistence operation.

For SQLAlchemy, both values are updated before a single transaction commit.

This prevents partial reset states such as:

```text
new password saved
but old auth_id still active
```

---

# Flask-Login

Session authentication uses Flask-Login.

The toolkit configures a `LoginManager` and supplies a user loader using:

```text
auth_id
```

rather than exposing the database primary key as the login-session identifier.

---

# auth_id

Each user has a random authentication identifier:

```text
auth_id
```

This is separate from the database primary key.

It is generated using:

```python
secrets.token_urlsafe(32)
```

The `auth_id` is used for:

```text
Flask-Login identity
remember-me identity
password-reset token identity
```

Rotating it invalidates authentication state tied to the previous value.

---

# Password Reset

Password reset tokens are generated with a signed and timed serializer.

The process is:

```text
forgot-password request
→ generate token containing auth_id
→ send reset link
→ user submits token + new password
→ verify token
→ locate user by auth_id
→ update password
→ rotate auth_id
```

Rotating the `auth_id` makes the reset token effectively single-use.

After a successful reset:

```text
old reset token
→ references old auth_id
→ no longer resolves
→ rejected
```

---

# Reset Token Expiration

The default reset-token lifetime is configurable.

Example:

```python
app.config["MARKS_AUTH_RESET_TOKEN_TTL"] = 1800
```

This represents:

```text
30 minutes
```

---

# Mailer Abstraction

Password reset delivery uses the `Mailer` interface.

A development implementation currently exists:

```text
ConsoleMailer
```

which prints reset links to the console.

Production applications can provide another mailer implementation.

Examples could include:

```text
SMTP
Amazon SES
SendGrid
Mailgun
Postmark
```

The authentication services do not need to know which provider is used.

---

# CSRF Protection

The toolkit includes session-based CSRF protection.

The frontend first requests:

```text
GET /auth/csrf
```

and receives:

```json
{
  "csrf_token": "..."
}
```

State-changing requests send that token using:

```text
X-CSRF-Token
```

Protected routes use:

```python
@csrf_protected
```

The backend performs constant-time token comparison.

---

# Remember Me

Login supports:

```json
{
  "remember": true
}
```

Flask-Login then creates a persistent remember cookie.

The duration is configurable:

```python
app.config["MARKS_AUTH_REMEMBER_DAYS"] = 30
```

---

# Cookie Security

The toolkit explicitly configures both Flask session cookies and Flask-Login remember cookies.

Supported policies include:

```text
HttpOnly
SameSite
Secure
```

Production applications should enable:

```python
app.config["MARKS_AUTH_COOKIE_SECURE"] = True
```

when running behind HTTPS.

Local HTTP development should normally use:

```python
app.config["MARKS_AUTH_COOKIE_SECURE"] = False
```

---

# Session Protection

Flask-Login session protection is configurable.

Default:

```text
strong
```

Configuration:

```python
app.config["MARKS_AUTH_SESSION_PROTECTION"] = "strong"
```

---

# Unauthorized API Responses

Protected routes return standardized JSON instead of HTML redirects.

Example:

```json
{
  "ok": false,
  "error": {
    "code": "AUTH_REQUIRED",
    "message": "Authentication is required."
  }
}
```

with HTTP status:

```text
401
```

---

# Risk Engine

`RiskService` tracks failed login behavior.

It currently supports:

```text
CAPTCHA escalation
login blocking
failure windows
```

Default policy values are configurable.

Example:

```python
app.config[
    "MARKS_AUTH_LOGIN_CAPTCHA_THRESHOLD"
] = 4

app.config[
    "MARKS_AUTH_LOGIN_BLOCK_THRESHOLD"
] = 15

app.config[
    "MARKS_AUTH_LOGIN_FAILURE_WINDOW"
] = 900
```

A typical login progression is:

```text
normal login
→ password only

repeated failures
→ CAPTCHA required

continued failures
→ login temporarily blocked
```

---

# CAPTCHA

CAPTCHA support uses a provider abstraction.

Current providers include:

```text
TestCaptchaProvider
TurnstileCaptchaProvider
```

Applications must explicitly provide a CAPTCHA provider.

There is intentionally no automatic fallback to the test provider.

---

# Cloudflare Turnstile

The real CAPTCHA implementation uses Cloudflare Turnstile.

The frontend receives the public site key through:

```text
GET /auth/config
```

Example response:

```json
{
  "ok": true,
  "data": {
    "captcha_site_key": "..."
  }
}
```

The frontend renders Turnstile only after the backend returns:

```text
CAPTCHA_REQUIRED
```

The flow is:

```text
login failures
→ risk threshold reached
→ backend returns CAPTCHA_REQUIRED
→ frontend renders Turnstile
→ Turnstile returns token
→ frontend resubmits login with captcha_token
→ backend verifies token
→ authentication continues
```

---

# Explicit CAPTCHA Configuration

The application must explicitly supply the provider:

```python
captcha_provider = TurnstileCaptchaProvider(
    secret_key="..."
)

auth_kit.init_app(
    app,
    user_store=user_store,
    captcha_provider=captcha_provider
)
```

Production secrets should come from environment variables.

Example:

```python
import os

captcha_provider = TurnstileCaptchaProvider(
    secret_key=os.environ[
        "TURNSTILE_SECRET_KEY"
    ]
)
```

Never expose the secret key to the browser.

---

# Throttling

`ThrottleService` provides request-volume protection.

The toolkit includes a reusable decorator:

```python
@throttle(...)
```

Example:

```python
@throttle(
    action="forgot-password",
    identities=("ip", "email"),
    limit_config="forgot_password_limit",
    window_config="forgot_password_window"
)
```

The decorator can throttle multiple independent identities.

For forgot-password:

```text
IP bucket
+
email bucket
```

For reset-password:

```text
IP bucket
```

---

# Forgot Password Throttling

Forgot-password requests are throttled to prevent:

```text
email spam
mailer abuse
account-targeted flooding
resource abuse
```

Registered and unregistered emails are throttled identically so the throttle behavior does not reveal whether an account exists.

---

# Reset Password Throttling

Reset-password submissions are also throttled.

This protects against large numbers of invalid or garbage reset-token attempts.

Even though valid reset tokens are single-use, the endpoint still requires protection from resource abuse.

---

# SecurityStore

Temporary security state is accessed through the `SecurityStore` abstraction.

Current implementations:

```text
MemorySecurityStore
RedisSecurityStore
```

The same store is shared by:

```text
RiskService
ThrottleService
```

and is intended to support future MFA attempt tracking as well.

---

# MemorySecurityStore

Used primarily for:

```text
local development
tests
single-process development servers
```

Security state disappears when the Python process ends.

It should not be relied on for production deployments with multiple workers.

---

# RedisSecurityStore

The toolkit includes a Redis-backed implementation for production environments.

Redis allows multiple Flask/Gunicorn workers to share the same counters.

Without shared state:

```text
worker 1
→ counter A

worker 2
→ separate counter B
```

With Redis:

```text
worker 1 ─┐
worker 2 ─┼──> shared Redis state
worker 3 ─┘
```

Configuration:

```python
app.config["MARKS_AUTH_SECURITY_STORE"] = "redis"

app.config["MARKS_AUTH_REDIS_URL"] = (
    "redis://127.0.0.1:6379/0"
)
```

Development defaults to:

```text
memory
```

---

# Redis Key Privacy

Structured security keys are serialized and hashed before being used as Redis keys.

This prevents raw values such as:

```text
email addresses
IP addresses
usernames
```

from being directly exposed in Redis key names.

---

# Proxy Handling

Risk and throttling systems rely on the client IP address.

Directly trusting `X-Forwarded-For` is unsafe because clients may spoof it.

The toolkit supports Werkzeug `ProxyFix` for deployments behind trusted reverse proxies.

Configuration:

```python
app.config[
    "MARKS_AUTH_PROXY_FIX_ENABLED"
] = True

app.config[
    "MARKS_AUTH_PROXY_FIX_X_FOR"
] = 1

app.config[
    "MARKS_AUTH_PROXY_FIX_X_PROTO"
] = 1
```

The exact number of trusted proxy hops must match the deployment.

Example:

```text
client
→ Nginx
→ Flask
```

may differ from:

```text
client
→ Cloudflare
→ Nginx
→ Flask
```

Do not guess proxy-hop counts.

---

# Audit Logging

The toolkit includes an audit logging abstraction:

```text
AuditLogger
StandardAuditLogger
```

Authentication events can be recorded without embedding logging logic throughout the application.

Current events include examples such as:

```text
login_failure
login_success
login_rate_limited
captcha_required
```

Sensitive values are filtered from standard audit details.

Filtered keys include:

```text
password
password_hash
token
captcha_token
totp_secret
```

---

# Logging Configuration

The toolkit emits audit events but does not configure the host application's global logging policy.

A development application can enable INFO logs using:

```python
import logging

logging.basicConfig(
    level=logging.INFO,
    format=(
        "%(asctime)s %(levelname)s "
        "%(name)s: %(message)s"
    )
)
```

Production applications may route logs into systems such as:

```text
CloudWatch
Datadog
Splunk
SIEM platforms
structured JSON logging
```

---

# React Frontend

The toolkit currently includes reusable React authentication components.

The frontend is designed around **modals rather than dedicated auth pages**.

The goal is for host applications to import working authentication UI and primarily customize styling.

---

# AuthProvider

`AuthProvider` owns global frontend authentication state.

It manages:

```text
AuthClient
configuration
initialization
authenticated user
login state
logout behavior
```

Wrap the application:

```jsx
<AuthProvider>
    <App />
</AuthProvider>
```

Components can access authentication state using:

```jsx
const {
    authenticated,
    user,
    logout
} = useAuth();
```

---

# AuthClient

`AuthClient` handles communication with the Flask authentication API.

It manages:

```text
base URL
cookies
CSRF headers
JSON requests
auth configuration
```

Methods currently include functionality for:

```text
initialize
login
register
logout
me
forgot password
reset password
```

The default backend URL prefix is:

```text
/auth
```

---

# AuthModal

Authentication UI is presented through:

```jsx
<AuthModal />
```

Example:

```jsx
<AuthModal
    open={authOpen}
    onClose={() => setAuthOpen(false)}
/>
```

The modal internally switches between:

```text
login
registration
forgot password
reset password
CAPTCHA challenge
```

---

# Modal Closing Behavior

The modal supports:

```text
close button
clicking the backdrop
Escape key
```

Successful login automatically closes the login modal.

Other modal views are not automatically closed merely because the user is authenticated.

---

# LoginView

The login form supports:

```text
username or email
password
remember me
CAPTCHA escalation
loading state
error handling
```

Successful authentication updates global state through `AuthProvider`.

---

# RegisterView

The registration form supports:

```text
username
email
password
backend validation
duplicate identity handling
loading state
success/error states
```

The frontend does not attempt to replace backend identity validation.

---

# ForgotPasswordView

The forgot-password modal submits an email address and always displays generic behavior.

This protects against account enumeration.

A request for:

```text
real@example.com
```

and:

```text
fake@example.com
```

should appear effectively identical from the user's perspective.

---

# ResetPasswordView

The reset-password modal receives the reset token externally.

Users do not manually enter the token.

The form handles:

```text
new password
password confirmation
missing-token UX validation
backend token verification
success/error state
```

The backend remains authoritative for:

```text
token validity
expiration
password policy
account lookup
```

---

# CaptchaChallenge

Turnstile rendering is isolated inside:

```text
CaptchaChallenge.jsx
```

This prevents Cloudflare-specific script-loading logic from being embedded directly inside `LoginView`.

The component manages:

```text
Turnstile script loading
explicit widget rendering
success callback
expired token handling
error callback
widget cleanup
```

---

# Frontend Styling

Authentication UI uses:

```text
frontend/auth/auth.css
```

The current styling provides a clean neutral default.

Host applications are expected to customize:

```text
colors
fonts
spacing
shadows
border radius
branding
logo
animations
```

The long-term goal is to expose most styling through reusable CSS variables or theme tokens so projects rarely need to modify the component logic.

---

# Vite Development Proxy

During local frontend development, Vite can proxy `/auth` requests to Flask.

Example `vite.config.js`:

```javascript
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
    plugins: [react()],

    server: {
        proxy: {
            "/auth": {
                target: "http://127.0.0.1:5000",
                changeOrigin: true
            }
        }
    }
});
```

This allows the frontend to use:

```text
/auth/login
/auth/csrf
/auth/config
```

without enabling permissive CORS rules in Flask solely for development.

---

# Example Development Configuration

A development application might contain:

```python
from flask import Flask

from marks_toolkit.auth import AuthKit
from marks_toolkit.auth.captcha import (
    TurnstileCaptchaProvider
)

app = Flask(__name__)

app.config["SECRET_KEY"] = "development-only-secret"

app.config["MARKS_AUTH_RESET_URL"] = (
    "http://localhost:5173/reset-password"
)

app.config["MARKS_AUTH_COOKIE_SECURE"] = False

app.config[
    "MARKS_AUTH_CAPTCHA_SITE_KEY"
] = "CLOUDFLARE_TEST_SITE_KEY"

captcha_provider = TurnstileCaptchaProvider(
    secret_key="CLOUDFLARE_TEST_SECRET"
)

auth_kit = AuthKit()

auth_kit.init_app(
    app,
    user_store=user_store,
    captcha_provider=captcha_provider
)
```

Do not use development secrets in production.

---

# Environment Variables

Real secrets should not be stored in Git.

Recommended `.gitignore` entries:

```gitignore
.env
.env.*
!.env.example
```

Production values should be loaded from environment variables.

Example:

```text
SECRET_KEY
TURNSTILE_SITE_KEY
TURNSTILE_SECRET_KEY
DATABASE_URL
REDIS_URL
```

---

# Current Security Posture

The toolkit currently includes substantial security controls:

```text
Argon2 password hashing
transparent password rehashing
CSRF protection
HttpOnly cookies
SameSite cookie policy
configurable Secure cookies
Flask-Login session protection
generic login errors
case-insensitive identity matching
database uniqueness constraints
random auth IDs
single-use reset behavior
reset token expiration
forgot-password throttling
reset-password throttling
adaptive CAPTCHA
login blocking
Cloudflare Turnstile verification
shared SecurityStore architecture
Redis production adapter
trusted proxy support
audit logging
standardized JSON errors
```

The project is still under active development and should not yet be considered finished security infrastructure.

---

# Planned Security Work

Major planned additions include:

```text
automated security tests
expanded database integration testing
distributed Redis integration testing
more comprehensive audit events
persistent session management
session revocation
MFA
TOTP authenticator support
passkeys / WebAuthn
recovery codes
step-up authentication
risk-based MFA escalation
```

---

# Planned MFA Architecture

Future authentication is intended to support:

```text
normal risk
→ password

elevated risk
→ password + CAPTCHA

high risk
→ password + CAPTCHA + MFA

extreme risk
→ deny login
```

MFA methods are planned to include:

```text
Passkeys / WebAuthn
TOTP authenticator applications
Recovery codes
```

Passkeys are intended to be the preferred phishing-resistant method.

TOTP will provide compatibility with applications such as:

```text
Google Authenticator
Microsoft Authenticator
1Password
Authy
```

---

# Passkeys

Future WebAuthn/passkey support is intended to allow authentication using platform authenticators such as:

```text
Apple Face ID
Apple Touch ID
Windows Hello
Android biometrics
hardware security keys
```

The application will not store biometric data.

The device uses local biometric verification to unlock a cryptographic private key.

The server stores only the corresponding public credential.

---

# Development Philosophy

MARKS Toolkit is intentionally being built incrementally.

Each feature should:

1. have a clearly defined responsibility
2. expose reusable interfaces
3. avoid hidden application assumptions
4. fail securely
5. remain configurable
6. separate policy from infrastructure
7. preserve a stable frontend/backend contract
8. be testable independently

Examples of this design pattern include:

```text
Mailer
→ delivery abstraction

CaptchaProvider
→ CAPTCHA abstraction

UserStore
→ user persistence abstraction

SecurityStore
→ temporary security-state abstraction

AuditLogger
→ audit destination abstraction
```

This lets applications replace infrastructure without rewriting authentication behavior.

---

# Development Status

Current status:

```text
Core authentication             Working
Registration                    Working
Login                           Working
Logout                          Working
Remember me                     Working
Session restoration             Working
CSRF                            Working
Forgot password                 Working
Reset password                  Working
Single-use reset behavior       Working
Risk engine                     Working
Adaptive CAPTCHA                Working
Turnstile                       Working
Request throttling              Working
Audit logging                   Working
SQLAlchemy persistence layer    In progress
Redis adapter                   Implemented
Redis integration testing       Pending
Automated security tests        Planned
TOTP MFA                        Planned
Passkeys/WebAuthn               Planned
Recovery codes                  Planned
```

---

# Git Workflow

Before starting development on another machine:

```bash
git pull
```

After making changes:

```bash
git status
git --no-pager diff
git add .
git commit -m "Describe the change"
git push
```

Virtual environments should never be committed.

Each machine should create its own:

```text
.venv
```

and install the toolkit using:

```bash
python -m pip install -e .
```

---

# Cross-Platform Development

The same repository can be used across Windows, macOS, and Linux.

Source code and configuration files are synchronized through Git.

Local artifacts such as:

```text
.venv
node_modules
.env
cookie test files
build output
```

should remain excluded from Git.

---

# Security Notice

MARKS Toolkit is under active development.

Although the project already implements a substantial set of modern authentication protections, security-sensitive applications should perform independent review and testing before production deployment.

Never commit:

```text
passwords
private API keys
Turnstile production secrets
database credentials
session secrets
reset tokens
TOTP secrets
private cryptographic keys
```

to the repository.

---

# License

A license has not yet been defined for the project.

Add the appropriate license before distributing the toolkit publicly.
