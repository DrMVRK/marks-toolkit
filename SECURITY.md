Security Policy

MARKS Toolkit is a reusable authentication and application-security toolkit. Security reports are taken seriously, especially when they affect authentication, session handling, password recovery, MFA, CAPTCHA, throttling, cryptographic secret handling, or persistence adapters.

Supported Versions

MARKS Toolkit is currently under active development and has not yet reached a stable 1.0 release.

Security fixes are expected to target the current development branch and the most recent published release, if releases are available.

Version

Supported

Current main branch

Yes

Latest published release

Yes

Older development snapshots

No guarantee

Modified third-party forks

No

Until a formal long-term-support policy is published, users should stay current with the latest security fixes.

Reporting a Vulnerability

Please do not open a public GitHub issue for a suspected security vulnerability before coordinated disclosure has occurred.

A private report should include as much of the following as possible:

affected component or file

affected version, commit, or branch

vulnerability description

steps to reproduce

proof-of-concept details, if available

expected behavior

actual behavior

estimated security impact

conditions required for exploitation

suggested mitigation, if known

Please avoid including real production secrets, credentials, session cookies, recovery codes, MFA secrets, private user data, or other sensitive information in a report.

Preferred Reporting Channel

Until a dedicated security-reporting address is published, use GitHub's private vulnerability reporting feature for this repository when available.

If private vulnerability reporting is not enabled, contact the repository owner privately before publishing technical details.

Do not publish working exploit details in a public issue while a vulnerability is still being investigated.

Responsible Disclosure

When a valid security issue is reported, the project intends to:

confirm receipt of the report

reproduce and assess the issue

determine affected components and versions

develop and test a remediation

update tests to prevent regression where practical

publish the fix

disclose technical details after users have had a reasonable opportunity to update

Exact response times cannot be guaranteed for this independently maintained project.

Security Scope

Reports are especially useful when they involve:

authentication bypass

authorization bypass in toolkit-owned functionality

account takeover paths

password reset weaknesses

reset-token replay or forgery

session fixation or session revocation failures

remember-cookie weaknesses

CSRF bypass

MFA bypass

MFA challenge replay

TOTP replay

recovery-code reuse

CAPTCHA validation bypass

rate-limit or risk-control bypass

user-enumeration or significant authentication timing leaks

insecure cryptographic key handling

plaintext credential or MFA-secret storage

sensitive-data leakage through responses or logs

insecure default configuration

Redis-backed security-state consistency issues

SQLAlchemy persistence bugs that compromise authentication security

malformed-input paths that bypass security controls

Out of Scope

The following are generally outside the toolkit's direct security scope unless the issue is caused by MARKS Toolkit itself:

vulnerabilities in Flask, Flask-Login, Redis, SQLAlchemy, Argon2, cryptography, PyOTP, httpx, React, or other third-party dependencies

insecure host-application authorization logic outside AuthKit

compromised infrastructure

compromised operating systems

leaked host-application environment variables

insecure reverse-proxy configuration not caused by AuthKit

weak host-application secret generation

database or Redis exposure caused by deployment configuration

email-provider compromise

CAPTCHA-provider compromise

vulnerabilities introduced by downstream modifications to the toolkit

Third-party dependency vulnerabilities should normally be reported to the relevant upstream project.

Production Security Assumptions

MARKS Toolkit provides secure mechanisms, but production security still depends on correct deployment.

Production applications are expected to provide:

HTTPS

secure session and remember cookies

a strong Flask SECRET_KEY

a stable external MFA encryption key

a stable external recovery-code HMAC key

persistent user storage

persistent MFA storage

database migrations

a production mail provider

production CAPTCHA credentials

CAPTCHA hostname validation

CAPTCHA action validation where applicable

Redis-backed shared security state for multi-worker deployments

trusted reverse-proxy configuration

secure database and Redis networking

production secret-management infrastructure

centralized logging and monitoring

tested backup and recovery procedures

Development-only options must not be enabled in production, including:

MARKS_AUTH_ALLOW_CONSOLE_MAILER=True
MARKS_AUTH_ALLOW_INSECURE_RESET_URL=True
MARKS_AUTH_COOKIE_SECURE=False

Shared-State Requirements

In-memory stores are intended for tests, development, and single-process demonstrations.

Multi-worker or multi-instance deployments should use shared Redis-backed security state so authentication throttling, risk tracking, and MFA challenge state remain consistent between workers.

The application must ensure all workers use compatible:

Flask secrets

MFA encryption keys

recovery-code keys

Redis configuration

persistent database state

Cryptographic Material

Do not commit production cryptographic keys to source control.

Important secrets include:

Flask SECRET_KEY
MARKS_AUTH_MFA_ENCRYPTION_KEY
MARKS_AUTH_RECOVERY_CODE_KEY
CAPTCHA secret keys
database credentials
Redis credentials
mail-provider credentials

TOTP encryption keys and recovery-code HMAC keys serve different purposes and should remain separate.

Loss of the TOTP encryption key may make existing encrypted TOTP enrollments unusable.

Authentication State Revocation

MARKS Toolkit uses rotating authentication IDs to invalidate existing authentication state after supported security-sensitive events.

Current revocation-triggering operations include:

password change

password reset

enabling TOTP

disabling TOTP

Applications should not bypass these mechanisms when modifying authentication credentials or MFA state.

Sensitive Response Handling

Responses containing secret MFA material use Cache-Control: no-store.

This includes responses containing:

TOTP enrollment secrets

newly generated recovery codes

Host applications and reverse proxies should not override these responses with weaker cache behavior.

Security Testing

Security-sensitive changes should include regression tests where practical.

The current automated suite covers areas including:

password hashing and verification

unknown-account timing mitigation

password reset

password change

authentication-ID rotation

cookie security

malformed request validation

login risk controls

throttling

CAPTCHA behavior

Turnstile hostname/action validation

TOTP enrollment

TOTP replay prevention

recovery-code single-use behavior

MFA challenge replay prevention

Redis-backed MFA challenge behavior

secret-response cache prevention

A passing test suite does not by itself guarantee that a deployment is secure.

Disclosure Credit

Reporters who responsibly disclose valid vulnerabilities may be credited in release notes or security advisories if they wish.

Please indicate whether you want:

public credit

anonymous credit

no credit

Safe Harbor

Good-faith security research intended to identify and report vulnerabilities is welcome when it:

avoids unnecessary access to real user data

avoids service disruption

avoids destructive testing

does not retain sensitive data

stops once sufficient evidence of the issue has been collected

follows applicable law

reports the issue privately before public disclosure

This policy does not authorize testing against systems you do not own or have permission to test.

Security Disclaimer

MARKS Toolkit is intended to provide reusable security-focused authentication components, but no software library can guarantee a secure application by itself.

The host application remains responsible for:

authorization outside the toolkit

infrastructure security

dependency management

deployment configuration

secret management

operational monitoring

data protection

legal and regulatory requirements

Security should be treated as an ongoing process rather than a one-time configuration step.