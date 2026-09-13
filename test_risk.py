import time

from marks_toolkit.auth.risk import RiskService


risk = RiskService(
    captcha_threshold=2,
    block_threshold=4,
    failure_window_seconds=2
)

identity = "mark@example.com"
ip_address = "127.0.0.1"


print("\n--- RISK SERVICE TEST ---")


# 1. Fresh identity should have no risk
decision = risk.assess(
    action="login",
    identity=identity,
    ip_address=ip_address
)

print("Initial score:", decision.score)
print("Initial captcha required:", decision.captcha_required)
print("Initial blocked:", decision.blocked)


# 2. Record two failed logins
risk.record_failure(
    "login",
    identity,
    ip_address
)

risk.record_failure(
    "login",
    identity,
    ip_address
)


# 3. Two failures should now require CAPTCHA
decision = risk.assess(
    "login",
    identity,
    ip_address
)

print("\nAfter two failures:")
print("Score:", decision.score)
print("Captcha required:", decision.captcha_required)
print("Blocked:", decision.blocked)


# 4. Wait longer than the 2-second failure window
print("\nWaiting for failures to expire...")
time.sleep(3)


# 5. Assess again
decision = risk.assess(
    "login",
    identity,
    ip_address
)

print("\nAfter expiration:")
print("Score:", decision.score)
print("Captcha required:", decision.captcha_required)
print("Blocked:", decision.blocked)


print("\n--- SUCCESS CLEANUP TEST ---")

risk.record_failure(
    "login",
    identity,
    ip_address
)

risk.record_failure(
    "login",
    identity,
    ip_address
)

decision = risk.assess(
    "login",
    identity,
    ip_address
)

print("Before successful login:")
print("Score:", decision.score)
print("Captcha required:", decision.captcha_required)

risk.record_success(
    "login",
    identity,
    ip_address
)

decision = risk.assess(
    "login",
    identity,
    ip_address
)

print("\nAfter successful login:")
print("Score:", decision.score)
print("Captcha required:", decision.captcha_required)