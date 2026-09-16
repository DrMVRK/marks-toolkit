# MARKS Toolkit frontend demo presentation layer

This bundle contains a polished presentation shell for `frontend-test`.

## Files

Copy these into the existing repository:

```text
frontend-test/
└── src/
    ├── App.jsx
    ├── demo.css
    └── components/
        ├── DemoHeader.jsx
        ├── SecurityBadge.jsx
        └── UserDashboard.jsx
```

The existing files under:

```text
frontend-test/src/auth/
```

are intentionally left untouched.

## Design

The shell adds:

- branded MARKS Toolkit header
- responsive landing page
- polished sign-in/register call-to-action
- security capability badges
- authenticated account dashboard
- dedicated MFA/security section
- demo information panel
- dark/light theme toggle
- responsive mobile layout
- explicit development-environment labeling
- automatic reset-token detection from `token` or `reset_token` query parameters

## AuthModal integration assumption

`App.jsx` uses the documented modal-first frontend and passes:

```jsx
<AuthModal
    open={authOpen}
    onClose={() => setAuthOpen(false)}
    initialView={authView}
    resetToken={resetToken}
/>
```

If your local `AuthModal` currently names the visibility prop `isOpen`
instead of `open`, change only this line:

```jsx
open={authOpen}
```

to:

```jsx
isOpen={authOpen}
```

No backend or authentication-service changes are required.

## Verify

From `frontend-test`:

```powershell
npm run build
npm run dev
```

Then manually exercise:

1. Login
2. Registration
3. Forgot password
4. Reset link
5. MFA challenge
6. MFA enrollment
7. Recovery-code generation
8. TOTP disable
9. Logout
10. Theme toggle
