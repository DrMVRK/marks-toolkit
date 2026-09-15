import { useState } from "react";

import AuthModal from "./auth/AuthModal";
import {
    AuthProvider,
    useAuth
} from "./auth/AuthProvider";

import "./auth/auth.css";


function AuthStatus() {
    const {
        authenticated,
        user,
        logout
    } = useAuth();

    return (
        <div>
            <pre>
                {JSON.stringify(
                    {
                        authenticated,
                        user
                    },
                    null,
                    2
                )}
            </pre>

            {authenticated && (
                <button
                    type="button"
                    onClick={logout}
                >
                    Log Out
                </button>
            )}
        </div>
    );
}


function DevMFAControls() {
    const {
        client,
        authenticated
    } = useAuth();

    const [status, setStatus] = useState(null);
    const [secret, setSecret] = useState("");
    const [code, setCode] = useState("");
    const [recoveryCodes, setRecoveryCodes] = useState([]);
    const [message, setMessage] = useState("");

    async function refreshStatus() {
        setMessage("");

        const response = await client.get(
            "/mfa/status"
        );

        if (response.ok) {
            setStatus(response.data);
        } else {
            setMessage(
                response.error?.message
                || "Unable to load MFA status."
            );
        }
    }

    async function enrollTotp() {
        setMessage("");

        const response = await client.post(
            "/mfa/totp/enroll"
        );

        if (!response.ok) {
            setMessage(
                response.error?.message
                || "Unable to start enrollment."
            );

            return;
        }

        setSecret(
            response.data.secret
        );

        setMessage(
            "TOTP enrollment started. "
            + "Add the setup key to your authenticator app."
        );
    }

    async function verifyTotp() {
        setMessage("");

        const response = await client.post(
            "/mfa/totp/verify-enrollment",
            {
                code
            }
        );

        if (!response.ok) {
            setMessage(
                response.error?.message
                || "Verification failed."
            );

            return;
        }

        setMessage(
            "TOTP enabled successfully."
        );

        setCode("");
        setSecret("");

        await refreshStatus();
    }

    async function generateRecoveryCodes() {
        const currentPassword = window.prompt(
            "Enter your current password"
        );

        if (!currentPassword) {
            return;
        }

        setMessage("");

        const response = await client.post(
            "/mfa/recovery-codes/generate",
            {
                current_password:
                    currentPassword
            }
        );

        if (!response.ok) {
            setMessage(
                response.error?.message
                || "Unable to generate recovery codes."
            );

            return;
        }

        setRecoveryCodes(
            response.data.codes || []
        );

        setMessage(
            "Recovery codes generated. "
            + "Save them somewhere safe."
        );

        await refreshStatus();
    }

    async function disableTotp() {
        const currentPassword = window.prompt(
            "Enter your current password"
        );

        if (!currentPassword) {
            return;
        }

        setMessage("");

        const response = await client.post(
            "/mfa/totp/disable",
            {
                current_password:
                    currentPassword
            }
        );

        if (!response.ok) {
            setMessage(
                response.error?.message
                || "Unable to disable TOTP."
            );

            return;
        }

        setSecret("");
        setCode("");
        setRecoveryCodes([]);

        setMessage(
            "TOTP disabled successfully."
        );

        await refreshStatus();
    }

    if (!authenticated) {
        return null;
    }

    return (
        <div
            style={{
                marginTop: "2rem",
                padding: "1rem",
                border: "1px solid #ccc"
            }}
        >
            <h2>
                Development MFA Controls
            </h2>

            <button
                type="button"
                onClick={refreshStatus}
            >
                Refresh MFA Status
            </button>

            {status && (
                <pre>
                    {JSON.stringify(
                        status,
                        null,
                        2
                    )}
                </pre>
            )}

            <hr />

            <button
                type="button"
                onClick={enrollTotp}
            >
                Start TOTP Enrollment
            </button>

            {secret && (
                <>
                    <p>
                        Add this setup key to
                        your authenticator app:
                    </p>

                    <code>
                        {secret}
                    </code>

                    <div
                        style={{
                            marginTop: "1rem"
                        }}
                    >
                        <input
                            type="text"
                            inputMode="numeric"
                            value={code}
                            onChange={(event) =>
                                setCode(
                                    event.target.value
                                )
                            }
                            placeholder="6-digit code"
                        />

                        <button
                            type="button"
                            onClick={verifyTotp}
                        >
                            Verify TOTP
                        </button>
                    </div>
                </>
            )}

            <hr />

            <button
                type="button"
                onClick={
                    generateRecoveryCodes
                }
            >
                Generate Recovery Codes
            </button>

            {recoveryCodes.length > 0 && (
                <div>
                    <h3>
                        Recovery Codes
                    </h3>

                    <ul>
                        {recoveryCodes.map(
                            (recoveryCode) => (
                                <li
                                    key={
                                        recoveryCode
                                    }
                                >
                                    <code>
                                        {
                                            recoveryCode
                                        }
                                    </code>
                                </li>
                            )
                        )}
                    </ul>
                </div>
            )}

            <hr />

            <button
                type="button"
                onClick={disableTotp}
            >
                Disable TOTP
            </button>

            {message && (
                <p>
                    {message}
                </p>
            )}
        </div>
    );
}


function App() {
    const [
        authOpen,
        setAuthOpen
    ] = useState(false);

    return (
        <AuthProvider>
            <div
                style={{
                    padding: "40px"
                }}
            >
                <h1>
                    MARKS Toolkit Auth Test
                </h1>

                <AuthStatus />

                <button
                    type="button"
                    onClick={() =>
                        setAuthOpen(true)
                    }
                >
                    Open Auth
                </button>

                <AuthModal
                    open={authOpen}
                    onClose={() =>
                        setAuthOpen(false)
                    }
                />

                <DevMFAControls />
            </div>
        </AuthProvider>
    );
}


export default App;