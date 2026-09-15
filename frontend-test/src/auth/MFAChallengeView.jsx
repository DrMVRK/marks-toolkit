import { useState } from "react";

import { useAuth } from "./AuthProvider";


export default function MFAChallengeView({
    challengeId,
    methods = [],
    onSuccess,
    onCancel,
}) {
    const { client } = useAuth();

    const [method, setMethod] = useState(
        methods.includes("totp")
            ? "totp"
            : "recovery_code"
    );

    const [code, setCode] = useState("");
    const [error, setError] = useState("");
    const [loading, setLoading] = useState(false);

    async function handleSubmit(event) {
        event.preventDefault();

        setError("");
        setLoading(true);

        try {
            let response;

            if (method === "totp") {
                response = await client.completeTotpChallenge({
                    challengeId,
                    code,
                });
            } else {
                response =
                    await client.completeRecoveryCodeChallenge({
                        challengeId,
                        recoveryCode: code,
                    });
            }

            if (!response.ok) {
                setError(
                    response.error?.message
                    || "Authentication failed."
                );

                return;
            }

            onSuccess(response.data);

        } catch {
            setError(
                "Unable to complete authentication."
            );

        } finally {
            setLoading(false);
        }
    }

    return (
        <form
            className="marks-auth-form"
            onSubmit={handleSubmit}
        >
            <h2>Verify your identity</h2>

            {method === "totp" ? (
                <>
                    <p>
                        Enter the 6-digit code from your
                        authenticator app.
                    </p>

                    <input
                        type="text"
                        inputMode="numeric"
                        autoComplete="one-time-code"
                        value={code}
                        onChange={(event) =>
                            setCode(event.target.value)
                        }
                        placeholder="123456"
                        required
                    />
                </>
            ) : (
                <>
                    <p>
                        Enter one of your recovery codes.
                    </p>

                    <input
                        type="text"
                        autoComplete="off"
                        value={code}
                        onChange={(event) =>
                            setCode(event.target.value)
                        }
                        placeholder="XXXX-XXXX-XXXX-XXXX"
                        required
                    />
                </>
            )}

            {error && (
                <div className="marks-auth-error">
                    {error}
                </div>
            )}

            <button
                type="submit"
                disabled={loading || !code.trim()}
            >
                {loading
                    ? "Verifying..."
                    : "Verify"}
            </button>

            {methods.includes("totp")
                && methods.includes("recovery_code")
                && (
                    <button
                        type="button"
                        className="marks-auth-secondary"
                        onClick={() => {
                            setCode("");
                            setError("");

                            setMethod(
                                method === "totp"
                                    ? "recovery_code"
                                    : "totp"
                            );
                        }}
                    >
                        {method === "totp"
                            ? "Use recovery code"
                            : "Use authenticator code"}
                    </button>
                )}

            <button
                type="button"
                className="marks-auth-secondary"
                onClick={onCancel}
            >
                Cancel
            </button>
        </form>
    );
}