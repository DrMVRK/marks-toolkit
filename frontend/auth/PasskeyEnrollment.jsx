import { useState } from "react";

import { useAuth } from "./AuthProvider";
import ReauthDialog from "./ReauthDialog";


export default function PasskeyEnrollment({
    onEnrolled = null
}) {
    const {
        client,
        authenticated
    } = useAuth();

    const [reauthOpen, setReauthOpen] =
        useState(false);

    const [loading, setLoading] =
        useState(false);

    const [error, setError] =
        useState(null);

    const [message, setMessage] =
        useState("");

    if (!authenticated) {
        return null;
    }

    async function enrollPasskey(
        currentPassword
    ) {
        setLoading(true);
        setError(null);
        setMessage("");

        try {
            if (
                typeof window.PublicKeyCredential
                === "undefined"
                || typeof navigator.credentials
                    ?.create !== "function"
            ) {
                setError({
                    code: "WEBAUTHN_UNAVAILABLE",
                    message:
                        "Passkeys are not supported by this browser."
                });

                return;
            }

            if (
                typeof PublicKeyCredential
                    .parseCreationOptionsFromJSON
                !== "function"
            ) {
                setError({
                    code: "WEBAUTHN_UNAVAILABLE",
                    message:
                        "This browser does not support the required passkey registration API."
                });

                return;
            }

            const beginResponse =
                await client
                    .beginPasskeyRegistration({
                        currentPassword
                    });

            if (!beginResponse.ok) {
                setError(
                    beginResponse.error || {
                        message:
                            "Unable to start passkey registration."
                    }
                );

                return;
            }

            const {
                challenge_id: challengeId,
                options
            } = beginResponse.data;

            const publicKey =
                PublicKeyCredential
                    .parseCreationOptionsFromJSON(
                        options
                    );

            const credential =
                await navigator.credentials.create({
                    publicKey
                });

            if (!credential) {
                setError({
                    code: "PASSKEY_CANCELLED",
                    message:
                        "Passkey registration was cancelled."
                });

                return;
            }

            if (
                typeof credential.toJSON
                !== "function"
            ) {
                setError({
                    code: "WEBAUTHN_UNAVAILABLE",
                    message:
                        "This browser cannot serialize the passkey response."
                });

                return;
            }

            const serializedCredential =
                credential.toJSON();

            const finishResponse =
                await client
                    .finishPasskeyRegistration({
                        challengeId,
                        credential:
                            serializedCredential
                    });

            if (!finishResponse.ok) {
                setError(
                    finishResponse.error || {
                        message:
                            "Unable to verify the new passkey."
                    }
                );

                return;
            }

            setMessage(
                "Passkey registered successfully."
            );

            setReauthOpen(false);

            if (
                typeof onEnrolled
                === "function"
            ) {
                await onEnrolled(
                    finishResponse.data
                );
            }

        } catch (requestError) {
            console.error(
                "Passkey enrollment failed:",
                requestError
            );

            if (
                requestError?.name
                === "NotAllowedError"
            ) {
                setError({
                    code: "PASSKEY_CANCELLED",
                    message:
                        "Passkey registration was cancelled or timed out."
                });

                return;
            }

            setError({
                code: "PASSKEY_ERROR",
                message:
                    "Unable to register the passkey."
            });

        } finally {
            setLoading(false);
        }
    }

    return (
        <div className="marks-auth-mfa-section">
            <h3>
                Passkeys
            </h3>

            <p>
                Add a passkey to sign in using
                Touch ID, Face ID, Windows Hello,
                a device PIN, or another compatible
                authenticator.
            </p>

            {error && (
                <p className="marks-auth-error">
                    {
                        error.message
                        || "Passkey registration failed."
                    }
                </p>
            )}

            {message && (
                <p className="marks-auth-success">
                    {message}
                </p>
            )}

            <button
                type="button"
                onClick={() => {
                    setError(null);
                    setMessage("");
                    setReauthOpen(true);
                }}
                disabled={loading}
            >
                Add a Passkey
            </button>

            <ReauthDialog
                open={reauthOpen}

                title="Add a Passkey"

                message={
                    "Enter your current password before adding a new passkey."
                }

                confirmLabel={
                    "Continue"
                }

                loading={loading}

                error={error}

                onConfirm={
                    enrollPasskey
                }

                onCancel={() => {
                    setReauthOpen(false);
                    setError(null);
                }}
            />
        </div>
    );
}