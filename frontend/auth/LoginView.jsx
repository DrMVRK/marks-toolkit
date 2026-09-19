import { useState } from "react";

import { useAuth } from "./AuthProvider";
import CaptchaChallenge from "./CaptchaChallenge";


export default function LoginView({
    onRegister,
    onForgotPassword,
    onMFARequired
}) {
    const {
        client,
        config,
        ready,
        handleLogin
    } = useAuth();

    const [identity, setIdentity] =
        useState("");

    const [password, setPassword] =
        useState("");

    const [remember, setRemember] =
        useState(false);

    const [error, setError] =
        useState(null);

    const [loading, setLoading] =
        useState(false);

    const [
        passkeyLoading,
        setPasskeyLoading
    ] = useState(false);

    const [
        captchaRequired,
        setCaptchaRequired
    ] = useState(false);

    const [
        captchaToken,
        setCaptchaToken
    ] = useState(null);


    async function handleSubmit(
        event
    ) {
        event.preventDefault();

        if (
            !ready
            || loading
            || passkeyLoading
        ) {
            return;
        }

        setLoading(true);
        setError(null);

        try {
            const response =
                await client.login({
                    identity,
                    password,
                    remember,
                    captchaToken
                });

            if (!response.ok) {
                if (
                    response.error?.code
                    === "CAPTCHA_REQUIRED"
                ) {
                    setCaptchaRequired(
                        true
                    );

                    setCaptchaToken(
                        null
                    );

                    setError(null);

                    return;
                }

                setError(
                    response.error
                );

                return;
            }

            if (
                response.data
                    ?.mfa_required
                && response.data
                    ?.challenge_id
            ) {
                onMFARequired({
                    challengeId:
                        response.data
                            .challenge_id,

                    methods:
                        response.data
                            .methods
                        || []
                });

                return;
            }

            handleLogin(
                response.data
            );

        } catch (requestError) {
            console.error(
                "Login request failed:",
                requestError
            );

            setError({
                code: "NETWORK_ERROR",
                message:
                    "Unable to contact the authentication server."
            });

        } finally {
            setLoading(false);
        }
    }


    async function handlePasskeyLogin() {
        if (
            !ready
            || loading
            || passkeyLoading
        ) {
            return;
        }

        setPasskeyLoading(true);
        setError(null);

        try {
            if (
                typeof window
                    .PublicKeyCredential
                === "undefined"
                || typeof navigator
                    .credentials?.get
                    !== "function"
            ) {
                setError({
                    code:
                        "WEBAUTHN_UNAVAILABLE",

                    message:
                        "Passkeys are not supported by this browser."
                });

                return;
            }

            if (
                typeof PublicKeyCredential
                    .parseRequestOptionsFromJSON
                !== "function"
            ) {
                setError({
                    code:
                        "WEBAUTHN_UNAVAILABLE",

                    message:
                        "This browser does not support the required passkey login API."
                });

                return;
            }

            const beginResponse =
                await client
                    .beginPasskeyLogin();

            if (!beginResponse.ok) {
                setError(
                    beginResponse.error
                    || {
                        message:
                            "Unable to start passkey authentication."
                    }
                );

                return;
            }

            const {
                challenge_id:
                    challengeId,

                options
            } = beginResponse.data;

            const publicKey =
                PublicKeyCredential
                    .parseRequestOptionsFromJSON(
                        options
                    );

            const credential =
                await navigator
                    .credentials
                    .get({
                        publicKey
                    });

            if (!credential) {
                setError({
                    code:
                        "PASSKEY_CANCELLED",

                    message:
                        "Passkey authentication was cancelled."
                });

                return;
            }

            if (
                typeof credential
                    .toJSON
                !== "function"
            ) {
                setError({
                    code:
                        "WEBAUTHN_UNAVAILABLE",

                    message:
                        "This browser cannot serialize the passkey response."
                });

                return;
            }

            const serialized =
                credential.toJSON();

            const finishResponse =
                await client
                    .finishPasskeyLogin({
                        challengeId,
                        credential:
                            serialized
                    });

            if (!finishResponse.ok) {
                setError(
                    finishResponse.error
                    || {
                        message:
                            "Passkey authentication failed."
                    }
                );

                return;
            }

            if (remember) {
                try {
                    localStorage.setItem(
                        "marks_auth_remembered_account",
                        JSON.stringify({
                            username:
                                finishResponse
                                    .data
                                    .username,

                            email:
                                finishResponse
                                    .data
                                    .email
                        })
                    );

                } catch (
                    storageError
                ) {
                    console.warn(
                        "Unable to remember account hint:",
                        storageError
                    );
                }

            } else {
                try {
                    localStorage.removeItem(
                        "marks_auth_remembered_account"
                    );

                } catch (
                    storageError
                ) {
                    console.warn(
                        "Unable to clear account hint:",
                        storageError
                    );
                }
            }

            handleLogin(
                finishResponse.data
            );

        } catch (requestError) {
            console.error(
                "Passkey login failed:",
                requestError
            );

            if (
                requestError?.name
                === "NotAllowedError"
            ) {
                setError({
                    code:
                        "PASSKEY_CANCELLED",

                    message:
                        "Passkey authentication was cancelled or timed out."
                });

                return;
            }

            setError({
                code: "PASSKEY_ERROR",
                message:
                    "Unable to sign in with a passkey."
            });

        } finally {
            setPasskeyLoading(
                false
            );
        }
    }


    const passkeysAvailable = (
        config?.passkeys_available
        === true
    );


    return (
        <form onSubmit={handleSubmit}>
            <h2>
                Sign In
            </h2>

            <input
                type="text"
                placeholder={
                    "Email or username"
                }
                value={identity}
                onChange={(event) =>
                    setIdentity(
                        event.target.value
                    )
                }
                autoComplete={
                    "username webauthn"
                }
            />

            <input
                type="password"
                placeholder="Password"
                value={password}
                onChange={(event) =>
                    setPassword(
                        event.target.value
                    )
                }
                autoComplete={
                    "current-password"
                }
            />

            <label>
                <input
                    type="checkbox"
                    checked={remember}
                    onChange={(event) =>
                        setRemember(
                            event.target
                                .checked
                        )
                    }
                />

                Remember me
            </label>

            {captchaRequired && (
                <CaptchaChallenge
                    siteKey={
                        config
                            ?.captcha_site_key
                    }

                    onSuccess={(
                        token
                    ) => {
                        setCaptchaToken(
                            token
                        );

                        setError(null);
                    }}

                    onExpired={() => {
                        setCaptchaToken(
                            null
                        );
                    }}

                    onError={() => {
                        setCaptchaToken(
                            null
                        );

                        setError({
                            code:
                                "CAPTCHA_ERROR",

                            message:
                                "The security check could not be completed."
                        });
                    }}
                />
            )}

            {error && (
                <p className="marks-auth-error">
                    {
                        error.message
                        || "An authentication error occurred."
                    }
                </p>
            )}

            <button
                type="submit"
                disabled={
                    !ready
                    || loading
                    || passkeyLoading
                    || (
                        captchaRequired
                        && !captchaToken
                    )
                }
            >
                {
                    loading
                        ? "Signing in..."
                        : "Sign In"
                }
            </button>

            {passkeysAvailable && (
                <>
                    <div
                        className={
                            "marks-auth-divider"
                        }
                    >
                        <span>
                            or
                        </span>
                    </div>

                    <button
                        type="button"
                        className={
                            "marks-auth-secondary"
                        }
                        onClick={
                            handlePasskeyLogin
                        }
                        disabled={
                            !ready
                            || loading
                            || passkeyLoading
                        }
                    >
                        {
                            passkeyLoading
                                ? "Waiting for passkey..."
                                : "Sign in with a passkey"
                        }
                    </button>
                </>
            )}

            <div className="marks-auth-actions">
                <button
                    type="button"
                    onClick={
                        onForgotPassword
                    }
                >
                    Forgot password?
                </button>

                <button
                    type="button"
                    onClick={
                        onRegister
                    }
                >
                    Create account
                </button>
            </div>
        </form>
    );
}