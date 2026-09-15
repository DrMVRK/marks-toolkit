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

    const [identity, setIdentity] = useState("");
    const [password, setPassword] = useState("");
    const [remember, setRemember] = useState(false);

    const [error, setError] = useState(null);
    const [loading, setLoading] = useState(false);

    const [captchaRequired, setCaptchaRequired] =
        useState(false);

    const [captchaToken, setCaptchaToken] =
        useState(null);

    async function handleSubmit(event) {
        event.preventDefault();

        if (!ready || loading) {
            return;
        }

        setLoading(true);
        setError(null);

        try {
            const response = await client.login({
                identity,
                password,
                remember,
                captchaToken
            });

            if (!response.ok) {
                if (
                    response.error?.code ===
                    "CAPTCHA_REQUIRED"
                ) {
                    setCaptchaRequired(true);
                    setCaptchaToken(null);
                    setError(null);

                    return;
                }

                setError(response.error);

                return;
            }

            if (
                response.data?.mfa_required
                && response.data?.challenge_id
            ) {
                onMFARequired({
                    challengeId:
                        response.data.challenge_id,

                    methods:
                        response.data.methods || []
                });

                return;
            }

            handleLogin(response.data);

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

    return (
        <form onSubmit={handleSubmit}>
            <h2>Sign In</h2>

            <input
                type="text"
                placeholder="Email or username"
                value={identity}
                onChange={(event) =>
                    setIdentity(event.target.value)
                }
                autoComplete="username"
            />

            <input
                type="password"
                placeholder="Password"
                value={password}
                onChange={(event) =>
                    setPassword(event.target.value)
                }
                autoComplete="current-password"
            />

            <label>
                <input
                    type="checkbox"
                    checked={remember}
                    onChange={(event) =>
                        setRemember(
                            event.target.checked
                        )
                    }
                />

                Remember me
            </label>

            {captchaRequired && (
                <CaptchaChallenge
                    siteKey={
                        config?.captcha_site_key
                    }

                    onSuccess={(token) => {
                        setCaptchaToken(token);
                        setError(null);
                    }}

                    onExpired={() => {
                        setCaptchaToken(null);
                    }}

                    onError={() => {
                        setCaptchaToken(null);

                        setError({
                            code: "CAPTCHA_ERROR",
                            message:
                                "The security check could not be completed."
                        });
                    }}
                />
            )}

            {error && (
                <p className="marks-auth-error">
                    {error.message}
                </p>
            )}

            <button
                type="submit"
                disabled={
                    !ready
                    || loading
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

            <div className="marks-auth-actions">
                <button
                    type="button"
                    onClick={onForgotPassword}
                >
                    Forgot password?
                </button>

                <button
                    type="button"
                    onClick={onRegister}
                >
                    Create account
                </button>
            </div>
        </form>
    );
}