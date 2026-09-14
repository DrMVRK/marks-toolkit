import { useState } from "react";
import { useAuth } from "./AuthProvider";


export default function LoginView({
    onRegister,
    onForgotPassword
}) {
    const {
        client,
        ready,
        handleLogin
    } = useAuth();

    const [identity, setIdentity] = useState("");
    const [password, setPassword] = useState("");
    const [remember, setRemember] = useState(false);

    const [error, setError] = useState(null);
    const [loading, setLoading] = useState(false);

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
                remember
            });

            if (!response.ok) {
                setError(response.error);
                return;
            }

            handleLogin(response.data);

        } catch (requestError) {
            setError({
                code: "NETWORK_ERROR",
                message: "Unable to contact the authentication server."
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
                        setRemember(event.target.checked)
                    }
                />

                Remember me
            </label>

            {error && (
                <p className="marks-auth-error">
                    {error.message}
                </p>
            )}

            <button
                type="submit"
                disabled={!ready || loading}
            >
                {loading ? "Signing in..." : "Sign In"}
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