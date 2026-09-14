import { useState } from "react";
import { useAuth } from "./AuthProvider";


export default function ForgotPasswordView({
    onLogin
}) {
    const {
        client,
        ready
    } = useAuth();

    const [email, setEmail] = useState("");
    const [error, setError] = useState(null);
    const [success, setSuccess] = useState(null);
    const [loading, setLoading] = useState(false);

    async function handleSubmit(event) {
        event.preventDefault();

        if (!ready || loading) {
            return;
        }

        setLoading(true);
        setError(null);
        setSuccess(null);

        try {
            const response =
                await client.forgotPassword(email);

            if (!response.ok) {
                setError(response.error);
                return;
            }

            setSuccess(
                response.message ||
                "If an account exists for that email, a password reset link has been sent."
            );

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
            <h2>Forgot Password</h2>

            <p>
                Enter your email address and we’ll send you
                instructions to reset your password.
            </p>

            <input
                type="email"
                placeholder="Email"
                value={email}
                onChange={(event) =>
                    setEmail(event.target.value)
                }
                autoComplete="email"
            />

            {error && (
                <p className="marks-auth-error">
                    {error.message}
                </p>
            )}

            {success && (
                <p className="marks-auth-success">
                    {success}
                </p>
            )}

            <button
                type="submit"
                disabled={!ready || loading}
            >
                {loading
                    ? "Sending..."
                    : "Send Reset Link"}
            </button>

            <div className="marks-auth-actions">
                <button
                    type="button"
                    onClick={onLogin}
                >
                    Back to Login
                </button>
            </div>
        </form>
    );
}