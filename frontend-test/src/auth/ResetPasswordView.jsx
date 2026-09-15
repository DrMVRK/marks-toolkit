import { useState } from "react";
import { useAuth } from "./AuthProvider";


export default function ResetPasswordView({
    resetToken,
    onLogin
}) {
    const {
        client,
        ready
    } = useAuth();

    const [password, setPassword] =
        useState("");

    const [
        confirmPassword,
        setConfirmPassword
    ] = useState("");

    const [error, setError] =
        useState(null);

    const [success, setSuccess] =
        useState(null);

    const [loading, setLoading] =
        useState(false);


    function clearPasswordFields() {
        setPassword("");
        setConfirmPassword("");
    }


    async function handleSubmit(event) {
        event.preventDefault();

        if (!ready || loading) {
            return;
        }

        setError(null);
        setSuccess(null);

        if (!resetToken) {
            clearPasswordFields();

            setError({
                code: "MISSING_RESET_TOKEN",
                message:
                    "This password reset link is invalid."
            });

            return;
        }

        if (password !== confirmPassword) {
            setError({
                code: "PASSWORD_MISMATCH",
                message:
                    "Passwords do not match."
            });

            return;
        }

        setLoading(true);

        try {
            const response =
                await client.resetPassword({
                    token: resetToken,
                    password
                });

            if (!response.ok) {
                setError(response.error);
                return;
            }

            clearPasswordFields();

            setSuccess(
                response.message ||
                "Password reset successfully."
            );

        } catch (requestError) {
            setError({
                code: "NETWORK_ERROR",
                message:
                    "Unable to contact the authentication server."
            });

        } finally {
            setLoading(false);
        }
    }


    function handleBackToLogin() {
        clearPasswordFields();
        setError(null);
        setSuccess(null);

        onLogin();
    }


    return (
        <form onSubmit={handleSubmit}>
            <h2>Reset Password</h2>

            <input
                type="password"
                placeholder="New password"
                value={password}
                onChange={(event) =>
                    setPassword(
                        event.target.value
                    )
                }
                autoComplete="new-password"
            />

            <input
                type="password"
                placeholder="Confirm new password"
                value={confirmPassword}
                onChange={(event) =>
                    setConfirmPassword(
                        event.target.value
                    )
                }
                autoComplete="new-password"
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
                {
                    loading
                        ? "Resetting password..."
                        : "Reset Password"
                }
            </button>

            <div className="marks-auth-actions">
                <button
                    type="button"
                    onClick={
                        handleBackToLogin
                    }
                >
                    Back to Login
                </button>
            </div>
        </form>
    );
}