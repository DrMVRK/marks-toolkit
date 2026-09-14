import { useState } from "react";
import { useAuth } from "./AuthProvider";


export default function RegisterView({
    onLogin
}) {
    const {
        client,
        ready
    } = useAuth();

    const [username, setUsername] = useState("");
    const [email, setEmail] = useState("");
    const [password, setPassword] = useState("");

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
            const response = await client.register({
                email,
                username,
                password
            });

            if (!response.ok) {
                setError(response.error);
                return;
            }

            setSuccess(
                "Account created successfully. You can now sign in."
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
            <h2>Create Account</h2>

            <input
                type="text"
                placeholder="Username"
                value={username}
                onChange={(event) =>
                    setUsername(event.target.value)
                }
                autoComplete="username"
            />

            <input
                type="email"
                placeholder="Email"
                value={email}
                onChange={(event) =>
                    setEmail(event.target.value)
                }
                autoComplete="email"
            />

            <input
                type="password"
                placeholder="Password"
                value={password}
                onChange={(event) =>
                    setPassword(event.target.value)
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
                {loading
                    ? "Creating account..."
                    : "Create Account"}
            </button>

            <div className="marks-auth-actions">
                <button
                    type="button"
                    onClick={onLogin}
                >
                    Already have an account?
                </button>
            </div>
        </form>
    );
}