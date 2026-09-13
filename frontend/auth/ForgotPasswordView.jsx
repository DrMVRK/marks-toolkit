export default function ForgotPasswordView({
    onLogin
}) {
    return (
        <div>
            <h2>Forgot Password</h2>

            <input
                type="email"
                placeholder="Email"
            />

            <button type="button">
                Send Reset Link
            </button>

            <button
                type="button"
                onClick={onLogin}
            >
                Back to login
            </button>
        </div>
    );
}