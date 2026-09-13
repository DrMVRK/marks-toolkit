export default function ResetPasswordView({
    resetToken,
    onLogin
}) {
    return (
        <div>
            <h2>Reset Password</h2>

            <input
                type="password"
                placeholder="New password"
            />

            <button type="button">
                Reset Password
            </button>

            <button
                type="button"
                onClick={onLogin}
            >
                Back to login
            </button>

            <input
                type="hidden"
                value={resetToken || ""}
                readOnly
            />
        </div>
    );
}