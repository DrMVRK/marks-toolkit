export default function LoginView({
    onRegister,
    onForgotPassword
}) {
    return (
        <div>
            <h2>Sign In</h2>

            <input
                type="text"
                placeholder="Email or username"
            />

            <input
                type="password"
                placeholder="Password"
            />

            <label>
                <input type="checkbox" />
                Remember me
            </label>

            <button type="button">
                Sign In
            </button>

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
    );
}