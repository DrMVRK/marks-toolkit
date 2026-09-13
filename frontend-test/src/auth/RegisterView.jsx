export default function RegisterView({
    onLogin
}) {
    return (
        <div>
            <h2>Create Account</h2>

            <input
                type="text"
                placeholder="Username"
            />

            <input
                type="email"
                placeholder="Email"
            />

            <input
                type="password"
                placeholder="Password"
            />

            <button type="button">
                Register
            </button>

            <button
                type="button"
                onClick={onLogin}
            >
                Already have an account?
            </button>
        </div>
    );
}