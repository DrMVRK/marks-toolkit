function SunIcon() {
    return (
        <svg viewBox="0 0 24 24" aria-hidden="true">
            <circle cx="12" cy="12" r="4" />
            <path d="M12 2v2M12 20v2M4.93 4.93l1.42 1.42M17.66 17.66l1.41 1.41M2 12h2M20 12h2M4.93 19.07l1.42-1.42M17.66 6.34l1.41-1.41" />
        </svg>
    );
}


function MoonIcon() {
    return (
        <svg viewBox="0 0 24 24" aria-hidden="true">
            <path d="M20 15.2A8.5 8.5 0 0 1 8.8 4 8.5 8.5 0 1 0 20 15.2Z" />
        </svg>
    );
}


export default function DemoHeader({
    authenticated,
    user,
    theme,
    onThemeToggle,
    onLogin,
    onRegister,
    onLogout,
}) {
    return (
        <header className="demo-header">
            <a
                className="demo-brand"
                href="/"
                aria-label="MARKS Toolkit demo home"
            >
                <span className="demo-brand-mark">
                    M
                </span>
                <span>
                    <strong>MARKS</strong>
                    <small>Toolkit</small>
                </span>
            </a>

            <div className="demo-header-center">
                <span className="demo-live-dot" />
                Auth demo
                <span className="demo-version-pill">
                    v0.1.0
                </span>
            </div>

            <div className="demo-header-actions">
                <button
                    type="button"
                    className="demo-icon-button"
                    onClick={onThemeToggle}
                    aria-label={`Switch to ${
                        theme === "dark"
                            ? "light"
                            : "dark"
                    } theme`}
                >
                    {theme === "dark" ? (
                        <SunIcon />
                    ) : (
                        <MoonIcon />
                    )}
                </button>

                {!authenticated ? (
                    <>
                        <button
                            type="button"
                            className="demo-header-link"
                            onClick={onLogin}
                        >
                            Sign in
                        </button>

                        <button
                            type="button"
                            className="demo-button demo-button--small demo-button--primary"
                            onClick={onRegister}
                        >
                            Create account
                        </button>
                    </>
                ) : (
                    <>
                        <div className="demo-header-user">
                            <span>
                                {(
                                    user?.username ||
                                    user?.email ||
                                    "U"
                                )
                                    .charAt(0)
                                    .toUpperCase()}
                            </span>
                            <div>
                                <strong>
                                    {user?.username ||
                                        "Account"}
                                </strong>
                                <small>Authenticated</small>
                            </div>
                        </div>

                        <button
                            type="button"
                            className="demo-header-link"
                            onClick={onLogout}
                        >
                            Log out
                        </button>
                    </>
                )}
            </div>
        </header>
    );
}
