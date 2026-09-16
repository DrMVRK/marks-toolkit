const CONTROLS = [
    {
        title: "CSRF protection",
        body: "State-changing authentication requests are protected.",
    },
    {
        title: "Secure session handling",
        body: "Flask-Login sessions use rotating authentication identifiers.",
    },
    {
        title: "MFA and recovery",
        body: "TOTP, replay prevention, and atomic recovery codes are available.",
    },
    {
        title: "Abuse controls",
        body: "Risk tracking, throttling, and adaptive CAPTCHA protect auth endpoints.",
    },
];


export default function UserDashboard({
    user,
    onManageSecurity,
}) {
    const displayName =
        user?.username ||
        user?.email?.split("@")[0] ||
        "there";

    return (
        <div className="demo-panel-stack">
            <div className="demo-dashboard-hero">
                <div>
                    <span className="demo-eyebrow">
                        AUTHENTICATED
                    </span>
                    <h1>
                        Welcome back, {displayName}.
                    </h1>
                    <p>
                        This dashboard is presentation
                        scaffolding around the real MARKS
                        Toolkit authentication state.
                    </p>
                </div>

                <div className="demo-authenticated-chip">
                    <span />
                    Session active
                </div>
            </div>

            <div className="demo-account-card">
                <div className="demo-card-heading">
                    <div>
                        <span className="demo-eyebrow">
                            ACCOUNT
                        </span>
                        <h2>Current identity</h2>
                    </div>

                    <button
                        type="button"
                        className="demo-button demo-button--secondary demo-button--small"
                        onClick={onManageSecurity}
                    >
                        Manage security
                    </button>
                </div>

                <dl className="demo-account-details">
                    <div>
                        <dt>Email</dt>
                        <dd>
                            {user?.email || "Not provided"}
                        </dd>
                    </div>
                    <div>
                        <dt>Username</dt>
                        <dd>
                            {user?.username ||
                                "Not provided"}
                        </dd>
                    </div>
                    <div>
                        <dt>Session</dt>
                        <dd>
                            <span className="demo-inline-status">
                                <span />
                                Authenticated
                            </span>
                        </dd>
                    </div>
                    <div>
                        <dt>Environment</dt>
                        <dd>Development harness</dd>
                    </div>
                </dl>
            </div>

            <div>
                <div className="demo-card-heading demo-card-heading--spaced">
                    <div>
                        <span className="demo-eyebrow">
                            ACTIVE CONTROLS
                        </span>
                        <h2>
                            Security capabilities
                        </h2>
                    </div>
                </div>

                <div className="demo-control-grid">
                    {CONTROLS.map((control) => (
                        <article
                            className="demo-control-card"
                            key={control.title}
                        >
                            <div className="demo-control-icon">
                                ✓
                            </div>
                            <div>
                                <h3>
                                    {control.title}
                                </h3>
                                <p>{control.body}</p>
                            </div>
                        </article>
                    ))}
                </div>
            </div>
        </div>
    );
}
