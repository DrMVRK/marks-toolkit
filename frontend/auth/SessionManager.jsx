import {
    useCallback,
    useEffect,
    useState
} from "react";

import {
    useAuth
} from "./AuthProvider.jsx";


function formatDate(value) {
    if (!value) {
        return "Unknown";
    }

    const date = new Date(value);

    if (
        Number.isNaN(
            date.getTime()
        )
    ) {
        return "Unknown";
    }

    return date.toLocaleString();
}


function describeBrowser(
    userAgent
) {
    if (!userAgent) {
        return "Unknown browser";
    }

    if (
        userAgent.includes(
            "Edg/"
        )
    ) {
        return "Microsoft Edge";
    }

    if (
        userAgent.includes(
            "Chrome/"
        )
        && !userAgent.includes(
            "Edg/"
        )
    ) {
        return "Google Chrome";
    }

    if (
        userAgent.includes(
            "Firefox/"
        )
    ) {
        return "Mozilla Firefox";
    }

    if (
        userAgent.includes(
            "Safari/"
        )
        && !userAgent.includes(
            "Chrome/"
        )
    ) {
        return "Safari";
    }

    return "Browser";
}


function describeDevice(
    userAgent
) {
    if (!userAgent) {
        return "Unknown device";
    }

    if (
        userAgent.includes(
            "Windows"
        )
    ) {
        return "Windows";
    }

    if (
        userAgent.includes(
            "Macintosh"
        )
    ) {
        return "Mac";
    }

    if (
        userAgent.includes(
            "iPhone"
        )
    ) {
        return "iPhone";
    }

    if (
        userAgent.includes(
            "iPad"
        )
    ) {
        return "iPad";
    }

    if (
        userAgent.includes(
            "Android"
        )
    ) {
        return "Android";
    }

    if (
        userAgent.includes(
            "Linux"
        )
    ) {
        return "Linux";
    }

    return "Device";
}


function describeAuthentication(
    method
) {
    switch (method) {
        case "password":
            return "Password";

        case "passkey":
            return "Passkey";

        case "password+totp":
            return (
                "Password + Authenticator"
            );

        case "password+recovery_code":
            return (
                "Password + Recovery Code"
            );

        case "security-refresh":
            return (
                "Security verification"
            );

        default:
            return (
                method
                || "Unknown"
            );
    }
}


export default function SessionManager() {
    const {
        client,
        authenticated
    } = useAuth();

    const [
        sessions,
        setSessions
    ] = useState([]);

    const [
        loading,
        setLoading
    ] = useState(false);

    const [
        actionSessionId,
        setActionSessionId
    ] = useState(null);

    const [
        revokingOthers,
        setRevokingOthers
    ] = useState(false);

    const [
        error,
        setError
    ] = useState(null);

    const [
        message,
        setMessage
    ] = useState("");


    const loadSessions = useCallback(
        async () => {
            if (!authenticated) {
                setSessions([]);
                return;
            }

            setLoading(true);
            setError(null);

            try {
                const response =
                    await client.get(
                        "/sessions"
                    );

                if (!response.ok) {
                    setError(
                        response.error
                        || {
                            message:
                                "Unable to load active sessions."
                        }
                    );

                    return;
                }

                setSessions(
                    response.data
                        ?.sessions
                    || []
                );

            } catch (
                requestError
            ) {
                console.error(
                    "Session list request failed:",
                    requestError
                );

                setError({
                    code:
                        "NETWORK_ERROR",

                    message:
                        "Unable to load active sessions."
                });

            } finally {
                setLoading(false);
            }
        },
        [
            authenticated,
            client
        ]
    );


    useEffect(() => {
        loadSessions();
    }, [
        loadSessions
    ]);


    async function revokeSession(
        sessionRecord
    ) {
        if (
            !sessionRecord
            || actionSessionId
        ) {
            return;
        }

        setActionSessionId(
            sessionRecord.id
        );

        setError(null);
        setMessage("");

        try {
            const response =
                await client.delete(
                    `/sessions/${sessionRecord.id}`
                );

            if (!response.ok) {
                setError(
                    response.error
                    || {
                        message:
                            "Unable to revoke session."
                    }
                );

                return;
            }

            if (
                sessionRecord.current
            ) {
                setSessions([]);

                window.location.reload();

                return;
            }

            setSessions(
                (currentSessions) =>
                    currentSessions.filter(
                        (item) =>
                            item.id
                            !== sessionRecord.id
                    )
            );

            setMessage(
                "Device signed out successfully."
            );

        } catch (
            requestError
        ) {
            console.error(
                "Session revocation failed:",
                requestError
            );

            setError({
                code:
                    "NETWORK_ERROR",

                message:
                    "Unable to revoke session."
            });

        } finally {
            setActionSessionId(
                null
            );
        }
    }


    async function revokeOthers() {
        if (revokingOthers) {
            return;
        }

        setRevokingOthers(true);

        setError(null);
        setMessage("");

        try {
            const response =
                await client.post(
                    "/sessions/revoke-others"
                );

            if (!response.ok) {
                setError(
                    response.error
                    || {
                        message:
                            "Unable to sign out other devices."
                    }
                );

                return;
            }

            setSessions(
                (currentSessions) =>
                    currentSessions.filter(
                        (item) =>
                            item.current
                    )
            );

            const count =
                response.data
                    ?.revoked_count
                ?? 0;

            setMessage(
                count === 1
                    ? "1 other device was signed out."
                    : `${count} other devices were signed out.`
            );

        } catch (
            requestError
        ) {
            console.error(
                "Other-session revocation failed:",
                requestError
            );

            setError({
                code:
                    "NETWORK_ERROR",

                message:
                    "Unable to sign out other devices."
            });

        } finally {
            setRevokingOthers(
                false
            );
        }
    }


    if (!authenticated) {
        return null;
    }


    const otherSessionCount =
        sessions.filter(
            (record) =>
                !record.current
        ).length;


    return (
        <section
            className="marks-auth-session-manager"
        >
            <div
                className="marks-auth-session-header"
            >
                <div>
                    <h3>
                        Your Devices
                    </h3>

                    <p>
                        Devices and browsers
                        currently signed in to
                        your account.
                    </p>
                </div>

                <button
                    type="button"
                    className="marks-auth-secondary"
                    onClick={
                        loadSessions
                    }
                    disabled={
                        loading
                    }
                >
                    {
                        loading
                            ? "Refreshing..."
                            : "Refresh"
                    }
                </button>
            </div>


            {
                error && (
                    <p
                        className="marks-auth-error"
                    >
                        {
                            error.message
                        }
                    </p>
                )
            }


            {
                message && (
                    <p
                        className="marks-auth-success"
                    >
                        {message}
                    </p>
                )
            }


            {
                loading
                && sessions.length === 0
                ? (
                    <div
                        className="marks-auth-session-empty"
                    >
                        Loading devices...
                    </div>
                )
                : null
            }


            {
                !loading
                && sessions.length === 0
                ? (
                    <div
                        className="marks-auth-session-empty"
                    >
                        No active sessions
                        were found.
                    </div>
                )
                : null
            }


            <div
                className="marks-auth-session-list"
            >
                {
                    sessions.map(
                        (
                            sessionRecord
                        ) => {
                            const browser =
                                describeBrowser(
                                    sessionRecord.user_agent
                                );

                            const device =
                                describeDevice(
                                    sessionRecord.user_agent
                                );

                            const isBusy =
                                actionSessionId
                                === sessionRecord.id;

                            return (
                                <article
                                    key={
                                        sessionRecord.id
                                    }
                                    className={
                                        [
                                            "marks-auth-session-card",

                                            sessionRecord.current
                                                ? "marks-auth-session-current"
                                                : ""
                                        ]
                                            .filter(Boolean)
                                            .join(" ")
                                    }
                                >
                                    <div
                                        className="marks-auth-session-icon"
                                        aria-hidden="true"
                                    >
                                        {
                                            device
                                            === "iPhone"
                                            || device
                                            === "Android"
                                                ? "▯"
                                                : "▰"
                                        }
                                    </div>


                                    <div
                                        className="marks-auth-session-content"
                                    >
                                        <div
                                            className="marks-auth-session-title"
                                        >
                                            <strong>
                                                {
                                                    `${browser} on ${device}`
                                                }
                                            </strong>

                                            {
                                                sessionRecord.current
                                                && (
                                                    <span
                                                        className="marks-auth-session-current-badge"
                                                    >
                                                        This device
                                                    </span>
                                                )
                                            }
                                        </div>


                                        <div
                                            className="marks-auth-session-meta"
                                        >
                                            <span>
                                                {
                                                    sessionRecord.ip_address
                                                    || "IP unavailable"
                                                }
                                            </span>

                                            <span>
                                                {
                                                    describeAuthentication(
                                                        sessionRecord
                                                            .authentication_method
                                                    )
                                                }
                                            </span>

                                            {
                                                sessionRecord.remembered
                                                && (
                                                    <span>
                                                        Remembered
                                                    </span>
                                                )
                                            }
                                        </div>


                                        <div
                                            className="marks-auth-session-times"
                                        >
                                            <span>
                                                Last active{" "}
                                                {
                                                    formatDate(
                                                        sessionRecord
                                                            .last_seen_at
                                                    )
                                                }
                                            </span>

                                            <span>
                                                Signed in{" "}
                                                {
                                                    formatDate(
                                                        sessionRecord
                                                            .created_at
                                                    )
                                                }
                                            </span>
                                        </div>
                                    </div>


                                    <button
                                        type="button"
                                        className="marks-auth-session-revoke"
                                        disabled={
                                            isBusy
                                        }
                                        onClick={() =>
                                            revokeSession(
                                                sessionRecord
                                            )
                                        }
                                    >
                                        {
                                            isBusy
                                                ? "Signing out..."
                                                : sessionRecord.current
                                                    ? "Sign Out"
                                                    : "Remove"
                                        }
                                    </button>
                                </article>
                            );
                        }
                    )
                }
            </div>


            {
                otherSessionCount > 0
                && (
                    <div
                        className="marks-auth-session-footer"
                    >
                        <button
                            type="button"
                            className="marks-auth-danger-button"
                            disabled={
                                revokingOthers
                            }
                            onClick={
                                revokeOthers
                            }
                        >
                            {
                                revokingOthers
                                    ? "Signing out..."
                                    : "Sign Out All Other Devices"
                            }
                        </button>

                        <p>
                            Your current device
                            will stay signed in.
                        </p>
                    </div>
                )
            }
        </section>
    );
}