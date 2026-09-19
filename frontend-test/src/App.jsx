import { useEffect, useMemo, useState } from "react";

import AuthModal from "@marks-auth/AuthModal";
import { useAuth } from "@marks-auth/AuthProvider";
import MFASettings from "@marks-auth/MFASettings";

import DemoHeader from "./components/DemoHeader";
import SecurityBadge from "./components/SecurityBadge";
import UserDashboard from "./components/UserDashboard";
import SessionManager
    from "@marks-auth/SessionManager.jsx";

import "@marks-auth/auth.css";
import "./demo.css";


const SECURITY_BADGES = [
    {
        label: "CSRF protected",
        detail: "State-changing auth requests use CSRF protection.",
    },
    {
        label: "MFA ready",
        detail: "TOTP and single-use recovery codes are supported.",
    },
    {
        label: "Argon2 passwords",
        detail: "Passwords are protected with Argon2 hashing.",
    },
    {
        label: "Session revocation",
        detail: "Authentication IDs can invalidate old sessions.",
    },
];


function getResetToken() {
    const params = new URLSearchParams(window.location.search);

    return (
        params.get("token") ||
        params.get("reset_token") ||
        ""
    );
}


export default function App() {
    const {
        ready,
        user,
        authenticated,
        logout,
    } = useAuth();

    const [authOpen, setAuthOpen] = useState(false);
    const [authView, setAuthView] = useState("login");
    const [activePanel, setActivePanel] = useState("overview");
    const [theme, setTheme] = useState(() => {
        return (
            window.localStorage.getItem(
                "marks-demo-theme"
            ) || "dark"
        );
    });

    const resetToken = useMemo(
        () => getResetToken(),
        []
    );

    useEffect(() => {
        document.documentElement.dataset.theme =
            theme;

        window.localStorage.setItem(
            "marks-demo-theme",
            theme
        );
    }, [theme]);

    useEffect(() => {
        if (resetToken && !authenticated) {
            setAuthView("reset-password");
            setAuthOpen(true);
        }
    }, [resetToken, authenticated]);

    useEffect(() => {
        if (!authenticated) {
            setActivePanel("overview");
        }
    }, [authenticated]);

    function openAuth(view = "login") {
        setAuthView(view);
        setAuthOpen(true);
    }

    async function handleLogout() {
        await logout();
        setActivePanel("overview");
    }

    if (!ready) {
        return (
            <div className="demo-loading-screen">
                <div className="demo-loader" />
                <p>Initializing MARKS Auth…</p>
            </div>
        );
    }

    return (
        <div className="demo-app">
            <div className="demo-background-glow demo-background-glow--one" />
            <div className="demo-background-glow demo-background-glow--two" />

            <DemoHeader
                authenticated={authenticated}
                user={user}
                theme={theme}
                onThemeToggle={() =>
                    setTheme((current) =>
                        current === "dark"
                            ? "light"
                            : "dark"
                    )
                }
                onLogin={() => openAuth("login")}
                onRegister={() =>
                    openAuth("register")
                }
                onLogout={handleLogout}
            />

            <main className="demo-main">
                {!authenticated ? (
                    <>
                        <section className="demo-hero demo-hero--single">
                            <div className="demo-hero-copy">
                                <div className="demo-eyebrow">
                                    MARKS AUTH DEMO
                                </div>

                                <h1>
                                    Authentication infrastructure,
                                    <span> presented like a product.</span>
                                </h1>

                                <p className="demo-hero-lead">
                                    A live development showcase for the MARKS Toolkit
                                    Flask + React authentication stack. Exercise
                                    registration, password recovery, adaptive CAPTCHA,
                                    MFA, session handling, and account security from
                                    one polished interface.
                                </p>

                                <div className="demo-hero-actions">
                                    <button
                                        type="button"
                                        className="demo-button demo-button--primary"
                                        onClick={() => openAuth("login")}
                                    >
                                        Open sign-in modal
                                    </button>

                                    <button
                                        type="button"
                                        className="demo-button demo-button--secondary"
                                        onClick={() => openAuth("register")}
                                    >
                                        Open registration
                                    </button>
                                </div>

                                <div className="demo-badge-row">
                                    {SECURITY_BADGES.map((badge) => (
                                        <SecurityBadge
                                            key={badge.label}
                                            {...badge}
                                        />
                                    ))}
                                </div>
                            </div>
                        </section>

                        <section className="demo-capabilities">
                            <div className="demo-section-heading">
                                <span className="demo-eyebrow">
                                    SECURITY LAYERS
                                </span>
                                <h2>
                                    Built to demonstrate the real
                                    toolkit behavior.
                                </h2>
                                <p>
                                    The test harness is presentation
                                    only. Authentication decisions
                                    remain on the Flask backend.
                                </p>
                            </div>

                            <div className="demo-capability-grid">
                                <article className="demo-capability-card">
                                    <span className="demo-card-number">
                                        01
                                    </span>
                                    <h3>
                                        Credential security
                                    </h3>
                                    <p>
                                        Argon2 hashing, dummy
                                        verification, typed input
                                        validation, reset-token
                                        handling, and authentication
                                        state rotation.
                                    </p>
                                </article>

                                <article className="demo-capability-card">
                                    <span className="demo-card-number">
                                        02
                                    </span>
                                    <h3>
                                        Multi-factor authentication
                                    </h3>
                                    <p>
                                        TOTP enrollment, QR setup,
                                        replay prevention, recovery
                                        codes, password reauth, and
                                        distributed challenge
                                        storage.
                                    </p>
                                </article>

                                <article className="demo-capability-card">
                                    <span className="demo-card-number">
                                        03
                                    </span>
                                    <h3>
                                        Abuse resistance
                                    </h3>
                                    <p>
                                        Adaptive CAPTCHA, risk
                                        tracking, atomic throttling,
                                        Redis-backed shared state,
                                        and security event auditing.
                                    </p>
                                </article>
                            </div>
                        </section>
                    </>
                ) : (
                    <section className="demo-authenticated-layout">
                        <aside className="demo-sidebar">
                            <div className="demo-sidebar-account">
                                <div className="demo-avatar">
                                    {(
                                        user?.username ||
                                        user?.email ||
                                        "U"
                                    )
                                        .charAt(0)
                                        .toUpperCase()}
                                </div>

                                <div>
                                    <strong>
                                        {user?.username ||
                                            "Signed-in user"}
                                    </strong>
                                    <span>
                                        {user?.email ||
                                            "Authenticated"}
                                    </span>
                                </div>
                            </div>

                            <nav
                                className="demo-sidebar-nav"
                                aria-label="Demo account navigation"
                            >
                                <button
                                    type="button"
                                    className={
                                        activePanel ===
                                        "overview"
                                            ? "active"
                                            : ""
                                    }
                                    onClick={() =>
                                        setActivePanel(
                                            "overview"
                                        )
                                    }
                                >
                                    Overview
                                </button>

                                <button
                                    type="button"
                                    className={
                                        activePanel ===
                                        "security"
                                            ? "active"
                                            : ""
                                    }
                                    onClick={() =>
                                        setActivePanel(
                                            "security"
                                        )
                                    }
                                >
                                    Security & MFA
                                </button>

                                <button
                                    type="button"
                                    className={
                                        activePanel ===
                                        "about"
                                            ? "active"
                                            : ""
                                    }
                                    onClick={() =>
                                        setActivePanel(
                                            "about"
                                        )
                                    }
                                >
                                    Demo details
                                </button>
                            </nav>

                            <div className="demo-sidebar-note">
                                <strong>
                                    Development demo
                                </strong>
                                <p>
                                    In-memory state may reset when
                                    the backend restarts.
                                </p>
                            </div>
                        </aside>

                        <div className="demo-content-panel">
                            {activePanel ===
                                "overview" && (
                                <UserDashboard
                                    user={user}
                                    onManageSecurity={() =>
                                        setActivePanel(
                                            "security"
                                        )
                                    }
                                />
                            )}

                            {activePanel ===
                                "security" && (
                                <div className="demo-panel-stack">
                                    <div className="demo-panel-heading">
                                        <span className="demo-eyebrow">
                                            ACCOUNT SECURITY
                                        </span>
                                        <h1>
                                            Multi-factor
                                            authentication
                                        </h1>
                                        <p>
                                            Manage TOTP and recovery
                                            codes through the actual
                                            reusable MARKS Toolkit
                                            component.
                                        </p>
                                    </div>

                                    <div className="demo-embedded-auth">
                                        <MFASettings />
                                        <SessionManager />
                                    </div>
                                </div>
                            )}

                            {activePanel === "about" && (
                                <div className="demo-panel-stack">
                                    <div className="demo-panel-heading">
                                        <span className="demo-eyebrow">
                                            ABOUT THIS HARNESS
                                        </span>
                                        <h1>
                                            A polished wrapper around
                                            the reusable auth stack.
                                        </h1>
                                        <p>
                                            This shell deliberately
                                            keeps demo presentation
                                            separate from the reusable
                                            authentication components.
                                        </p>
                                    </div>

                                    <div className="demo-info-grid">
                                        <article>
                                            <span>Backend</span>
                                            <strong>
                                                Flask / AuthKit
                                            </strong>
                                        </article>
                                        <article>
                                            <span>Frontend</span>
                                            <strong>
                                                React / Vite
                                            </strong>
                                        </article>
                                        <article>
                                            <span>Test suite</span>
                                            <strong>
                                                139 passing
                                            </strong>
                                        </article>
                                        <article>
                                            <span>Release</span>
                                            <strong>
                                                v0.1.0 demo
                                            </strong>
                                        </article>
                                    </div>

                                    <div className="demo-warning-card">
                                        <strong>
                                            Development use only
                                        </strong>
                                        <p>
                                            This harness may use
                                            localhost HTTP,
                                            development keys,
                                            in-memory stores,
                                            Turnstile test
                                            credentials, and the
                                            console mailer. Those are
                                            explicit development
                                            exceptions, not
                                            production defaults.
                                        </p>
                                    </div>
                                </div>
                            )}
                        </div>
                    </section>
                )}
            </main>

            <footer className="demo-footer">
                <div>
                    <strong>MARKS Toolkit</strong>
                    <span>
                        Authentication & application security
                    </span>
                </div>

                <p>
                    Development demonstration interface — not a
                    production deployment.
                </p>
            </footer>

            <AuthModal
                open={authOpen}
                onClose={() => setAuthOpen(false)}
                initialView={authView}
                resetToken={resetToken}
            />
        </div>
    );
}
