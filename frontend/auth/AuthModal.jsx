import { useEffect, useState } from "react";
import { useAuth } from "./AuthProvider";

import LoginView from "./LoginView";
import RegisterView from "./RegisterView";
import ForgotPasswordView from "./ForgotPasswordView";
import ResetPasswordView from "./ResetPasswordView";


export default function AuthModal({
    open,
    onClose,
    initialView = "login",
    resetToken = null
}) {
    const [view, setView] = useState(initialView);
    const { authenticated } = useAuth();

    useEffect(() => {
        if (open) {
            setView(initialView);
        }
    }, [open, initialView]);

    useEffect(() => {
        if (authenticated && open && view === "login") {
            onClose();
        }
    }, [authenticated, open, view, onClose]);

    useEffect(() => {
        function handleKeyDown(event) {
            if (event.key === "Escape" && open) {
                onClose();
            }
        }

        document.addEventListener("keydown", handleKeyDown);

        return () => {
            document.removeEventListener(
                "keydown",
                handleKeyDown
            );
        };
    }, [open, onClose]);

    if (!open) {
        return null;
    }

    function handleOverlayClick(event) {
        if (event.target === event.currentTarget) {
            onClose();
        }
    }

    let content = null;

    if (view === "login") {
        content = (
            <LoginView
                onRegister={() => setView("register")}
                onForgotPassword={() =>
                    setView("forgot-password")
                }
            />
        );
    }

    if (view === "register") {
        content = (
            <RegisterView
                onLogin={() => setView("login")}
            />
        );
    }

    if (view === "forgot-password") {
        content = (
            <ForgotPasswordView
                onLogin={() => setView("login")}
            />
        );
    }

    if (view === "reset-password") {
        content = (
            <ResetPasswordView
                resetToken={resetToken}
                onLogin={() => setView("login")}
            />
        );
    }

    return (
        <div
            className="marks-auth-overlay"
            onClick={handleOverlayClick}
        >
            <div
                className="marks-auth-modal"
                role="dialog"
                aria-modal="true"
            >
                <button
                    type="button"
                    className="marks-auth-close"
                    onClick={onClose}
                    aria-label="Close authentication dialog"
                >
                    ×
                </button>

                {content}
            </div>
        </div>
    );
}