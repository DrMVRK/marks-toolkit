import { useEffect, useState } from "react";

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

    useEffect(() => {
        if (open) {
            setView(initialView);
        }
    }, [open, initialView]);

    if (!open) {
        return null;
    }

    let content = null;

    if (view === "login") {
        content = (
            <LoginView
                onRegister={() => setView("register")}
                onForgotPassword={() => setView("forgot-password")}
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
        <div className="marks-auth-overlay">
            <div className="marks-auth-modal">
                <button
                    type="button"
                    className="marks-auth-close"
                    onClick={onClose}
                >
                    ×
                </button>

                {content}
            </div>
        </div>
    );
}