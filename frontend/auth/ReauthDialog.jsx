import {
    useEffect,
    useState
} from "react";


export default function ReauthDialog({
    open,
    title = "Confirm Your Password",
    message = "Enter your current password to continue.",
    confirmLabel = "Continue",
    loading = false,
    error = null,
    onConfirm,
    onCancel
}) {
    const [password, setPassword] =
        useState("");


    useEffect(() => {
        if (!open) {
            setPassword("");
        }
    }, [open]);


    if (!open) {
        return null;
    }


    function handleSubmit(event) {
        event.preventDefault();

        if (
            loading ||
            !password
        ) {
            return;
        }

        onConfirm(password);
    }


    function handleCancel() {
        if (loading) {
            return;
        }

        setPassword("");
        onCancel();
    }


    return (
        <div
            className="marks-auth-reauth-backdrop"
            role="presentation"
            onMouseDown={(event) => {
                if (
                    event.target ===
                    event.currentTarget
                ) {
                    handleCancel();
                }
            }}
        >
            <div
                className="marks-auth-reauth-dialog"
                role="dialog"
                aria-modal="true"
                aria-labelledby="marks-auth-reauth-title"
            >
                <form onSubmit={handleSubmit}>
                    <h3 id="marks-auth-reauth-title">
                        {title}
                    </h3>

                    <p>
                        {message}
                    </p>

                    <input
                        type="password"
                        autoComplete="current-password"
                        placeholder="Current password"
                        value={password}
                        autoFocus
                        onChange={(event) =>
                            setPassword(
                                event.target.value
                            )
                        }
                    />

                    {error && (
                        <p className="marks-auth-error">
                            {
                                error.message ||
                                "Password confirmation failed."
                            }
                        </p>
                    )}

                    <div className="marks-auth-reauth-actions">
                        <button
                            type="button"
                            onClick={handleCancel}
                            disabled={loading}
                        >
                            Cancel
                        </button>

                        <button
                            type="submit"
                            disabled={
                                loading ||
                                !password
                            }
                        >
                            {
                                loading
                                    ? "Confirming..."
                                    : confirmLabel
                            }
                        </button>
                    </div>
                </form>
            </div>
        </div>
    );
}