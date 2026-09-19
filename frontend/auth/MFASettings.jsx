import { useEffect, useState } from "react";
import { QRCodeSVG } from "qrcode.react";

import { useAuth } from "./AuthProvider";
import ReauthDialog from "./ReauthDialog";
import PasskeyManager from "./PasskeyManager";


export default function MFASettings() {
    const {
        client,
        authenticated
    } = useAuth();

    const [status, setStatus] =
        useState(null);

    const [loadingStatus, setLoadingStatus] =
        useState(false);

    const [setupSecret, setSetupSecret] =
        useState("");

    const [provisioningUri, setProvisioningUri] =
        useState("");

    const [verificationCode, setVerificationCode] =
        useState("");

    const [recoveryCodes, setRecoveryCodes] =
        useState([]);

    const [message, setMessage] =
        useState("");

    const [error, setError] =
        useState(null);

    const [reauthAction, setReauthAction] =
        useState(null);

    const [reauthError, setReauthError] =
        useState(null);

    const [reauthLoading, setReauthLoading] =
        useState(false);


    useEffect(() => {
        if (authenticated) {
            refreshStatus();
        } else {
            setStatus(null);
            setSetupSecret("");
            setProvisioningUri("");
            setVerificationCode("");
            setRecoveryCodes([]);
            setMessage("");
            setError(null);
            setReauthAction(null);
            setReauthError(null);
        }
    }, [authenticated]);


    async function refreshStatus() {
        setLoadingStatus(true);
        setError(null);

        try {
            const response = await client.get(
                "/mfa/status"
            );

            if (!response.ok) {
                setError(
                    response.error || {
                        message:
                            "Unable to load MFA status."
                    }
                );

                return;
            }

            setStatus(response.data);

        } catch (requestError) {
            console.error(
                "MFA status request failed:",
                requestError
            );

            setError({
                code: "NETWORK_ERROR",
                message:
                    "Unable to load MFA status."
            });

        } finally {
            setLoadingStatus(false);
        }
    }


    async function beginTotpEnrollment(
        currentPassword
    ) {
        setReauthLoading(true);
        setReauthError(null);

        setError(null);
        setMessage("");
        setRecoveryCodes([]);
        setVerificationCode("");
        setSetupSecret("");
        setProvisioningUri("");

        try {
            const response = await client.post(
                "/mfa/totp/enroll",
                {
                    current_password:
                        currentPassword
                }
            );

            if (!response.ok) {
                setReauthError(
                    response.error
                );

                return;
            }

            setSetupSecret(
                response.data.secret || ""
            );

            setProvisioningUri(
                response.data.provisioning_uri
                || ""
            );

            setMessage(
                "Scan the QR code with your authenticator app, then enter the current 6-digit code."
            );

            setReauthAction(null);

        } catch (requestError) {
            console.error(
                "TOTP enrollment request failed:",
                requestError
            );

            setReauthError({
                code: "NETWORK_ERROR",
                message:
                    "Unable to start TOTP enrollment."
            });

        } finally {
            setReauthLoading(false);
        }
    }


    async function verifyTotpEnrollment() {
        setError(null);
        setMessage("");

        try {
            const response = await client.post(
                "/mfa/totp/verify-enrollment",
                {
                    code:
                        verificationCode.trim()
                }
            );

            if (!response.ok) {
                setError(response.error);
                return;
            }

            setSetupSecret("");
            setProvisioningUri("");
            setVerificationCode("");

            setMessage(
                "Authenticator MFA enabled successfully."
            );

            await refreshStatus();

        } catch (requestError) {
            console.error(
                "TOTP verification request failed:",
                requestError
            );

            setError({
                code: "NETWORK_ERROR",
                message:
                    "Unable to verify the authenticator code."
            });
        }
    }


    async function generateRecoveryCodes(
        currentPassword
    ) {
        setReauthLoading(true);
        setReauthError(null);

        setError(null);
        setMessage("");
        setRecoveryCodes([]);

        try {
            const response = await client.post(
                "/mfa/recovery-codes/generate",
                {
                    current_password:
                        currentPassword
                }
            );

            if (!response.ok) {
                setReauthError(
                    response.error
                );

                return;
            }

            setRecoveryCodes(
                response.data.codes || []
            );

            setMessage(
                "New recovery codes generated. Save them now. They will not be shown again."
            );

            setReauthAction(null);

            await refreshStatus();

        } catch (requestError) {
            console.error(
                "Recovery-code generation failed:",
                requestError
            );

            setReauthError({
                code: "NETWORK_ERROR",
                message:
                    "Unable to generate recovery codes."
            });

        } finally {
            setReauthLoading(false);
        }
    }


    async function disableTotp(
        currentPassword
    ) {
        setReauthLoading(true);
        setReauthError(null);

        setError(null);
        setMessage("");

        try {
            const response = await client.post(
                "/mfa/totp/disable",
                {
                    current_password:
                        currentPassword
                }
            );

            if (!response.ok) {
                setReauthError(
                    response.error
                );

                return;
            }

            setSetupSecret("");
            setProvisioningUri("");
            setVerificationCode("");

            setMessage(
                "Authenticator MFA disabled successfully."
            );

            setReauthAction(null);

            await refreshStatus();

        } catch (requestError) {
            console.error(
                "TOTP disable request failed:",
                requestError
            );

            setReauthError({
                code: "NETWORK_ERROR",
                message:
                    "Unable to disable authenticator MFA."
            });

        } finally {
            setReauthLoading(false);
        }
    }


    if (!authenticated) {
        return null;
    }


    return (
        <section className="marks-auth-mfa-settings">
            <h2>
                Multi-Factor Authentication
            </h2>

            {loadingStatus && (
                <p>
                    Loading MFA status...
                </p>
            )}

            {status && (
                <div className="marks-auth-mfa-status">
                    <p>
                        MFA enabled:{" "}
                        <strong>
                            {
                                status.mfa_enabled
                                    ? "Yes"
                                    : "No"
                            }
                        </strong>
                    </p>

                    <p>
                        Authenticator enabled:{" "}
                        <strong>
                            {
                                status.totp_enabled
                                    ? "Yes"
                                    : "No"
                            }
                        </strong>
                    </p>

                    <p>
                        Passkeys:{" "}
                        <strong>
                            {
                                status.passkey_count
                                ?? 0
                            }
                        </strong>
                    </p>
                </div>
            )}

            {error && (
                <p className="marks-auth-error">
                    {
                        error.message
                        || "An authentication error occurred."
                    }
                </p>
            )}

            {message && (
                <p className="marks-auth-success">
                    {message}
                </p>
            )}

            {!status?.totp_enabled && (
                <div className="marks-auth-mfa-section">
                    <h3>
                        Authenticator App
                    </h3>

                    {!setupSecret && (
                        <button
                            type="button"
                            onClick={() => {
                                setReauthError(null);
                                setReauthAction(
                                    "setup-totp"
                                );
                            }}
                        >
                            Set Up Authenticator
                        </button>
                    )}

                    {setupSecret && (
                        <>
                            <p>
                                Scan this QR code with
                                Google Authenticator,
                                Microsoft Authenticator,
                                1Password, or another
                                compatible authenticator
                                app.
                            </p>

                            {provisioningUri && (
                                <div className="marks-auth-mfa-qr">
                                    <QRCodeSVG
                                        value={
                                            provisioningUri
                                        }
                                        size={220}
                                        level="M"
                                        marginSize={4}
                                    />
                                </div>
                            )}

                            <p>
                                If you cannot scan the QR
                                code, enter this setup key
                                manually:
                            </p>

                            <code className="marks-auth-mfa-secret">
                                {setupSecret}
                            </code>

                            <div className="marks-auth-mfa-verify">
                                <input
                                    type="text"
                                    inputMode="numeric"
                                    autoComplete="one-time-code"
                                    placeholder="6-digit code"
                                    maxLength={6}
                                    value={
                                        verificationCode
                                    }
                                    onChange={(event) => {
                                        const value =
                                            event.target.value
                                                .replace(
                                                    /\D/g,
                                                    ""
                                                )
                                                .slice(
                                                    0,
                                                    6
                                                );

                                        setVerificationCode(
                                            value
                                        );
                                    }}
                                />

                                <button
                                    type="button"
                                    onClick={
                                        verifyTotpEnrollment
                                    }
                                    disabled={
                                        verificationCode
                                            .length !== 6
                                    }
                                >
                                    Verify Authenticator
                                </button>
                            </div>
                        </>
                    )}
                </div>
            )}

            {status?.totp_enabled && (
                <div className="marks-auth-mfa-section">
                    <h3>
                        Authenticator App
                    </h3>

                    <p>
                        An authenticator application is
                        currently enabled on this account.
                    </p>

                    <button
                        type="button"
                        onClick={() => {
                            setReauthError(null);

                            setReauthAction(
                                "disable-totp"
                            );
                        }}
                    >
                        Disable Authenticator
                    </button>
                </div>
            )}

            {status?.passkeys_available && (
                <PasskeyManager
                    onChanged={
                        refreshStatus
                    }
                />
            )}

            {status?.mfa_enabled && (
                <div className="marks-auth-mfa-section">
                    <h3>
                        Recovery Codes
                    </h3>

                    <p>
                        Recovery codes can be used if you
                        lose access to your normal MFA
                        method.
                    </p>

                    <button
                        type="button"
                        onClick={() => {
                            setReauthError(null);

                            setReauthAction(
                                "generate-recovery-codes"
                            );
                        }}
                    >
                        Generate New Recovery Codes
                    </button>

                    {recoveryCodes.length > 0 && (
                        <div className="marks-auth-recovery-codes">
                            <p>
                                Save these somewhere safe.
                                Each code can only be used
                                once.
                            </p>

                            <ul>
                                {recoveryCodes.map(
                                    (recoveryCode) => (
                                        <li
                                            key={
                                                recoveryCode
                                            }
                                        >
                                            <code>
                                                {
                                                    recoveryCode
                                                }
                                            </code>
                                        </li>
                                    )
                                )}
                            </ul>
                        </div>
                    )}
                </div>
            )}

            <button
                type="button"
                className="marks-auth-secondary"
                onClick={refreshStatus}
            >
                Refresh Status
            </button>

            <ReauthDialog
                open={reauthAction !== null}

                title={
                    reauthAction === "setup-totp"
                        ? "Set Up Authenticator"
                        : reauthAction === "disable-totp"
                            ? "Disable Authenticator"
                            : "Generate Recovery Codes"
                }

                message={
                    reauthAction === "setup-totp"
                        ? "Enter your current password to set up authenticator MFA."
                        : reauthAction === "disable-totp"
                            ? "Enter your current password to disable authenticator MFA."
                            : "Enter your current password to generate a new set of recovery codes."
                }

                confirmLabel={
                    reauthAction === "setup-totp"
                        ? "Continue Setup"
                        : reauthAction === "disable-totp"
                            ? "Disable Authenticator"
                            : "Generate Codes"
                }

                loading={reauthLoading}

                error={reauthError}

                onConfirm={(password) => {
                    if (
                        reauthAction ===
                        "setup-totp"
                    ) {
                        beginTotpEnrollment(
                            password
                        );

                        return;
                    }

                    if (
                        reauthAction ===
                        "disable-totp"
                    ) {
                        disableTotp(
                            password
                        );

                        return;
                    }

                    if (
                        reauthAction ===
                        "generate-recovery-codes"
                    ) {
                        generateRecoveryCodes(
                            password
                        );
                    }
                }}

                onCancel={() => {
                    setReauthAction(null);
                    setReauthError(null);
                }}
            />
        </section>
    );
}