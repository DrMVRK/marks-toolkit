import {
    useEffect,
    useRef,
    useState
} from "react";

import { useAuth } from "./AuthProvider";
import CaptchaChallenge from "./CaptchaChallenge";


const REMEMBERED_ACCOUNT_KEY =
    "marks_auth_remembered_account";


export default function LoginView({
    onRegister,
    onForgotPassword,
    onMFARequired
}) {
    const {
        client,
        config,
        ready,
        handleLogin
    } = useAuth();

    const [identity, setIdentity] =
        useState("");

    const [password, setPassword] =
        useState("");

    const [remember, setRemember] =
        useState(false);

    const [error, setError] =
        useState(null);

    const [loading, setLoading] =
        useState(false);

    const [
        passkeyLoading,
        setPasskeyLoading
    ] = useState(false);

    const [
        captchaRequired,
        setCaptchaRequired
    ] = useState(false);

    const [
        captchaToken,
        setCaptchaToken
    ] = useState(null);

    const [
        rememberedAccount,
        setRememberedAccount
    ] = useState(null);

    const [
        showPasswordLogin,
        setShowPasswordLogin
    ] = useState(false);

    const [
        conditionalAvailable,
        setConditionalAvailable
    ] = useState(false);

    const conditionalAbortControllerRef =
        useRef(null);

    const conditionalInProgressRef =
        useRef(false);

    const rememberRef =
        useRef(false);


    useEffect(() => {
        rememberRef.current =
            remember;
    }, [remember]);


    useEffect(() => {
        try {
            const stored =
                localStorage.getItem(
                    REMEMBERED_ACCOUNT_KEY
                );

            if (stored) {
                const parsed =
                    JSON.parse(stored);

                if (
                    parsed
                    && typeof parsed
                        === "object"
                ) {
                    const username =
                        typeof parsed.username
                        === "string"
                            ? parsed.username
                            : "";

                    const email =
                        typeof parsed.email
                        === "string"
                            ? parsed.email
                            : "";

                    if (
                        username
                        || email
                    ) {
                        setRememberedAccount({
                            username,
                            email
                        });

                        setRemember(true);

                    } else {
                        localStorage.removeItem(
                            REMEMBERED_ACCOUNT_KEY
                        );
                    }
                }
            }

        } catch (storageError) {
            console.warn(
                "Unable to read remembered account:",
                storageError
            );
        }


        async function detectConditionalUI() {
            try {
                if (
                    typeof window
                        .PublicKeyCredential
                    === "undefined"
                ) {
                    return;
                }

                if (
                    typeof PublicKeyCredential
                        .isConditionalMediationAvailable
                    !== "function"
                ) {
                    return;
                }

                const available =
                    await PublicKeyCredential
                        .isConditionalMediationAvailable();

                setConditionalAvailable(
                    available === true
                );

            } catch (detectionError) {
                console.warn(
                    "Unable to detect conditional passkey support:",
                    detectionError
                );
            }
        }

        detectConditionalUI();


        return () => {
            if (
                conditionalAbortControllerRef
                    .current
            ) {
                conditionalAbortControllerRef
                    .current
                    .abort();

                conditionalAbortControllerRef
                    .current = null;
            }

            conditionalInProgressRef
                .current = false;
        };
    }, []);


    async function handleSubmit(
        event
    ) {
        event.preventDefault();

        if (
            !ready
            || loading
            || passkeyLoading
        ) {
            return;
        }

        abortConditionalLogin();

        setLoading(true);
        setError(null);

        try {
            const response =
                await client.login({
                    identity,
                    password,
                    remember,
                    captchaToken
                });

            if (!response.ok) {
                if (
                    response.error?.code
                    === "CAPTCHA_REQUIRED"
                ) {
                    setCaptchaRequired(
                        true
                    );

                    setCaptchaToken(
                        null
                    );

                    setError(null);

                    return;
                }

                setError(
                    response.error
                );

                return;
            }

            if (
                response.data
                    ?.mfa_required
                && response.data
                    ?.challenge_id
            ) {
                onMFARequired({
                    challengeId:
                        response.data
                            .challenge_id,

                    methods:
                        response.data
                            .methods
                        || []
                });

                return;
            }

            handleLogin(
                response.data
            );

        } catch (requestError) {
            console.error(
                "Login request failed:",
                requestError
            );

            setError({
                code:
                    "NETWORK_ERROR",

                message:
                    "Unable to contact the authentication server."
            });

        } finally {
            setLoading(false);
        }
    }


    function abortConditionalLogin() {
        if (
            conditionalAbortControllerRef
                .current
        ) {
            conditionalAbortControllerRef
                .current
                .abort();

            conditionalAbortControllerRef
                .current = null;
        }

        conditionalInProgressRef
            .current = false;
    }


    function saveRememberedAccount(
        account
    ) {
        try {
            localStorage.setItem(
                REMEMBERED_ACCOUNT_KEY,
                JSON.stringify(
                    account
                )
            );

            setRememberedAccount(
                account
            );

        } catch (storageError) {
            console.warn(
                "Unable to remember account hint:",
                storageError
            );
        }
    }


    function clearRememberedAccount() {
        try {
            localStorage.removeItem(
                REMEMBERED_ACCOUNT_KEY
            );

        } catch (storageError) {
            console.warn(
                "Unable to clear remembered account:",
                storageError
            );
        }

        setRememberedAccount(
            null
        );

        setShowPasswordLogin(
            false
        );

        setIdentity("");
        setPassword("");
        setRemember(false);
        setError(null);
    }


    async function finishPasskeyAuthentication({
        challengeId,
        credential,
        shouldRemember
    }) {
        if (
            typeof credential
                .toJSON
            !== "function"
        ) {
            throw new Error(
                "Passkey response cannot be serialized."
            );
        }

        const serialized =
            credential.toJSON();

        const finishResponse =
            await client
                .finishPasskeyLogin({
                    challengeId,
                    credential:
                        serialized
                });

        if (!finishResponse.ok) {
            return {
                ok: false,
                error:
                    finishResponse.error
                    || {
                        message:
                            "Passkey authentication failed."
                    }
            };
        }

        if (shouldRemember) {
            saveRememberedAccount({
                username:
                    finishResponse
                        .data
                        .username,

                email:
                    finishResponse
                        .data
                        .email
            });

        } else {
            try {
                localStorage.removeItem(
                    REMEMBERED_ACCOUNT_KEY
                );

                setRememberedAccount(
                    null
                );

            } catch (storageError) {
                console.warn(
                    "Unable to clear account hint:",
                    storageError
                );
            }
        }

        handleLogin(
            finishResponse.data
        );

        return {
            ok: true
        };
    }


    async function handlePasskeyLogin() {
        if (
            !ready
            || loading
            || passkeyLoading
        ) {
            return;
        }

        /*
         * An explicit WebAuthn request should
         * replace any pending conditional
         * request. Browsers generally do not
         * want competing navigator.credentials
         * requests.
         */
        abortConditionalLogin();

        setPasskeyLoading(true);
        setError(null);

        try {
            if (
                typeof window
                    .PublicKeyCredential
                === "undefined"
                || typeof navigator
                    .credentials?.get
                    !== "function"
            ) {
                setError({
                    code:
                        "WEBAUTHN_UNAVAILABLE",

                    message:
                        "Passkeys are not supported by this browser."
                });

                return;
            }

            if (
                typeof PublicKeyCredential
                    .parseRequestOptionsFromJSON
                !== "function"
            ) {
                setError({
                    code:
                        "WEBAUTHN_UNAVAILABLE",

                    message:
                        "This browser does not support the required passkey login API."
                });

                return;
            }

            const beginResponse =
                await client
                    .beginPasskeyLogin();

            if (!beginResponse.ok) {
                setError(
                    beginResponse.error
                    || {
                        message:
                            "Unable to start passkey authentication."
                    }
                );

                return;
            }

            const {
                challenge_id:
                    challengeId,

                options
            } = beginResponse.data;

            const publicKey =
                PublicKeyCredential
                    .parseRequestOptionsFromJSON(
                        options
                    );

            const credential =
                await navigator
                    .credentials
                    .get({
                        publicKey
                    });

            if (!credential) {
                setError({
                    code:
                        "PASSKEY_CANCELLED",

                    message:
                        "Passkey authentication was cancelled."
                });

                return;
            }

            const result =
                await finishPasskeyAuthentication({
                    challengeId,
                    credential,
                    shouldRemember:
                        remember
                });

            if (!result.ok) {
                setError(
                    result.error
                );
            }

        } catch (requestError) {
            console.error(
                "Passkey login failed:",
                requestError
            );

            if (
                requestError?.name
                === "NotAllowedError"
            ) {
                setError({
                    code:
                        "PASSKEY_CANCELLED",

                    message:
                        "Passkey authentication was cancelled or timed out."
                });

                return;
            }

            if (
                requestError?.name
                === "AbortError"
            ) {
                return;
            }

            setError({
                code:
                    "PASSKEY_ERROR",

                message:
                    "Unable to sign in with a passkey."
            });

        } finally {
            setPasskeyLoading(
                false
            );
        }
    }


    async function startConditionalPasskeyLogin() {
        if (
            !ready
            || !passkeysAvailable
            || !conditionalAvailable
            || conditionalInProgressRef
                .current
            || loading
            || passkeyLoading
        ) {
            return;
        }

        if (
            typeof navigator
                .credentials?.get
            !== "function"
            || typeof PublicKeyCredential
                .parseRequestOptionsFromJSON
                !== "function"
        ) {
            return;
        }

        conditionalInProgressRef
            .current = true;

        const abortController =
            new AbortController();

        conditionalAbortControllerRef
            .current =
                abortController;

        try {
            const beginResponse =
                await client
                    .beginPasskeyLogin();

            if (!beginResponse.ok) {
                /*
                 * Conditional UI is optional.
                 * Do not interrupt normal
                 * password login if starting it
                 * fails.
                 */
                return;
            }

            const {
                challenge_id:
                    challengeId,

                options
            } = beginResponse.data;

            const publicKey =
                PublicKeyCredential
                    .parseRequestOptionsFromJSON(
                        options
                    );

            const credential =
                await navigator
                    .credentials
                    .get({
                        publicKey,

                        mediation:
                            "conditional",

                        signal:
                            abortController
                                .signal
                    });

            if (!credential) {
                return;
            }

            const result =
                await finishPasskeyAuthentication({
                    challengeId,
                    credential,

                    shouldRemember:
                        rememberRef.current
                });

            if (!result.ok) {
                setError(
                    result.error
                );
            }

        } catch (requestError) {
            /*
             * Cancellation is normal for
             * conditional mediation and should
             * not show an error to the user.
             */
            if (
                requestError?.name
                    === "AbortError"
                || requestError?.name
                    === "NotAllowedError"
            ) {
                return;
            }

            console.warn(
                "Conditional passkey login failed:",
                requestError
            );

        } finally {
            if (
                conditionalAbortControllerRef
                    .current
                === abortController
            ) {
                conditionalAbortControllerRef
                    .current = null;
            }

            conditionalInProgressRef
                .current = false;
        }
    }


    function useRememberedPassword() {
        abortConditionalLogin();

        const rememberedIdentity =
            rememberedAccount?.email
            || rememberedAccount?.username
            || "";

        setIdentity(
            rememberedIdentity
        );

        setPassword("");

        setRemember(true);

        setError(null);

        setShowPasswordLogin(
            true
        );
    }


    function useDifferentAccount() {
        abortConditionalLogin();

        setIdentity("");
        setPassword("");
        setRemember(false);
        setError(null);

        setCaptchaRequired(
            false
        );

        setCaptchaToken(
            null
        );

        setShowPasswordLogin(
            true
        );
    }


    const passkeysAvailable = (
        config?.passkeys_available
        === true
    );


    const rememberedName = (
        rememberedAccount?.username
        || rememberedAccount?.email
        || "there"
    );


    if (
        rememberedAccount
        && !showPasswordLogin
    ) {
        return (
            <div className="marks-auth-login">
                <h2>
                    Welcome back,{" "}
                    {rememberedName}
                </h2>

                {rememberedAccount.email && (
                    <p>
                        {
                            rememberedAccount
                                .email
                        }
                    </p>
                )}

                {error && (
                    <p className="marks-auth-error">
                        {
                            error.message
                            || "An authentication error occurred."
                        }
                    </p>
                )}

                {passkeysAvailable && (
                    <button
                        type="button"
                        className={
                            "marks-auth-primary-button"
                        }
                        onClick={
                            handlePasskeyLogin
                        }
                        disabled={
                            !ready
                            || loading
                            || passkeyLoading
                        }
                    >
                        {
                            passkeyLoading
                                ? "Waiting for passkey..."
                                : "Continue with passkey"
                        }
                    </button>
                )}

                <div className="marks-auth-actions">
                    <button
                        type="button"
                        className={
                            "marks-auth-secondary"
                        }
                        onClick={
                            useRememberedPassword
                        }
                        disabled={
                            loading
                            || passkeyLoading
                        }
                    >
                        Use password instead
                    </button>

                    <button
                        type="button"
                        className={
                            "marks-auth-secondary"
                        }
                        onClick={
                            useDifferentAccount
                        }
                        disabled={
                            loading
                            || passkeyLoading
                        }
                    >
                        Sign in with a different account
                    </button>

                    <button
                        type="button"
                        className={
                            "marks-auth-secondary"
                        }
                        onClick={
                            clearRememberedAccount
                        }
                        disabled={
                            loading
                            || passkeyLoading
                        }
                    >
                        Forget this account
                    </button>
                </div>
            </div>
        );
    }


    return (
        <form onSubmit={handleSubmit}>
            <h2>
                Sign In
            </h2>

            <input
                type="text"
                placeholder={
                    "Email or username"
                }
                value={identity}
                onChange={(event) =>
                    setIdentity(
                        event.target.value
                    )
                }
                onFocus={
                    startConditionalPasskeyLogin
                }
                autoComplete={
                    "username webauthn"
                }
            />

            <input
                type="password"
                placeholder="Password"
                value={password}
                onChange={(event) =>
                    setPassword(
                        event.target.value
                    )
                }
                autoComplete={
                    "current-password"
                }
            />

            <label>
                <input
                    type="checkbox"
                    checked={remember}
                    onChange={(event) =>
                        setRemember(
                            event.target
                                .checked
                        )
                    }
                />

                Remember me
            </label>

            {captchaRequired && (
                <CaptchaChallenge
                    siteKey={
                        config
                            ?.captcha_site_key
                    }

                    onSuccess={(
                        token
                    ) => {
                        setCaptchaToken(
                            token
                        );

                        setError(null);
                    }}

                    onExpired={() => {
                        setCaptchaToken(
                            null
                        );
                    }}

                    onError={() => {
                        setCaptchaToken(
                            null
                        );

                        setError({
                            code:
                                "CAPTCHA_ERROR",

                            message:
                                "The security check could not be completed."
                        });
                    }}
                />
            )}

            {error && (
                <p className="marks-auth-error">
                    {
                        error.message
                        || "An authentication error occurred."
                    }
                </p>
            )}

            <button
                type="submit"
                disabled={
                    !ready
                    || loading
                    || passkeyLoading
                    || (
                        captchaRequired
                        && !captchaToken
                    )
                }
            >
                {
                    loading
                        ? "Signing in..."
                        : "Sign In"
                }
            </button>

            {passkeysAvailable && (
                <>
                    <div className="marks-auth-divider">
                        <span>
                            or
                        </span>
                    </div>

                    <button
                        type="button"
                        className={
                            "marks-auth-secondary"
                        }
                        onClick={
                            handlePasskeyLogin
                        }
                        disabled={
                            !ready
                            || loading
                            || passkeyLoading
                        }
                    >
                        {
                            passkeyLoading
                                ? "Waiting for passkey..."
                                : "Sign in with a passkey"
                        }
                    </button>
                </>
            )}

            {rememberedAccount && (
                <div className="marks-auth-actions">
                    <button
                        type="button"
                        onClick={() => {
                            abortConditionalLogin();

                            setShowPasswordLogin(
                                false
                            );

                            setError(null);
                        }}
                    >
                        Back to remembered account
                    </button>
                </div>
            )}

            <div className="marks-auth-actions">
                <button
                    type="button"
                    onClick={
                        onForgotPassword
                    }
                >
                    Forgot password?
                </button>

                <button
                    type="button"
                    onClick={
                        onRegister
                    }
                >
                    Create account
                </button>
            </div>
        </form>
    );
}