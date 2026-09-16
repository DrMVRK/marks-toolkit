import { useEffect, useRef } from "react";


export default function CaptchaChallenge({
    siteKey,
    onSuccess,
    onExpired,
    onError
}) {
    const containerRef = useRef(null);
    const widgetIdRef = useRef(null);

    const onSuccessRef = useRef(onSuccess);
    const onExpiredRef = useRef(onExpired);
    const onErrorRef = useRef(onError);


    useEffect(() => {
        onSuccessRef.current = onSuccess;
    }, [onSuccess]);


    useEffect(() => {
        onExpiredRef.current = onExpired;
    }, [onExpired]);


    useEffect(() => {
        onErrorRef.current = onError;
    }, [onError]);


    useEffect(() => {
        if (!siteKey) {
            return;
        }

        function renderTurnstile() {
            if (
                !window.turnstile ||
                !containerRef.current ||
                widgetIdRef.current !== null
            ) {
                return;
            }

            widgetIdRef.current =
                window.turnstile.render(
                    containerRef.current,
                    {
                        sitekey: siteKey,
                        theme: "auto",

                        callback(token) {
                            onSuccessRef.current?.(
                                token
                            );
                        },

                        "expired-callback"() {
                            onExpiredRef.current?.();

                            if (
                                widgetIdRef.current !==
                                null
                            ) {
                                window.turnstile.reset(
                                    widgetIdRef.current
                                );
                            }
                        },

                        "error-callback"() {
                            onErrorRef.current?.();
                        }
                    }
                );
        }


        if (window.turnstile) {
            renderTurnstile();

            return () => {
                if (
                    window.turnstile &&
                    widgetIdRef.current !== null
                ) {
                    window.turnstile.remove(
                        widgetIdRef.current
                    );
                }

                widgetIdRef.current = null;
            };
        }


        const existingScript =
            document.querySelector(
                'script[data-marks-turnstile="true"]'
            );

        if (existingScript) {
            existingScript.addEventListener(
                "load",
                renderTurnstile
            );

            return () => {
                existingScript.removeEventListener(
                    "load",
                    renderTurnstile
                );

                if (
                    window.turnstile &&
                    widgetIdRef.current !== null
                ) {
                    window.turnstile.remove(
                        widgetIdRef.current
                    );
                }

                widgetIdRef.current = null;
            };
        }


        const script =
            document.createElement("script");

        script.src =
            "https://challenges.cloudflare.com/" +
            "turnstile/v0/api.js?render=explicit";

        script.async = true;
        script.defer = true;

        script.dataset.marksTurnstile = "true";

        script.addEventListener(
            "load",
            renderTurnstile
        );

        document.head.appendChild(script);

        return () => {
            script.removeEventListener(
                "load",
                renderTurnstile
            );

            if (
                window.turnstile &&
                widgetIdRef.current !== null
            ) {
                window.turnstile.remove(
                    widgetIdRef.current
                );
            }

            widgetIdRef.current = null;
        };

    }, [siteKey]);


    if (!siteKey) {
        return (
            <p className="marks-auth-error">
                CAPTCHA is not configured.
            </p>
        );
    }


    return (
        <div
            className="marks-auth-captcha"
            ref={containerRef}
        />
    );
}