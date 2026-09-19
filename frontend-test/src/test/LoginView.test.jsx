import React from "react";

import {
    fireEvent,
    render,
    screen,
    waitFor
} from "@testing-library/react";

import userEvent from "@testing-library/user-event";

import {
    beforeEach,
    describe,
    expect,
    it,
    vi
} from "vitest";


const mockUseAuth = vi.fn();


vi.mock(
    "@marks-auth/AuthProvider.jsx",
    () => ({
        useAuth: () => mockUseAuth()
    })
);


vi.mock(
    "@marks-auth/CaptchaChallenge.jsx",
    () => ({
        default: () => (
            <div data-testid="captcha">
                CAPTCHA
            </div>
        )
    })
);


import LoginView from "@marks-auth/LoginView.jsx";


function makeAuthContext(
    overrides = {}
) {
    return {
        client: {
            login: vi.fn(),

            beginPasskeyLogin:
                vi.fn(),

            finishPasskeyLogin:
                vi.fn()
        },

        config: {
            captcha_site_key:
                "test-site-key",

            passkeys_available:
                true
        },

        ready: true,

        handleLogin:
            vi.fn(),

        ...overrides
    };
}


function renderLogin(
    authContext,
    props = {}
) {
    mockUseAuth.mockReturnValue(
        authContext
    );

    return render(
        <LoginView
            onRegister={
                vi.fn()
            }

            onForgotPassword={
                vi.fn()
            }

            onMFARequired={
                vi.fn()
            }

            {...props}
        />
    );
}


describe(
    "LoginView remembered account",
    () => {
        it(
            "shows remembered-account login when an account hint exists",
            async () => {
                localStorage.setItem(
                    "marks_auth_remembered_account",
                    JSON.stringify({
                        username: "Mark",
                        email:
                            "mark@example.com"
                    })
                );

                const authContext =
                    makeAuthContext();

                renderLogin(
                    authContext
                );

                expect(
                    await screen
                        .findByText(
                            /Welcome back, Mark/i
                        )
                ).toBeInTheDocument();

                expect(
                    screen.getByText(
                        "mark@example.com"
                    )
                ).toBeInTheDocument();

                expect(
                    screen.getByRole(
                        "button",
                        {
                            name:
                                /Continue with passkey/i
                        }
                    )
                ).toBeInTheDocument();

                expect(
                    screen.getByRole(
                        "button",
                        {
                            name:
                                /Use password instead/i
                        }
                    )
                ).toBeInTheDocument();

                expect(
                    screen.getByRole(
                        "button",
                        {
                            name:
                                /Sign in with a different account/i
                        }
                    )
                ).toBeInTheDocument();

                expect(
                    screen.getByRole(
                        "button",
                        {
                            name:
                                /Forget this account/i
                        }
                    )
                ).toBeInTheDocument();
            }
        );


        it(
            "forgets only the local account hint",
            async () => {
                const user =
                    userEvent.setup();

                localStorage.setItem(
                    "marks_auth_remembered_account",
                    JSON.stringify({
                        username: "Mark",
                        email:
                            "mark@example.com"
                    })
                );

                const authContext =
                    makeAuthContext();

                renderLogin(
                    authContext
                );

                const forgetButton =
                    await screen
                        .findByRole(
                            "button",
                            {
                                name:
                                    /Forget this account/i
                            }
                        );

                await user.click(
                    forgetButton
                );

                expect(
                    localStorage.getItem(
                        "marks_auth_remembered_account"
                    )
                ).toBeNull();

                expect(
                    screen.getByRole(
                        "heading",
                        {
                            name: /Sign In/i
                        }
                    )
                ).toBeInTheDocument();

                /*
                 * Forgetting the frontend
                 * account hint must not call
                 * any backend credential
                 * deletion operation.
                 */
                expect(
                    authContext.client
                        .beginPasskeyLogin
                ).not.toHaveBeenCalled();

                expect(
                    authContext.client
                        .finishPasskeyLogin
                ).not.toHaveBeenCalled();
            }
        );


        it(
            "prefills remembered identity when password login is selected",
            async () => {
                const user =
                    userEvent.setup();

                localStorage.setItem(
                    "marks_auth_remembered_account",
                    JSON.stringify({
                        username: "Mark",
                        email:
                            "mark@example.com"
                    })
                );

                renderLogin(
                    makeAuthContext()
                );

                await user.click(
                    await screen
                        .findByRole(
                            "button",
                            {
                                name:
                                    /Use password instead/i
                            }
                        )
                );

                const identityInput =
                    screen.getByPlaceholderText(
                        "Email or username"
                    );

                expect(
                    identityInput
                ).toHaveValue(
                    "mark@example.com"
                );

                expect(
                    screen.getByRole(
                        "checkbox",
                        {
                            name:
                                /Remember me/i
                        }
                    )
                ).toBeChecked();
            }
        );


        it(
            "opens a blank form for a different account without deleting the remembered hint",
            async () => {
                const user =
                    userEvent.setup();

                localStorage.setItem(
                    "marks_auth_remembered_account",
                    JSON.stringify({
                        username: "Mark",
                        email:
                            "mark@example.com"
                    })
                );

                renderLogin(
                    makeAuthContext()
                );

                await user.click(
                    await screen
                        .findByRole(
                            "button",
                            {
                                name:
                                    /Sign in with a different account/i
                            }
                        )
                );

                expect(
                    screen.getByPlaceholderText(
                        "Email or username"
                    )
                ).toHaveValue("");

                expect(
                    screen.getByRole(
                        "checkbox",
                        {
                            name:
                                /Remember me/i
                        }
                    )
                ).not.toBeChecked();

                expect(
                    localStorage.getItem(
                        "marks_auth_remembered_account"
                    )
                ).not.toBeNull();
            }
        );
    }
);


describe(
    "LoginView conditional passkeys",
    () => {
        beforeEach(() => {
            PublicKeyCredential
                .isConditionalMediationAvailable =
                vi.fn()
                    .mockResolvedValue(true);
        });


        it(
            "starts conditional WebAuthn when the identity field receives focus",
            async () => {
                const credential = {
                    toJSON:
                        vi.fn()
                            .mockReturnValue({
                                id:
                                    "credential-id",

                                rawId:
                                    "credential-id",

                                type:
                                    "public-key",

                                response: {
                                    authenticatorData:
                                        "auth-data",

                                    clientDataJSON:
                                        "client-data",

                                    signature:
                                        "signature",

                                    userHandle:
                                        "user-handle"
                                }
                            })
                };


                const credentialsGet =
                    vi.fn()
                        .mockResolvedValue(
                            credential
                        );


                Object.defineProperty(
                    navigator,
                    "credentials",
                    {
                        configurable: true,

                        value: {
                            get:
                                credentialsGet
                        }
                    }
                );


                const authContext =
                    makeAuthContext();


                authContext.client
                    .beginPasskeyLogin
                    .mockResolvedValue({
                        ok: true,

                        data: {
                            challenge_id:
                                "challenge-1",

                            options: {
                                challenge:
                                    "challenge",

                                rpId:
                                    "localhost",

                                timeout:
                                    300000,

                                userVerification:
                                    "required"
                            }
                        }
                    });


                authContext.client
                    .finishPasskeyLogin
                    .mockResolvedValue({
                        ok: true,

                        data: {
                            id: 1,
                            username:
                                "Mark",
                            email:
                                "mark@example.com"
                        }
                    });


                renderLogin(
                    authContext
                );


                /*
                 * Wait for the effect that
                 * checks conditional-mediation
                 * support to complete.
                 */
                await waitFor(
                    () => {
                        expect(
                            PublicKeyCredential
                                .isConditionalMediationAvailable
                        ).toHaveBeenCalled();
                    }
                );


                const identityInput =
                    screen.getByPlaceholderText(
                        "Email or username"
                    );


                fireEvent.focus(
                    identityInput
                );


                await waitFor(
                    () => {
                        expect(
                            authContext.client
                                .beginPasskeyLogin
                        ).toHaveBeenCalledTimes(
                            1
                        );
                    }
                );


                await waitFor(
                    () => {
                        expect(
                            credentialsGet
                        ).toHaveBeenCalled();
                    }
                );


                const webAuthnCall =
                    credentialsGet.mock
                        .calls[0][0];


                expect(
                    webAuthnCall.mediation
                ).toBe(
                    "conditional"
                );


                expect(
                    webAuthnCall.signal
                ).toBeInstanceOf(
                    AbortSignal
                );


                await waitFor(
                    () => {
                        expect(
                            authContext.client
                                .finishPasskeyLogin
                        ).toHaveBeenCalledWith({
                            challengeId:
                                "challenge-1",

                            credential: {
                                id:
                                    "credential-id",

                                rawId:
                                    "credential-id",

                                type:
                                    "public-key",

                                response: {
                                    authenticatorData:
                                        "auth-data",

                                    clientDataJSON:
                                        "client-data",

                                    signature:
                                        "signature",

                                    userHandle:
                                        "user-handle"
                                }
                            }
                        });
                    }
                );


                await waitFor(
                    () => {
                        expect(
                            authContext
                                .handleLogin
                        ).toHaveBeenCalledWith({
                            id: 1,
                            username:
                                "Mark",
                            email:
                                "mark@example.com"
                        });
                    }
                );
            }
        );


        it(
            "does not display an error when conditional authentication is cancelled",
            async () => {
                const abortError =
                    new DOMException(
                        "Authentication cancelled",
                        "AbortError"
                    );


                const credentialsGet =
                    vi.fn()
                        .mockRejectedValue(
                            abortError
                        );


                Object.defineProperty(
                    navigator,
                    "credentials",
                    {
                        configurable: true,

                        value: {
                            get:
                                credentialsGet
                        }
                    }
                );


                const authContext =
                    makeAuthContext();


                authContext.client
                    .beginPasskeyLogin
                    .mockResolvedValue({
                        ok: true,

                        data: {
                            challenge_id:
                                "challenge-2",

                            options: {
                                challenge:
                                    "challenge"
                            }
                        }
                    });


                renderLogin(
                    authContext
                );


                await waitFor(
                    () => {
                        expect(
                            PublicKeyCredential
                                .isConditionalMediationAvailable
                        ).toHaveBeenCalled();
                    }
                );


                fireEvent.focus(
                    screen.getByPlaceholderText(
                        "Email or username"
                    )
                );


                await waitFor(
                    () => {
                        expect(
                            credentialsGet
                        ).toHaveBeenCalled();
                    }
                );


                expect(
                    screen.queryByText(
                        /Unable to sign in with a passkey/i
                    )
                ).not.toBeInTheDocument();


                expect(
                    authContext
                        .handleLogin
                ).not.toHaveBeenCalled();
            }
        );
    }
);


describe(
    "LoginView explicit passkey authentication",
    () => {
        it(
            "authenticates with the explicit passkey button",
            async () => {
                const user =
                    userEvent.setup();


                const credential = {
                    toJSON:
                        vi.fn()
                            .mockReturnValue({
                                id:
                                    "explicit-passkey",

                                rawId:
                                    "explicit-passkey",

                                type:
                                    "public-key",

                                response: {
                                    authenticatorData:
                                        "auth-data",

                                    clientDataJSON:
                                        "client-data",

                                    signature:
                                        "signature",

                                    userHandle:
                                        "user-handle"
                                }
                            })
                };


                const credentialsGet =
                    vi.fn()
                        .mockResolvedValue(
                            credential
                        );


                Object.defineProperty(
                    navigator,
                    "credentials",
                    {
                        configurable: true,

                        value: {
                            get:
                                credentialsGet
                        }
                    }
                );


                const authContext =
                    makeAuthContext();


                authContext.client
                    .beginPasskeyLogin
                    .mockResolvedValue({
                        ok: true,

                        data: {
                            challenge_id:
                                "explicit-challenge",

                            options: {
                                challenge:
                                    "challenge",

                                rpId:
                                    "localhost"
                            }
                        }
                    });


                authContext.client
                    .finishPasskeyLogin
                    .mockResolvedValue({
                        ok: true,

                        data: {
                            id: 1,
                            username:
                                "Mark",
                            email:
                                "mark@example.com"
                        }
                    });


                renderLogin(
                    authContext
                );


                await user.click(
                    screen.getByRole(
                        "button",
                        {
                            name:
                                /Sign in with a passkey/i
                        }
                    )
                );


                await waitFor(
                    () => {
                        expect(
                            credentialsGet
                        ).toHaveBeenCalledWith({
                            publicKey: {
                                challenge:
                                    "challenge",

                                rpId:
                                    "localhost"
                            }
                        });
                    }
                );


                await waitFor(
                    () => {
                        expect(
                            authContext
                                .handleLogin
                        ).toHaveBeenCalled();
                    }
                );
            }
        );
    }
);