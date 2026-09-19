import {
    fireEvent,
    render,
    screen,
    waitFor
} from "@testing-library/react";

import {
    beforeEach,
    describe,
    expect,
    it,
    vi
} from "vitest";

import SessionManager
    from "@marks-auth/SessionManager.jsx";

import {
    useAuth
} from "@marks-auth/AuthProvider.jsx";


vi.mock(
    "@marks-auth/AuthProvider.jsx",
    () => ({
        useAuth: vi.fn()
    })
);


describe(
    "SessionManager",
    () => {
        let client;

        beforeEach(() => {
            client = {
                get: vi.fn(),
                post: vi.fn(),
                delete: vi.fn()
            };

            useAuth.mockReturnValue({
                client,
                authenticated: true
            });
        });


        it(
            "shows active sessions",
            async () => {
                client.get.mockResolvedValue({
                    ok: true,

                    data: {
                        sessions: [
                            {
                                id: "current-id",
                                current: true,
                                created_at:
                                    "2026-09-19T10:00:00Z",
                                last_seen_at:
                                    "2026-09-19T11:00:00Z",
                                ip_address:
                                    "127.0.0.1",
                                user_agent:
                                    "Mozilla/5.0 Windows Chrome/120",
                                authentication_method:
                                    "password",
                                remembered: false
                            }
                        ]
                    }
                });

                render(
                    <SessionManager />
                );

                expect(
                    await screen.findByText(
                        "This device"
                    )
                ).toBeInTheDocument();

                expect(
                    screen.getByText(
                        "Google Chrome on Windows"
                    )
                ).toBeInTheDocument();

                expect(
                    screen.getByText(
                        "Password"
                    )
                ).toBeInTheDocument();
            }
        );


        it(
            "revokes another session",
            async () => {
                client.get.mockResolvedValue({
                    ok: true,

                    data: {
                        sessions: [
                            {
                                id: "current-id",
                                current: true,
                                created_at: null,
                                last_seen_at: null,
                                ip_address:
                                    "127.0.0.1",
                                user_agent:
                                    "Windows Chrome/",
                                authentication_method:
                                    "password",
                                remembered: false
                            },

                            {
                                id: "other-id",
                                current: false,
                                created_at: null,
                                last_seen_at: null,
                                ip_address:
                                    "10.0.0.2",
                                user_agent:
                                    "Macintosh Safari/",
                                authentication_method:
                                    "passkey",
                                remembered: false
                            }
                        ]
                    }
                });

                client.delete
                    .mockResolvedValue({
                        ok: true
                    });

                render(
                    <SessionManager />
                );

                const removeButton =
                    await screen.findByRole(
                        "button",
                        {
                            name:
                                "Remove"
                        }
                    );

                fireEvent.click(
                    removeButton
                );

                await waitFor(() => {
                    expect(
                        client.delete
                    ).toHaveBeenCalledWith(
                        "/sessions/other-id"
                    );
                });

                await waitFor(() => {
                    expect(
                        screen.queryByText(
                            "Safari on Mac"
                        )
                    ).not
                        .toBeInTheDocument();
                });
            }
        );


        it(
            "revokes all other sessions",
            async () => {
                client.get.mockResolvedValue({
                    ok: true,

                    data: {
                        sessions: [
                            {
                                id: "current",
                                current: true,
                                created_at: null,
                                last_seen_at: null,
                                ip_address: null,
                                user_agent:
                                    "Windows Chrome/",
                                authentication_method:
                                    "password",
                                remembered: false
                            },

                            {
                                id: "other",
                                current: false,
                                created_at: null,
                                last_seen_at: null,
                                ip_address: null,
                                user_agent:
                                    "Macintosh Safari/",
                                authentication_method:
                                    "password",
                                remembered: true
                            }
                        ]
                    }
                });

                client.post
                    .mockResolvedValue({
                        ok: true,

                        data: {
                            revoked_count: 1
                        }
                    });

                render(
                    <SessionManager />
                );

                const button =
                    await screen.findByRole(
                        "button",
                        {
                            name:
                                "Sign Out All Other Devices"
                        }
                    );

                fireEvent.click(
                    button
                );

                await waitFor(() => {
                    expect(
                        client.post
                    ).toHaveBeenCalledWith(
                        "/sessions/revoke-others"
                    );
                });

                expect(
                    await screen.findByText(
                        "1 other device was signed out."
                    )
                ).toBeInTheDocument();
            }
        );


        it(
            "renders nothing when logged out",
            () => {
                useAuth.mockReturnValue({
                    client,
                    authenticated: false
                });

                const {
                    container
                } = render(
                    <SessionManager />
                );

                expect(
                    container
                ).toBeEmptyDOMElement();
            }
        );
    }
);