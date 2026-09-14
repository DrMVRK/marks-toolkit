import { useState } from "react";

import AuthModal from "./auth/AuthModal";
import {
    AuthProvider,
    useAuth
} from "./auth/AuthProvider";

import "./auth/auth.css";


function AuthStatus() {
    const {
        authenticated,
        user,
        logout
    } = useAuth();

    return (
        <div>
            <pre>
                {JSON.stringify(
                    {
                        authenticated,
                        user
                    },
                    null,
                    2
                )}
            </pre>

            {authenticated && (
                <button
                    type="button"
                    onClick={logout}
                >
                    Log Out
                </button>
            )}
        </div>
    );
}


function App() {
    const [authOpen, setAuthOpen] = useState(false);
    const [resetOpen, setResetOpen] = useState(false);

    const resetToken = "eyJhdXRoX2lkIjoia3ItZmhKTWhTQW8tblh2RE9DeGxQUFBOejlnLWEtbm11Rkp0NzJwUGc0YyJ9.aqftKw.vdV9f1rXKKjhboNidrYAzx_koZk";

    return (
        <AuthProvider>
            <div style={{ padding: "40px" }}>
                <h1>MARKS Toolkit Auth Test</h1>

                <AuthStatus />

                <button
                    type="button"
                    onClick={() => setAuthOpen(true)}
                >
                    Open Auth
                </button>

                <button
                    type="button"
                    onClick={() => setResetOpen(true)}
                >
                    Test Password Reset
                </button>

                <AuthModal
                    open={authOpen}
                    onClose={() => setAuthOpen(false)}
                />

                <AuthModal
                    open={resetOpen}
                    onClose={() => setResetOpen(false)}
                    initialView="reset-password"
                    resetToken={resetToken}
                />
            </div>
        </AuthProvider>
    );
}


export default App;