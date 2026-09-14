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
    const [user, setUser] = useState(null);

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

                <AuthModal
                    open={authOpen}
                    onClose={() => setAuthOpen(false)}
                />
            </div>
        </AuthProvider>
    );
}

export default App;