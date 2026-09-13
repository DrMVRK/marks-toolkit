import {
    AuthProvider,
    useAuth
} from "./auth/AuthProvider";


function AuthStatus() {
    const {
        ready,
        config,
        initializationError
    } = useAuth();

    if (initializationError) {
        return (
            <pre>
                {initializationError.message}
            </pre>
        );
    }

    if (!ready) {
        return <p>Initializing auth...</p>;
    }

    return (
        <pre>
            {JSON.stringify(
                {
                    ready,
                    config
                },
                null,
                2
            )}
        </pre>
    );
}


function App() {
    return (
        <AuthProvider>
            <div style={{ padding: "40px" }}>
                <h1>MARKS AuthProvider Test</h1>

                <AuthStatus />
            </div>
        </AuthProvider>
    );
}


export default App;