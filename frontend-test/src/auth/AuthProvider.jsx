import {
    createContext,
    useContext,
    useEffect,
    useMemo,
    useState
} from "react";

import AuthClient from "./AuthClient";


const AuthContext = createContext(null);


export function AuthProvider({
    children,
    baseUrl = "/auth"
}) {
    const client = useMemo(
        () => new AuthClient(baseUrl),
        [baseUrl]
    );

    const [ready, setReady] = useState(false);
    const [config, setConfig] = useState(null);
    const [user, setUser] = useState(null);
    
    const [initializationError, setInitializationError] =
        useState(null);

    useEffect(() => {
        async function initializeAuth() {
            try {
                const loadedConfig = await client.initialize();
                const meResponse = await client.me();

                setConfig(loadedConfig);

                if (
                    meResponse.ok &&
                    meResponse.data &&
                    meResponse.data.authenticated
                ) {
                    setUser(meResponse.data.user);
                } else {
                    setUser(null);
                }

                setInitializationError(null);
                setReady(true);

            } catch (error) {
                setInitializationError(error);
                setReady(false);
            }
        }

        initializeAuth();
    }, [client]);

    function handleLogin(userData) {
        setUser(userData);
    }

    async function logout() {
        const response = await client.logout();

        if (response.ok) {
            setUser(null);
        }

        return response;
    }

    const value = {
        client,
        config,
        ready,
        user,
        authenticated: user !== null,
        handleLogin,
        initializationError,
        logout
    };

    return (
        <AuthContext.Provider value={value}>
            {children}
        </AuthContext.Provider>
    );
}


export function useAuth() {
    const context = useContext(AuthContext);

    if (context === null) {
        throw new Error(
            "useAuth must be used inside AuthProvider."
        );
    }

    return context;
}