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
    const [initializationError, setInitializationError] =
        useState(null);

    useEffect(() => {
        async function initializeAuth() {
            try {
                const loadedConfig =
                    await client.initialize();

                setConfig(loadedConfig);
                setInitializationError(null);
                setReady(true);

            } catch (error) {
                setInitializationError(error);
                setReady(false);
            }
        }

        initializeAuth();
    }, [client]);

    const value = {
        client,
        config,
        ready,
        initializationError
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