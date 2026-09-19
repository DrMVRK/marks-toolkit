import {
    useEffect,
    useState
} from "react";

import { useAuth } from "./AuthProvider";
import PasskeyEnrollment from "./PasskeyEnrollment";
import ReauthDialog from "./ReauthDialog";


export default function PasskeyManager({
    onChanged = null
}) {
    const {
        client,
        authenticated
    } = useAuth();

    const [passkeys, setPasskeys] =
        useState([]);

    const [loading, setLoading] =
        useState(false);

    const [error, setError] =
        useState(null);

    const [message, setMessage] =
        useState("");

    const [
        editingCredentialId,
        setEditingCredentialId
    ] = useState(null);

    const [
        editingName,
        setEditingName
    ] = useState("");

    const [
        deletingPasskey,
        setDeletingPasskey
    ] = useState(null);

    const [
        deleteLoading,
        setDeleteLoading
    ] = useState(false);

    const [
        deleteError,
        setDeleteError
    ] = useState(null);


    useEffect(() => {
        if (authenticated) {
            refreshPasskeys();
        } else {
            setPasskeys([]);
            setError(null);
            setMessage("");
            setEditingCredentialId(
                null
            );
            setDeletingPasskey(
                null
            );
        }
    }, [authenticated]);


    async function refreshPasskeys() {
        setLoading(true);
        setError(null);

        try {
            const response =
                await client
                    .listPasskeys();

            if (!response.ok) {
                setError(
                    response.error || {
                        message:
                            "Unable to load passkeys."
                    }
                );

                return;
            }

            setPasskeys(
                response.data
                    ?.passkeys
                || []
            );

        } catch (requestError) {
            console.error(
                "Passkey list request failed:",
                requestError
            );

            setError({
                code: "NETWORK_ERROR",
                message:
                    "Unable to load passkeys."
            });

        } finally {
            setLoading(false);
        }
    }


    async function handleEnrollment() {
        setMessage(
            "Passkey added successfully."
        );

        await refreshPasskeys();

        if (
            typeof onChanged
            === "function"
        ) {
            await onChanged();
        }
    }


    function beginRename(
        passkey
    ) {
        setError(null);
        setMessage("");

        setEditingCredentialId(
            passkey.credential_id
        );

        setEditingName(
            passkey.name || ""
        );
    }


    function cancelRename() {
        setEditingCredentialId(
            null
        );

        setEditingName("");
    }


    async function saveRename(
        credentialId
    ) {
        setError(null);
        setMessage("");

        try {
            const response =
                await client
                    .renamePasskey({
                        credentialId,
                        name:
                            editingName
                    });

            if (!response.ok) {
                setError(
                    response.error || {
                        message:
                            "Unable to rename passkey."
                    }
                );

                return;
            }

            setEditingCredentialId(
                null
            );

            setEditingName("");

            setMessage(
                "Passkey renamed successfully."
            );

            await refreshPasskeys();

            if (
                typeof onChanged
                === "function"
            ) {
                await onChanged();
            }

        } catch (requestError) {
            console.error(
                "Passkey rename failed:",
                requestError
            );

            setError({
                code: "NETWORK_ERROR",
                message:
                    "Unable to rename passkey."
            });
        }
    }


    function beginDelete(
        passkey
    ) {
        setDeleteError(null);
        setError(null);
        setMessage("");

        setDeletingPasskey(
            passkey
        );
    }


    async function confirmDelete(
        currentPassword
    ) {
        if (!deletingPasskey) {
            return;
        }

        setDeleteLoading(true);
        setDeleteError(null);

        try {
            const response =
                await client
                    .deletePasskey({
                        credentialId:
                            deletingPasskey
                                .credential_id,

                        currentPassword
                    });

            if (!response.ok) {
                setDeleteError(
                    response.error || {
                        message:
                            "Unable to delete passkey."
                    }
                );

                return;
            }

            setDeletingPasskey(
                null
            );

            setMessage(
                "Passkey deleted successfully."
            );

            await refreshPasskeys();

            if (
                typeof onChanged
                === "function"
            ) {
                await onChanged();
            }

        } catch (requestError) {
            console.error(
                "Passkey deletion failed:",
                requestError
            );

            setDeleteError({
                code: "NETWORK_ERROR",
                message:
                    "Unable to delete passkey."
            });

        } finally {
            setDeleteLoading(false);
        }
    }


    function formatDate(
        value
    ) {
        if (!value) {
            return "Never";
        }

        const date = new Date(
            value
        );

        if (
            Number.isNaN(
                date.getTime()
            )
        ) {
            return value;
        }

        return date.toLocaleString();
    }


    if (!authenticated) {
        return null;
    }


    return (
        <div className="marks-auth-mfa-section">
            <h3>
                Passkeys
            </h3>

            <p>
                Passkeys let you sign in using
                Windows Hello, Touch ID, Face ID,
                a security key, or another
                compatible authenticator.
            </p>

            <PasskeyEnrollment
                onEnrolled={
                    handleEnrollment
                }
            />

            {error && (
                <p className="marks-auth-error">
                    {
                        error.message
                        || "A passkey error occurred."
                    }
                </p>
            )}

            {message && (
                <p className="marks-auth-success">
                    {message}
                </p>
            )}

            {loading && (
                <p>
                    Loading passkeys...
                </p>
            )}

            {!loading
                && passkeys.length === 0
                && (
                    <p>
                        No passkeys are currently
                        registered.
                    </p>
                )}

            {passkeys.length > 0 && (
                <div className="marks-auth-passkey-list">
                    {passkeys.map(
                        (passkey) => (
                            <div
                                key={
                                    passkey
                                        .credential_id
                                }
                                className={
                                    "marks-auth-passkey-item"
                                }
                            >
                                {
                                    editingCredentialId
                                    === passkey
                                        .credential_id
                                        ? (
                                            <div>
                                                <input
                                                    type="text"
                                                    value={
                                                        editingName
                                                    }
                                                    maxLength={
                                                        100
                                                    }
                                                    placeholder={
                                                        "Passkey name"
                                                    }
                                                    onChange={(
                                                        event
                                                    ) => {
                                                        setEditingName(
                                                            event
                                                                .target
                                                                .value
                                                        );
                                                    }}
                                                />

                                                <button
                                                    type="button"
                                                    onClick={() =>
                                                        saveRename(
                                                            passkey
                                                                .credential_id
                                                        )
                                                    }
                                                >
                                                    Save
                                                </button>

                                                <button
                                                    type="button"
                                                    className={
                                                        "marks-auth-secondary"
                                                    }
                                                    onClick={
                                                        cancelRename
                                                    }
                                                >
                                                    Cancel
                                                </button>
                                            </div>
                                        )
                                        : (
                                            <>
                                                <div>
                                                    <strong>
                                                        {
                                                            passkey.name
                                                            || "Unnamed passkey"
                                                        }
                                                    </strong>

                                                    <p>
                                                        Added:{" "}
                                                        {
                                                            formatDate(
                                                                passkey
                                                                    .created_at
                                                            )
                                                        }
                                                    </p>

                                                    <p>
                                                        Last used:{" "}
                                                        {
                                                            formatDate(
                                                                passkey
                                                                    .last_used_at
                                                            )
                                                        }
                                                    </p>

                                                    {
                                                        passkey
                                                            .transports
                                                            ?.length
                                                        > 0
                                                        && (
                                                            <p>
                                                                Transport:{" "}
                                                                {
                                                                    passkey
                                                                        .transports
                                                                        .join(
                                                                            ", "
                                                                        )
                                                                }
                                                            </p>
                                                        )
                                                    }
                                                </div>

                                                <div className="marks-auth-actions">
                                                    <button
                                                        type="button"
                                                        className={
                                                            "marks-auth-secondary"
                                                        }
                                                        onClick={() =>
                                                            beginRename(
                                                                passkey
                                                            )
                                                        }
                                                    >
                                                        Rename
                                                    </button>

                                                    <button
                                                        type="button"
                                                        onClick={() =>
                                                            beginDelete(
                                                                passkey
                                                            )
                                                        }
                                                    >
                                                        Delete
                                                    </button>
                                                </div>
                                            </>
                                        )
                                }
                            </div>
                        )
                    )}
                </div>
            )}

            <button
                type="button"
                className="marks-auth-secondary"
                onClick={
                    refreshPasskeys
                }
                disabled={loading}
            >
                Refresh Passkeys
            </button>

            <ReauthDialog
                open={
                    deletingPasskey
                    !== null
                }

                title="Delete Passkey"

                message={
                    deletingPasskey
                        ? (
                            `Enter your current password to delete ${
                                deletingPasskey.name
                                || "this passkey"
                            }.`
                        )
                        : ""
                }

                confirmLabel={
                    "Delete Passkey"
                }

                loading={
                    deleteLoading
                }

                error={
                    deleteError
                }

                onConfirm={
                    confirmDelete
                }

                onCancel={() => {
                    setDeletingPasskey(
                        null
                    );

                    setDeleteError(
                        null
                    );
                }}
            />
        </div>
    );
}