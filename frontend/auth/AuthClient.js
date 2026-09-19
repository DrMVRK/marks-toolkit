export default class AuthClient {
    constructor(baseUrl = "/auth") {
        this.baseUrl = baseUrl;
        this.csrfToken = null;
        this.config = null;
    }

    async get(path) {
        const response = await fetch(
            `${this.baseUrl}${path}`,
            {
                method: "GET",
                credentials: "include"
            }
        );

        return response.json();
    }

    async request(
        method,
        path,
        data = null
    ) {
        const options = {
            method,
            credentials: "include",
            headers: {
                "X-CSRF-Token":
                    this.csrfToken
            }
        };

        if (data !== null) {
            options.headers[
                "Content-Type"
            ] = "application/json";

            options.body =
                JSON.stringify(data);
        }

        const response = await fetch(
            `${this.baseUrl}${path}`,
            options
        );

        return response.json();
    }

    async post(
        path,
        data = {}
    ) {
        return this.request(
            "POST",
            path,
            data
        );
    }

    async patch(
        path,
        data = {}
    ) {
        return this.request(
            "PATCH",
            path,
            data
        );
    }

    async delete(
        path,
        data = {}
    ) {
        return this.request(
            "DELETE",
            path,
            data
        );
    }

    async initialize() {
        const configResponse =
            await this.get(
                "/config"
            );

        const csrfResponse =
            await this.get(
                "/csrf"
            );

        this.config =
            configResponse.data;

        this.csrfToken =
            csrfResponse
                .data
                .csrf_token;

        return this.config;
    }

    async login({
        identity,
        password,
        remember = false,
        captchaToken = null
    }) {
        const data = {
            identity,
            password,
            remember
        };

        if (captchaToken) {
            data.captcha_token =
                captchaToken;
        }

        return this.post(
            "/login",
            data
        );
    }

    async register({
        email,
        username,
        password
    }) {
        return this.post(
            "/register",
            {
                email,
                username,
                password
            }
        );
    }

    async forgotPassword(
        email
    ) {
        return this.post(
            "/forgot-password",
            {
                email
            }
        );
    }

    async logout() {
        return this.post(
            "/logout"
        );
    }

    async me() {
        return this.get(
            "/me"
        );
    }

    async resetPassword({
        token,
        password
    }) {
        return this.post(
            "/reset-password",
            {
                token,
                password
            }
        );
    }

    changePassword({
        currentPassword,
        newPassword
    }) {
        return this.post(
            "/change-password",
            {
                current_password:
                    currentPassword,
                new_password:
                    newPassword
            }
        );
    }

    completeTotpChallenge({
        challengeId,
        code
    }) {
        return this.post(
            "/mfa/challenge/totp",
            {
                challenge_id:
                    challengeId,
                code
            }
        );
    }

    completeRecoveryCodeChallenge({
        challengeId,
        recoveryCode
    }) {
        return this.post(
            "/mfa/challenge/recovery-code",
            {
                challenge_id:
                    challengeId,
                recovery_code:
                    recoveryCode
            }
        );
    }

    beginPasskeyRegistration({
        currentPassword
    }) {
        return this.post(
            "/passkeys/register/options",
            {
                current_password:
                    currentPassword
            }
        );
    }

    finishPasskeyRegistration({
        challengeId,
        credential,
        name = null
    }) {
        return this.post(
            "/passkeys/register/verify",
            {
                challenge_id:
                    challengeId,
                credential,
                name
            }
        );
    }

    beginPasskeyLogin() {
        return this.post(
            "/passkeys/login/options"
        );
    }

    finishPasskeyLogin({
        challengeId,
        credential
    }) {
        return this.post(
            "/passkeys/login/verify",
            {
                challenge_id:
                    challengeId,
                credential
            }
        );
    }

    listPasskeys() {
        return this.get(
            "/passkeys"
        );
    }

    renamePasskey({
        credentialId,
        name
    }) {
        return this.patch(
            `/passkeys/${encodeURIComponent(
                credentialId
            )}`,
            {
                name
            }
        );
    }

    deletePasskey({
        credentialId,
        currentPassword
    }) {
        return this.delete(
            `/passkeys/${encodeURIComponent(
                credentialId
            )}`,
            {
                current_password:
                    currentPassword
            }
        );
    }
}