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

    async post(path, data = {}) {
        const response = await fetch(
            `${this.baseUrl}${path}`,
            {
                method: "POST",
                credentials: "include",
                headers: {
                    "Content-Type": "application/json",
                    "X-CSRF-Token": this.csrfToken
                },
                body: JSON.stringify(data)
            }
        );

        return response.json();
    }

    async initialize() {
        const configResponse = await this.get("/config");
        const csrfResponse = await this.get("/csrf");

        this.config = configResponse.data;
        this.csrfToken = csrfResponse.data.csrf_token;

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
            data.captcha_token = captchaToken;
        }

        return this.post("/login", data);
    }

    async register({
        email,
        username,
        password
    }) {
        return this.post("/register", {
            email,
            username,
            password
        });
    }

    async logout() {
        return this.post("/logout");
    }

    async me() {
        return this.get("/me");
    }
}