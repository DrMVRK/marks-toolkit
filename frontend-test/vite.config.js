import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import path from "path";
import { fileURLToPath } from "url";


const __filename = fileURLToPath(
    import.meta.url
);

const __dirname = path.dirname(
    __filename
);


export default defineConfig({
    plugins: [
        react()
    ],

    resolve: {
        alias: {
            "@marks-auth": path.resolve(
                __dirname,
                "../frontend/auth"
            ),

            "react": path.resolve(
                __dirname,
                "node_modules/react"
            ),

            "react-dom": path.resolve(
                __dirname,
                "node_modules/react-dom"
            ),

            "qrcode.react": path.resolve(
                __dirname,
                "node_modules/qrcode.react"
            )
        },

        dedupe: [
            "react",
            "react-dom"
        ]
    },

    server: {
        fs: {
            allow: [
                path.resolve(
                    __dirname,
                    ".."
                )
            ]
        },

        proxy: {
            "/auth": {
                target:
                    "http://127.0.0.1:5000",

                changeOrigin: true
            }
        }
    }
});