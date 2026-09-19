import "@testing-library/jest-dom/vitest";

import {
    afterEach,
    beforeEach,
    vi
} from "vitest";

import {
    cleanup
} from "@testing-library/react";


beforeEach(() => {
    localStorage.clear();

    vi.stubGlobal(
        "PublicKeyCredential",
        class MockPublicKeyCredential {}
    );

    PublicKeyCredential
        .isConditionalMediationAvailable =
        vi.fn()
            .mockResolvedValue(false);

    PublicKeyCredential
        .parseRequestOptionsFromJSON =
        vi.fn(
            (options) => options
        );
});


afterEach(() => {
    cleanup();

    vi.unstubAllGlobals();

    localStorage.clear();
});