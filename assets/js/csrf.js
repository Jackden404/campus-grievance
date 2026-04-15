(() => {
    let cachedToken = null;
    let tokenPromise = null;

    function getEndpoint() {
        const meta = document.querySelector('meta[name="csrf-endpoint"]');
        return meta ? meta.getAttribute("content") : "php/csrf_token.php";
    }

    async function fetchCsrfToken() {
        if (cachedToken) {
            return cachedToken;
        }
        if (!tokenPromise) {
            tokenPromise = fetch(getEndpoint(), {
                method: "GET",
                credentials: "same-origin",
                headers: { "X-Requested-With": "XMLHttpRequest" }
            })
                .then((response) => response.json())
                .then((payload) => {
                    if (!payload || !payload.success || !payload.csrf_token) {
                        throw new Error("CSRF token fetch failed");
                    }
                    cachedToken = payload.csrf_token;
                    return cachedToken;
                });
        }
        return tokenPromise;
    }

    async function attachTokensToForms() {
        const token = await fetchCsrfToken();
        const forms = document.querySelectorAll("form[method='post'], form[method='POST']");
        forms.forEach((form) => {
            let tokenInput = form.querySelector("input[name='csrf_token']");
            if (!tokenInput) {
                tokenInput = document.createElement("input");
                tokenInput.type = "hidden";
                tokenInput.name = "csrf_token";
                form.appendChild(tokenInput);
            }
            tokenInput.value = token;

            form.addEventListener("submit", async (event) => {
                if (!tokenInput.value) {
                    event.preventDefault();
                    try {
                        tokenInput.value = await fetchCsrfToken();
                        form.submit();
                    } catch (_) {}
                }
            });
        });
    }

    window.getCsrfToken = fetchCsrfToken;

    document.addEventListener("DOMContentLoaded", () => {
        attachTokensToForms().catch(() => {});
    });
})();
