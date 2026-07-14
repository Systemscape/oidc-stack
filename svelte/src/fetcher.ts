/**
 * Fetch helpers for services built on oidc-stack's `bff` module.
 *
 * All requests send credentials. CSRF is enforced server-side via the
 * Sec-Fetch-Site / Origin check (tower-http CsrfLayer); the client sends no
 * token. Framework-agnostic: no Svelte imports here.
 */

/** HTTP methods the CSRF layer treats as mutating. */
const MUTATING_METHODS = ['POST', 'PUT', 'DELETE', 'PATCH'];

export interface AuthFetcherOptions {
    /**
     * URL prefix of routes proxied to a backend API (e.g. '/api/'). A 401
     * under this prefix means the backend rejected the forwarded token
     * (reported via `onProxyRejected`), not that the BFF session expired.
     */
    proxyPrefix?: string;
    /**
     * The BFF session is gone (401 outside `proxyPrefix`). Called at most
     * once per page life. Default: redirect to `/auth/clear`.
     */
    onSessionExpired?: () => void;
    /**
     * 401 under `proxyPrefix`: usually a token/audience misconfiguration.
     * Default: treated like a session expiry.
     */
    onProxyRejected?: (url: string, res: Response) => void;
    /**
     * 403: authenticated but not allowed. Purely a side-effect hook
     * (`customFetch` throws regardless); render the error inline.
     */
    onForbidden?: (url: string, res: Response, isMutating: boolean) => void;
}

export interface AuthFetcher {
    /**
     * Drop-in `fetch` replacement that sends credentials and handles 401.
     * Pass a per-call `on401` to override the configured handling.
     * Use for manual API calls (non-Orval).
     */
    apiFetch: (
        url: string,
        options?: RequestInit & { on401?: (url: string, res: Response) => void }
    ) => Promise<Response>;
    /**
     * Fetch function in the shape Orval expects from a `mutator`
     * (returns `{ data, status, headers }`, throws on non-2xx).
     */
    customFetch: <T>(url: string, options?: RequestInit) => Promise<T>;
    /** Run the configured session-expired handling (deduped). */
    handleSessionExpired: () => void;
}

/** Build the fetch helpers, wiring 401/403 handling to the given hooks. */
export function createAuthFetcher(options: AuthFetcherOptions = {}): AuthFetcher {
    /** Prevent multiple concurrent session-expired redirects. */
    let redirecting = false;

    const onSessionExpired =
        options.onSessionExpired ??
        (() => {
            window.location.href = '/auth/clear';
        });

    function handleSessionExpired(): void {
        if (redirecting) return;
        redirecting = true;
        onSessionExpired();
    }

    function handle401(url: string, res: Response): void {
        if (options.proxyPrefix && url.startsWith(options.proxyPrefix) && options.onProxyRejected) {
            options.onProxyRejected(url, res);
        } else {
            handleSessionExpired();
        }
    }

    async function apiFetch(
        url: string,
        fetchOptions?: RequestInit & { on401?: (url: string, res: Response) => void }
    ): Promise<Response> {
        const { on401, ...init } = fetchOptions ?? {};
        const res = await fetch(url, {
            ...init,
            credentials: 'include'
        });

        if (res.status === 401 && !redirecting) {
            if (on401) {
                on401(url, res);
            } else {
                handle401(url, res);
            }
        }

        return res;
    }

    async function customFetch<T>(url: string, init?: RequestInit): Promise<T> {
        const method = init?.method?.toUpperCase() || 'GET';
        const isMutating = MUTATING_METHODS.includes(method);

        const res = await fetch(url, {
            ...init,
            credentials: 'include'
        });

        if (res.status === 401) {
            if (!redirecting) handle401(url, res);
            throw new Error('Unauthorized');
        }

        if (res.status === 403) {
            options.onForbidden?.(url, res, isMutating);
            const text = await res.text();
            throw new Error(`Forbidden: ${text}`);
        }

        // Throw on non-2xx responses so callers don't need manual status checks
        if (res.status < 200 || res.status >= 300) {
            const text = await res.text();
            throw new Error(`Request failed (${res.status}): ${text}`);
        }

        // Parse response body safely
        const text = await res.text();
        let data: unknown;
        try {
            data = text ? JSON.parse(text) : undefined;
        } catch {
            data = text;
        }

        // Return in the format Orval expects: { data, status, headers }
        return {
            data,
            status: res.status,
            headers: res.headers
        } as T;
    }

    return { apiFetch, customFetch, handleSessionExpired };
}
