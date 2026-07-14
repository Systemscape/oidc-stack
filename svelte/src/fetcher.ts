/**
 * Fetch helpers for services built on oidc-stack's `bff` module.
 *
 * All requests send credentials and use manual redirect handling, so an
 * expired-session redirect surfaces as an opaque response instead of being
 * silently followed to a login page. CSRF is enforced server-side via the
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
     * The BFF session is gone (401 outside `proxyPrefix`, and recovery failed).
     * Called at most once per page life. Default: redirect to `/auth/clear`.
     */
    onSessionExpired?: () => void;
    /**
     * 401 under `proxyPrefix`: usually a token/audience misconfiguration.
     * Default: treated like a session expiry.
     */
    onProxyRejected?: (url: string, res: Response) => void;
    /**
     * 403: authenticated but not allowed. Side-effect hook only; `customFetch`
     * still returns the response so callers can render the error inline.
     */
    onForbidden?: (url: string, res: Response, isMutating: boolean) => void;
    /**
     * Endpoint hit once to force a server-side token refresh before treating a
     * 401 / redirect as a real session expiry. Concurrent failures share one
     * attempt; each caller then retries its request once. This absorbs the
     * common case where the access token expired and a concurrent refresh
     * raced. Default '/auth/me'; set to `null` to disable recovery.
     */
    recoverUrl?: string | null;
}

export interface AuthFetcher {
    /**
     * Drop-in `fetch` replacement that sends credentials and handles 401
     * (with one recovery+retry). Pass a per-call `on401` to override the
     * configured handling. Use for manual API calls (non-Orval).
     */
    apiFetch: (
        url: string,
        options?: RequestInit & { on401?: (url: string, res: Response) => void }
    ) => Promise<Response>;
    /**
     * Fetch function in the shape Orval expects from a `mutator`: returns
     * `{ data, status, headers }` for any completed response, success or
     * business error, so callers switch on `status`. Throws only when the
     * session has expired (the page is being redirected to re-auth).
     */
    customFetch: <T>(url: string, options?: RequestInit) => Promise<T>;
    /** Run the configured session-expired handling (deduped). */
    handleSessionExpired: () => void;
}

/** Build the fetch helpers, wiring 401/403 handling to the given hooks. */
export function createAuthFetcher(options: AuthFetcherOptions = {}): AuthFetcher {
    /** Prevent multiple concurrent session-expired redirects. */
    let redirecting = false;

    const recoverUrl = options.recoverUrl === undefined ? '/auth/me' : options.recoverUrl;

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

    /** A 401 or an opaque (manual) redirect both mean the session lost its token. */
    function isSessionExpiry(res: Response): boolean {
        return res.type === 'opaqueredirect' || res.status === 401;
    }

    /**
     * Single-flight session recovery: hit `recoverUrl` once to force the BFF to
     * refresh the access token. Concurrent callers share the same attempt, so a
     * burst of expired requests triggers exactly one refresh.
     */
    let recovery: Promise<boolean> | null = null;
    function recoverSession(): Promise<boolean> {
        if (!recoverUrl) return Promise.resolve(false);
        recovery ??= (async () => {
            try {
                const res = await fetch(recoverUrl, {
                    credentials: 'include',
                    redirect: 'manual'
                });
                return res.status === 200;
            } catch {
                return false;
            }
        })().finally(() => {
            recovery = null;
        });
        return recovery;
    }

    async function apiFetch(
        url: string,
        fetchOptions?: RequestInit & { on401?: (url: string, res: Response) => void }
    ): Promise<Response> {
        const { on401, ...init } = fetchOptions ?? {};

        const run = async (isRetry: boolean): Promise<Response> => {
            const res = await fetch(url, {
                ...init,
                credentials: 'include',
                redirect: 'manual'
            });

            if (isSessionExpiry(res)) {
                if (!isRetry && (await recoverSession())) return run(true);
                if (!redirecting) {
                    if (on401) on401(url, res);
                    else handle401(url, res);
                }
            }
            return res;
        };

        return run(false);
    }

    async function customFetch<T>(url: string, init?: RequestInit): Promise<T> {
        const method = init?.method?.toUpperCase() || 'GET';
        const isMutating = MUTATING_METHODS.includes(method);

        const run = async (isRetry: boolean): Promise<Response> => {
            const res = await fetch(url, {
                ...init,
                credentials: 'include',
                redirect: 'manual'
            });
            if (isSessionExpiry(res) && !isRetry && (await recoverSession())) {
                return run(true);
            }
            return res;
        };
        const res = await run(false);

        // Session gone (and recovery failed): abort the caller; the page is
        // being redirected to re-authenticate.
        if (isSessionExpiry(res)) {
            if (!redirecting) handle401(url, res);
            throw new Error('Unauthorized');
        }

        if (res.status === 403) {
            options.onForbidden?.(url, res.clone(), isMutating);
        }

        // Parse the body once. Any completed response (success or business
        // error) is returned so callers switch on `status` and render inline.
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
