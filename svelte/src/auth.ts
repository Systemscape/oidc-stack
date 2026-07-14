/**
 * Svelte stores and actions for the `/auth/*` routes mounted by
 * `BffAuth::attach` on the server.
 */

import { writable, type Writable } from 'svelte/store';
import type { AuthUser } from './types.js';

export interface AuthStoreOptions {
    /** Override the default `/auth/*` route paths. */
    meUrl?: string;
    loginUrl?: string;
    logoutUrl?: string;
    clearUrl?: string;
}

export interface AuthStore {
    /** Current user; null means not logged in (or not yet checked). */
    user: Writable<AuthUser | null>;
    /** True until the first `checkAuth` completes. */
    authLoading: Writable<boolean>;
    /** Authenticated but rejected by the server's group gate (403). */
    accessDenied: Writable<boolean>;
    /** Query `/auth/me` and update the stores; returns the user or null. */
    checkAuth: () => Promise<AuthUser | null>;
    /** Redirect to `/auth/login` (starts the OIDC flow when needed). */
    login: () => void;
    /** Redirect to `/auth/logout` (RP-initiated logout at the provider). */
    logout: () => void;
    /**
     * Redirect to `/auth/clear`: flushes the session and restarts the
     * login flow. Use when the session is corrupt/expired (401s).
     */
    clearSessionAndLogin: () => void;
}

/** Build the auth stores and actions. */
export function createAuthStore(options: AuthStoreOptions = {}): AuthStore {
    const meUrl = options.meUrl ?? '/auth/me';
    const loginUrl = options.loginUrl ?? '/auth/login';
    const logoutUrl = options.logoutUrl ?? '/auth/logout';
    const clearUrl = options.clearUrl ?? '/auth/clear';

    const user = writable<AuthUser | null>(null);
    const authLoading = writable(true);
    const accessDenied = writable(false);

    async function checkAuth(): Promise<AuthUser | null> {
        try {
            const res = await fetch(meUrl, { credentials: 'include' });

            if (res.ok) {
                const data = await res.json();
                const userData: AuthUser = {
                    sub: data.sub,
                    email: data.email ?? null,
                    name: data.name ?? null,
                    groups: data.groups ?? [],
                };
                user.set(userData);
                accessDenied.set(false);
                return userData;
            }

            if (res.status === 403) {
                accessDenied.set(true);
                return null;
            }
        } catch (e) {
            console.error('Auth check failed:', e);
        } finally {
            authLoading.set(false);
        }

        accessDenied.set(false);
        user.set(null);
        return null;
    }

    function login(): void {
        window.location.href = loginUrl;
    }

    function logout(): void {
        user.set(null);
        window.location.href = logoutUrl;
    }

    function clearSessionAndLogin(): void {
        user.set(null);
        window.location.href = clearUrl;
    }

    return {
        user,
        authLoading,
        accessDenied,
        checkAuth,
        login,
        logout,
        clearSessionAndLogin,
    };
}
