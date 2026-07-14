/**
 * Frontend counterpart of oidc-stack's `bff` module.
 *
 * Create one client per app (e.g. in `src/lib/auth.ts`) and import it
 * everywhere; `customFetch` is shaped for use as an Orval mutator.
 */

import {
    createAuthFetcher,
    type AuthFetcher,
    type AuthFetcherOptions,
} from './fetcher.js';
import {
    createAuthStore,
    type AuthStore,
    type AuthStoreOptions,
} from './auth.js';

export type { AuthUser } from './types.js';
export { hasGroup } from './types.js';
export {
    createAuthFetcher,
    type AuthFetcher,
    type AuthFetcherOptions,
} from './fetcher.js';
export {
    createAuthStore,
    type AuthStore,
    type AuthStoreOptions,
} from './auth.js';

export interface AuthClientOptions
    extends AuthFetcherOptions, AuthStoreOptions {}

export type AuthClient = AuthStore & AuthFetcher;

/**
 * Build the auth store and fetch helpers wired together: by default a 401
 * clears the user store and redirects to `/auth/clear`.
 */
export function createAuthClient(options: AuthClientOptions = {}): AuthClient {
    const store = createAuthStore(options);
    const fetcher = createAuthFetcher({
        ...options,
        onSessionExpired:
            options.onSessionExpired ?? (() => store.clearSessionAndLogin()),
    });
    return { ...store, ...fetcher };
}
