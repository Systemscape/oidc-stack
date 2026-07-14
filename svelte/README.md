# @systemscape/oidc-stack-svelte

Frontend counterpart of [oidc-stack](../README.md)'s `bff` module: a Svelte
auth store and fetch helpers matching the server's `/auth/*` routes and
401/403 semantics. CSRF is origin-based server-side, so no token handling.

## Install

```sh
pnpm add "github:Systemscape/oidc-stack#path:svelte"
# or pinned: "github:Systemscape/oidc-stack#v0.1.0&path:svelte"
```

## Usage

One client per app, e.g. `src/lib/auth.ts`:

```ts
import { createAuthClient } from '@systemscape/oidc-stack-svelte';

export const auth = createAuthClient({
    proxyPrefix: '/api/',
    onProxyRejected: (url) => console.error(`backend rejected token for ${url}`),
    onForbidden: () => forbiddenError.set(true) // render inline, not a toast
});
```

In the root layout: `await auth.checkAuth()`, gate on `auth.accessDenied` /
`auth.user`. Actions: `auth.login()`, `auth.logout()`,
`auth.clearSessionAndLogin()`.

As Orval mutator, re-export from a module Orval can point at:

```ts
// src/lib/api/fetcher.ts
import { auth } from '$lib/auth';
export const customFetch = auth.customFetch;
```

`./fetcher` has no Svelte dependency if you only need the fetch helpers.

`customFetch` returns `{ data, status, headers }` for any completed response,
success or business error, so callers switch on `status` and render errors
inline; it throws only once the session has expired. On a 401 it first hits
`recoverUrl` (default `/auth/me`) once to force a token refresh and retries the
request, absorbing access-token-expiry races before redirecting to re-auth.

The `AuthUser` shape mirrors the Rust crate's `AuthMeResponse`; a unit test
on the Rust side snapshots the JSON so the two cannot drift silently.
