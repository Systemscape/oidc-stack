/**
 * Authenticated user as returned by `GET /auth/me`.
 *
 * Mirrors `AuthMeResponse` in the Rust crate (src/bff/stack.rs); a unit test
 * there snapshots the JSON shape so drift fails the Rust test suite.
 */
export interface AuthUser {
    sub: string;
    email: string | null;
    name: string | null;
    groups: string[];
}

/** Whether `group` is among the user's groups (mirrors the server-side gate). */
export function hasGroup(user: AuthUser | null, group: string): boolean {
    return user?.groups.includes(group) ?? false;
}
