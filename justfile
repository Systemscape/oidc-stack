# Path to the prettier binary installed by the svelte package.
# Run `just install` first if it is missing.
prettier := "./svelte/node_modules/.bin/prettier"

# List available recipes.
default:
    @just --list

# Install the frontend toolchain (pnpm deps, incl. prettier & tsc).
install:
    cd svelte && pnpm install

# Format everything: Rust with cargo fmt, the rest with prettier.
fmt:
    cargo fmt --all
    {{prettier}} --write .

# Check formatting without modifying files (what CI runs).
fmt-check:
    cargo fmt --all --check
    {{prettier}} --check .

# Type-check the code: cargo check (all features) + tsc.
check:
    cargo check --all-features --all-targets
    cd svelte && pnpm run check

# Run all Rust tests (all features).
test:
    cargo test --all-features

# Run the full CI suite locally.
ci: fmt-check check test
