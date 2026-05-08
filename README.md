# attackmap-analyzer-rust

Rust ecosystem analyzer for [AttackMap](https://github.com/mlaify/AttackMap).

This analyzer extracts structured signals from Rust crates and Cargo workspaces:

- **Web frameworks** — axum, actix-web, rocket (route + entrypoint extraction)
- **Databases** — sqlx (Postgres / MySQL / SQLite), diesel, sea-orm, tokio-postgres, rusqlite, mongodb, redis, deadpool, AWS SDK (S3 / DynamoDB)
- **Auth crates** — jsonwebtoken, argon2 / bcrypt / scrypt / password-hash, oauth2, axum-login, actix-identity, tower-sessions, tower-http auth
- **HTTP clients (external calls)** — reqwest, isahc, surf, ureq
- **Secrets** — `std::env::var`, `dotenv` / `dotenvy`, `env!` macro, `secrecy::SecretString`
- **Service hints** — Cargo `[package].name` and `[workspace].members`

All emissions populate AttackMap's Signal v2 fields (line numbers, evidence snippets, confidence scores) so downstream insights can cite `path/to/file.rs:NN`.

## Install

```bash
pip install git+https://github.com/mlaify/attackmap-analyzer-rust.git
```

The analyzer is auto-discovered by AttackMap via the `attackmap.analyzers` entry-point group.

## Usage with AttackMap

```bash
# Auto-discovered when installed:
attackmap analyze /path/to/rust/repo

# Or invoke explicitly:
attackmap analyze /path/to/rust/repo --module rust
```

## Detection

`detect()` returns true when any of the following are present, ignoring `target/`, `.git/`, `node_modules/`, `.cargo/`, and `vendor/`:

- A `Cargo.toml` or `Cargo.lock` at the repository root, or anywhere in the tree
- One or more `.rs` files in the tree

## Coverage notes

- **Warp** is intentionally not covered yet — its filter-based routing makes path extraction unreliable from regex alone.
- **Tide** framework presence is detected via `tide::` imports; route extraction for tide's `app.at("/x").get(...)` chain is on the roadmap.
- Multi-method axum chains like `.route("/x", get(h).post(h2))` produce one `Route` per HTTP verb in the chain, all sharing the same `line`.
- The actix-web attribute regex (`#[get(...)]`) and rocket attribute regex are intentionally identical; rocket emissions only fire when the file also mentions `rocket` somewhere, to avoid double-counting actix routes.

## License

MIT
