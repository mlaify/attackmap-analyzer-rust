# attackmap-analyzer-rust

> [!IMPORTANT]
> **Active development, slow pace.** AttackMap is under active development, but
> progress may be slow until more contributors or co-maintainers join. Help is
> very welcome with the core engine, an analyzer, the macOS app, or the docs —
> see [CONTRIBUTING.md](CONTRIBUTING.md) or open an issue on
> [mlaify/AttackMap](https://github.com/mlaify/AttackMap/issues) to say hello.
> Security reports are still welcome at [security@mlaify.io](mailto:security@mlaify.io).

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
- **Route auth (AttackMap#256)**: each route carries `auth` (`required` / `anonymous` / `unknown`), `guards` and `guard_evidence`.
  - **axum:** a `Router::new()` chain is read in order. `.layer` / `.route_layer` wrap only the routes added before them. Routers bound with `let` or returned from `fn name() -> Router` are followed through `.merge(name)` / `.nest("/x", name)`, across files.
  - **actix-web:** `.wrap(...)` on `App::new()` / `web::scope(...)` covers every service in it, nested scopes included. `.service(handler)` links attribute-macro handlers to their scope.
  - **Auth layers:** `middleware::from_fn(require_auth)`, `from_extractor::<RequireAuth>`, `RequireAuthorizationLayer` / `ValidateRequestHeaderLayer::bearer`, `login_required!`, `HttpAuthentication::bearer`.
  - **Handler extractors:** a type like `Claims`, `AuthUser`, `CurrentUser`, `BearerAuth` or `Identity` makes a route `required`, as do Rocket request guards of the same kind. `Option<AuthUser>` makes it `anonymous`, but only when no auth layer applies and every layer on the way up is a known non-auth one (tracing, CORS, compression, ...). axum-login's `AuthManagerLayer` / `AuthSession` only load the user and don't count.
  - **Stays `unknown`:** routers re-layered or merged outside their own chain, handler names defined in more than one module, and Rocket path/data params.

## License

MIT
