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

- **Web frameworks** — axum, actix-web, rocket, poem, salvo, loco, warp, tide (routes with their full mounted path; entrypoints)
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

- **Route prefixes:** a route's path includes the prefixes of every router that mounts it.
  - **axum:** `.nest("/p", x)` / `.merge(x)` where `x` is an inline `Router::new()...`, a `let x = Router::new()...` binding (same file, nearest earlier one) or `x()` / `module::x()` returning a router (any file; several `fn routes()` are told apart by module path or by being in the caller's file). A router nested at two prefixes yields a route under each.
  - **actix-web:** `web::scope("/p")` and `web::resource("/p")` (also bare `scope(..)` / `resource(..)` when imported from `actix_web`), nested scopes, `.configure(module::config)`, and `#[get]` handlers mounted with `.service(handler)`.
  - **rocket:** `.mount("/base", routes![a, m::b])` and `.mount("/base", m::routes())` where `fn routes()` returns `routes![..]`.
  - **poem** `Route::new().at(..).nest(..)`, **salvo** `Router::with_path(..).get(h).push(..)`, **loco** `Routes::new().prefix(..).add(..)` under `AppRoutes::..().prefix(..).add_route(..)`.
  - **warp:** each `warp::path!("users" / u32)` is a route (`/users/{u32}`); its method is the `warp::get()`-style filter combined with it. `path!(".." / ..)` prefix filters and `path!` used under another filter (`x.and(warp::path!(..))`) aren't emitted, since their prefix isn't visible.
  - **tide:** `app.at("/x").at("/y").get(h)`, including receivers bound with `let api = app.at("/api")`.
  - A non-literal prefix (`.nest(&format!(..), x)`) or an ambiguous mount leaves the route at its own path. `let` bindings resolve only within their own fn, and `let api = api.route(..)` continues the earlier router.
  - A named router that nothing visible mounts counts as a fully-seen root (for `anonymous`) only when it is handed to a server (`axum::serve(l, app)`, poem `.run(app)`, salvo `.serve(router)`).
- Multi-method axum chains like `.route("/x", get(h).post(h2))` produce one `Route` per HTTP verb in the chain, all sharing the same `line`.
- The actix-web attribute regex (`#[get(...)]`) and rocket attribute regex are intentionally identical; rocket emissions only fire when the file also mentions `rocket` somewhere, to avoid double-counting actix routes.
- **Route auth (AttackMap#256)**: each route carries `auth` (`required` / `anonymous` / `unknown`), `guards` and `guard_evidence`.
  - **axum:** a `Router::new()` chain is read in order. `.layer` / `.route_layer` wrap only the routes added before them. Routers bound with `let` or returned from `fn name() -> Router` are followed through `.merge(name)` / `.nest("/x", name)`, across files.
  - **actix-web:** `.wrap(...)` on `App::new()` / `web::scope(...)` / `web::resource(...)` covers every service in it, nested and configured scopes included. `.service(handler)` links attribute-macro handlers to their scope.
  - **poem / salvo / loco:** poem `.with(..)` wraps the routes before it; salvo `.hoop(..)` and loco `.layer(..)` cover the whole router.
  - Each mount path is resolved on its own, so a router nested under an auth layer at `/admin` and outside it at `/preview` gets `required` only under `/admin`.
  - **Auth layers:** `middleware::from_fn(require_auth)`, `from_extractor::<RequireAuth>`, `RequireAuthorizationLayer` / `ValidateRequestHeaderLayer::bearer`, `login_required!`, `HttpAuthentication::bearer`.
  - **Handler extractors:** a type like `Claims`, `AuthUser`, `CurrentUser` or `LoggedUser` makes a route `required` only when its `FromRequestParts` / `FromRequest` impl is in the repo, can reject (not `type Rejection = Infallible`) and checks credentials (reads an auth header / cookie / session / token, or rejects with 401/403); the same goes for Rocket request guards. Library extractors that reject anonymous callers count without a visible impl: actix-web-httpauth `BearerAuth` / `BasicAuth`, actix-identity `Identity`, loco `JWT` / `JWTWithUser`. `Option<AuthUser>` makes it `anonymous`, but only when no auth layer applies and every layer on the way up is a known non-auth one (tracing, CORS, compression, ...). axum-login's `AuthManagerLayer` / `AuthSession` only load the user and don't count.
  - **Stays `unknown`:** routers re-layered or merged outside their own chain, handler names defined in more than one module that can't be told apart, extractors without a visible impl, Rocket path/data params, and warp / tide routes.

## License

MIT
