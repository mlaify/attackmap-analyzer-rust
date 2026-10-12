# Changelog

All notable changes to `attackmap-analyzer-rust` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added — route prefixes and more frameworks (#2, AttackMap#261)

- **Routes carry their full mounted path.** Routes are emitted after the whole repo is read, joined to the prefixes of every router that mounts them:
  - **axum:** `.nest("/p", x)` / `.merge(x)` with an inline `Router::new()`, a `let` binding (nearest earlier one in the file) or a router fn (`x()` / `module::x()`, any file). Several `fn routes()` are told apart by module path (`users::routes` → `users.rs` / `users/mod.rs`) or by living in the caller's file; ambiguous mounts are left alone. A fn router returned as the body's tail expression (after inner items) is now recognized too.
  - **actix-web:** `web::scope` / `web::resource` prefixes, nested scopes, `.configure(module::config)`, and `#[get]` handlers mounted with `.service(h)`. Bare `scope(..)` / `resource(..)` / `get()` count when imported from `actix_web`. `web::resource("/x").route(web::get().to(h))` and `.to(h)` are now routes (`ACTIX_RESOURCE_PATTERN` is no longer dead), as are `.route("", ..)` scope roots.
  - **rocket:** `.mount("/base", routes![..])` and `.mount("/base", m::routes())` prefix the handlers they list.
  - **New frameworks:** poem `Route::new().at(..).nest(..)`, salvo `Router::with_path(..).get(h).push(..)`, loco `Routes::new().prefix(..).add(..)` under `AppRoutes::..().prefix(..).add_route(..)`, warp `path!(..)` filters, tide `app.at(..).get(h)` (with `let api = app.at("/api")` receivers).
- **Precision rules for mounts.** A `let` binding resolves only within the fn it's in, so a parameter with the same name as another fn's binding isn't a mount. A named router that nothing visible mounts is a known root only when it's handed to a server (`axum::serve(l, app)`, `.serve(app.into_make_service())`, poem `.run(app)`); otherwise, and under a non-literal prefix, its auth stays `unknown`. `let api = api.route(..)` rebindings continue the earlier router. `/api/` + `/` is `/api`. Frameworks that share builder names (salvo / axum `Router`, poem, loco) are told apart by `use` lines, not by words.
- A router mounted at several prefixes yields one route per prefix, each with the auth layers on its own path (an auth `route_layer` added after `.nest("/admin", x)` but before `.nest("/preview", x)` guards only `/admin`). poem `.with`, salvo `.hoop`, loco `.layer` and actix `wrap` on resources are recognized auth layers.

### Changed

- **Extractor auth needs a visible impl.** A handler extractor named like auth (`AuthUser`, `Claims`, `CurrentUser`, `LoggedUser`, ...) makes a route `required` (or `Option<..>` `anonymous`) only when its `FromRequestParts` / `FromRequest` impl is in the repo, can reject (`type Rejection = Infallible` doesn't), and checks credentials: it reads an auth header, cookie, session or token, or rejects with 401/403. A rejecting extractor that merely has an auth-like name (`AdminFilters` parsing a query string) doesn't count. Library extractors `BearerAuth`, `BasicAuth`, `Identity` and loco `JWT` / `JWTWithUser` still count without one.
- Handler signatures are resolved by module path / same file when a name is defined more than once, instead of giving up.
- Route dedup uses a key set instead of scanning every emitted route (it was quadratic in the route count).
- axum `.route("/x", get(h))` methods come only from that `.route(..)` call; text after it (e.g. a test's `client.post(..)`) no longer adds methods.

### Added — route-level auth (#5, AttackMap#256)

- **Routes carry their auth in the core contract.** `Route.auth` is `required`, `anonymous` or `unknown`, with `guards` naming the layer or extractor and `guard_evidence` quoting it. AttackMap ≥ 0.6 trusts it over its own resolution, which can't read Rust, and over the ±40-line auth-hint window. Older cores ignore the fields, and the existing auth hints are unchanged.
- **axum:** `.layer` / `.route_layer` wrap the routes added before them in a `Router::new()` chain. Routers bound with `let` or returned from `fn` are followed through `.merge` / `.nest` into the routers that mount them, across files (memoized, depth-bounded; several mount points must agree). Recognized auth layers: `middleware::from_fn[_with_state](<auth fn>)`, `from_extractor::<T>`, `RequireAuthorizationLayer`, `ValidateRequestHeaderLayer::bearer`, `login_required!`.
- **actix-web:** `.wrap(HttpAuthentication::bearer(..))` (or another auth middleware) on `App::new()` / `web::scope(..)` guards every `.service(handler)` and `.route(..)` in it, nested scopes included.
- **Extractors and request guards** (axum, actix, Rocket): a handler parameter typed `Claims`, `AuthUser`, `CurrentUser`, `BearerAuth`, `Identity`, `Jwt<..>`, `ApiKey`, … makes the route `required`. Handlers are found across files, and names defined twice stay unresolved. `Option<AuthUser>` is an explicit opt-in to anonymous callers. The route is `anonymous` only when no auth layer applies and every layer on its path is a known non-auth one. That also covers a route added after a `route_layer` in the same router. Rocket path/data params (`<id>`) are not guards.
- Chain links may now be separated by comments. Brackets are matched in one cached pass per file, arguments are split by jumping over nested closures, and mount resolution is memoized, so adversarial input stays linear.

### Changed

- Walk and read the repo with the shared `attackmap.sdk.fs` helpers
  (`iter_repo_files`, `read_source`, `rel`, `line_of`) instead of a private
  `rglob` + `SKIP_DIRS` walk ([mlaify/AttackMap#253](https://github.com/mlaify/AttackMap/issues/253)).
  Skip dirs are now `DEFAULT_SKIP_DIRS` plus `.cargo` (a superset of the old list; it also skips `build/`, `dist/`, `out/`, `.venv/` and AttackMap output dirs).

### Fixed

- A repo checked out under a directory named like a skip dir (e.g. `/build/...`,
  `.../out/...`) was silently skipped entirely; skip dirs are now matched only
  inside the repo.
- Symlinked files pointing outside the repo are no longer analyzed.
- An unreadable file no longer raises out of `analyze()`, and cp1252/latin-1
  sources are analyzed instead of dropped. `files_scanned` counts only files
  that were actually read.
- `detect()` stops at the first `Cargo.toml` or `.rs` file and prunes skipped directories instead of walking all of them.

## [0.1.0] - 2026-06-04

### Added

- Initial public release. Rust ecosystem analyzer plugin for AttackMap (axum, actix-web, rocket; sqlx/diesel/sea-orm; jsonwebtoken/argon2; reqwest).
- Registered under the `attackmap.analyzers` entry-point group so the core
  AttackMap CLI auto-discovers this analyzer once installed.
- Emits Signal-v2 records (`file:line` citation, evidence text, and confidence
  score) for every signal.

[Unreleased]: https://github.com/mlaify/attackmap-analyzer-rust/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/mlaify/attackmap-analyzer-rust/releases/tag/v0.1.0
