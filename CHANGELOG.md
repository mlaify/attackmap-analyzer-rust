# Changelog

All notable changes to `attackmap-analyzer-rust` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
