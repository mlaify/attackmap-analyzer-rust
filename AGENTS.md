# AGENTS.md

## Project
This repository contains an AttackMap analyzer.

AttackMap analyzers live under:
- `github.com/mlaify`

This repo should implement one analyzer cleanly against the AttackMap core contract.

## Analyzer responsibilities
This analyzer should:
- detect whether it applies to a target repository
- emit structured signals
- remain heuristic but explainable

## Scope
Rust ecosystem coverage:

- **Web frameworks**: axum, actix-web, rocket (routes + entrypoint markers)
- **Databases**: sqlx, diesel, sea-orm, tokio-postgres, rusqlite, mongodb, redis, deadpool, AWS SDK (S3, DynamoDB)
- **Auth crates**: jsonwebtoken, argon2/bcrypt/scrypt/password-hash, oauth2, axum-login, actix-identity, tower-sessions, tower-http::auth
- **HTTP clients**: reqwest, isahc, surf, ureq (external call extraction)
- **Secrets**: `std::env::var`, `dotenv` / `dotenvy`, `env!` macro, `secrecy::SecretString`
- **Service hints**: Cargo `[package].name` + `[workspace].members`

## Out of scope (for now)
- **warp** route extraction — its filter-based routing requires AST-level analysis; pure regex is unreliable.
- **tide** route chain (`app.at("/x").get(h).post(h)`) — framework presence is detected, route chains are not.
- Cross-crate `use ... as ...` aliases that rename auth/DB types — pattern matching is on canonical paths.

## Signal v2 alignment
All emissions populate the optional `line`, `evidence_text`, and (where applicable) `confidence` fields on the AttackMap hint models, so insights can cite `path/to/file.rs:NN` and downstream detectors can filter low-confidence keyword sweeps from high-confidence pattern hits.

Confidence policy:
- Pattern hits on canonical crate paths (`jsonwebtoken::`, `argon2::`, `sqlx::postgres`, etc.) → ≥ 0.85
- Hash-style auth crates (argon2, bcrypt, scrypt) → 0.9 (very strong defensive signal)
- Keyword-only matches (`Authorization`, `Bearer`, `api_key`) → 0.6 (treat as supporting evidence, not load-bearing)
- Secret env-var extractions → 0.85

## Testing
Tests write realistic Rust snippets to `tmp_path` and assert on the resulting `ScanResult` — never on a single regex in isolation. New extractors must include both a positive test (signal fires on representative code) and a negative test (signal does **not** fire on look-alikes — e.g., `map.get("api_key")` is not a reqwest external call).
