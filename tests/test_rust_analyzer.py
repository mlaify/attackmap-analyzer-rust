"""Tests for the RustAnalyzer plugin.

Each test writes a realistic Rust snippet into tmp_path and asserts on the
ScanResult. Line-number assertions verify the Signal v2 plumbing.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from attackmap_analyzer_rust import RustAnalyzer


# ---------- detect() ----------


def test_detect_picks_up_cargo_toml(tmp_path: Path) -> None:
    (tmp_path / "Cargo.toml").write_text('[package]\nname = "demo"\n', encoding="utf-8")
    assert RustAnalyzer().detect(tmp_path) is True


def test_detect_picks_up_nested_cargo(tmp_path: Path) -> None:
    nested = tmp_path / "crates" / "api"
    nested.mkdir(parents=True)
    (nested / "Cargo.toml").write_text('[package]\nname = "api"\n', encoding="utf-8")
    assert RustAnalyzer().detect(tmp_path) is True


def test_detect_picks_up_bare_rs_files(tmp_path: Path) -> None:
    (tmp_path / "main.rs").write_text("fn main() {}", encoding="utf-8")
    assert RustAnalyzer().detect(tmp_path) is True


def test_detect_skips_target_dir(tmp_path: Path) -> None:
    target_dir = tmp_path / "target" / "debug"
    target_dir.mkdir(parents=True)
    (target_dir / "stale.rs").write_text("// build artifact", encoding="utf-8")
    assert RustAnalyzer().detect(tmp_path) is False


def test_detect_returns_false_for_empty_dir(tmp_path: Path) -> None:
    assert RustAnalyzer().detect(tmp_path) is False


def test_detect_returns_false_when_path_missing(tmp_path: Path) -> None:
    assert RustAnalyzer().detect(tmp_path / "nope") is False


# ---------- Routes: axum ----------


def test_axum_router_extracts_route_with_method_chain(tmp_path: Path) -> None:
    src = tmp_path / "src" / "main.rs"
    src.parent.mkdir(parents=True)
    src.write_text(
        "use axum::{Router, routing::get};\n"
        "\n"
        "fn app() -> Router {\n"
        '    Router::new()\n'
        '        .route("/users", get(list_users).post(create_user))\n'
        '        .route("/users/:id", get(get_user).delete(delete_user))\n'
        "}\n",
        encoding="utf-8",
    )

    result = RustAnalyzer().analyze(tmp_path)

    pairs = sorted({(r.path, r.method) for r in result.routes})
    assert ("/users", "GET") in pairs
    assert ("/users", "POST") in pairs
    assert ("/users/:id", "GET") in pairs
    assert ("/users/:id", "DELETE") in pairs

    users_post = next(r for r in result.routes if r.path == "/users" and r.method == "POST")
    assert users_post.line == 5  # the .route line


def test_axum_route_with_single_method_helper(tmp_path: Path) -> None:
    src = tmp_path / "src" / "lib.rs"
    src.parent.mkdir(parents=True)
    src.write_text(
        'use axum::{Router, routing::get};\n'
        'pub fn router() -> Router {\n'
        '    Router::new().route("/health", get(health_check))\n'
        '}\n',
        encoding="utf-8",
    )
    result = RustAnalyzer().analyze(tmp_path)
    methods = {(r.path, r.method) for r in result.routes}
    assert ("/health", "GET") in methods


# ---------- Routes: actix-web ----------


def test_actix_attribute_route_extracts_method_and_path(tmp_path: Path) -> None:
    src = tmp_path / "src" / "handlers.rs"
    src.parent.mkdir(parents=True)
    src.write_text(
        'use actix_web::{get, post, web, HttpResponse};\n'
        '\n'
        '#[get("/api/users")]\n'
        'pub async fn list_users() -> HttpResponse { HttpResponse::Ok().finish() }\n'
        '\n'
        '#[post("/api/users")]\n'
        'pub async fn create_user() -> HttpResponse { HttpResponse::Ok().finish() }\n',
        encoding="utf-8",
    )

    result = RustAnalyzer().analyze(tmp_path)
    methods = {(r.path, r.method) for r in result.routes}
    assert ("/api/users", "GET") in methods
    assert ("/api/users", "POST") in methods

    list_route = next(r for r in result.routes if r.method == "GET" and r.path == "/api/users")
    assert list_route.line == 3


def test_actix_web_route_function(tmp_path: Path) -> None:
    src = tmp_path / "src" / "app.rs"
    src.parent.mkdir(parents=True)
    src.write_text(
        'use actix_web::{web, App, HttpServer};\n'
        '\n'
        'fn config(cfg: &mut web::ServiceConfig) {\n'
        '    cfg.route("/admin/login", web::post().to(login));\n'
        '}\n',
        encoding="utf-8",
    )
    result = RustAnalyzer().analyze(tmp_path)
    assert any(r.path == "/admin/login" and r.method == "POST" for r in result.routes)


# ---------- Routes: rocket ----------


def test_rocket_attribute_routes(tmp_path: Path) -> None:
    src = tmp_path / "src" / "rocket_app.rs"
    src.parent.mkdir(parents=True)
    src.write_text(
        'use rocket::{get, post, launch, routes};\n'
        '\n'
        '#[get("/")]\n'
        'fn index() -> &\'static str { "Hello, world!" }\n'
        '\n'
        '#[post("/submit", data = "<body>")]\n'
        'fn submit(body: String) -> &\'static str { "ok" }\n'
        '\n'
        '#[launch]\n'
        'fn rocket() -> _ { rocket::build().mount("/", routes![index, submit]) }\n',
        encoding="utf-8",
    )
    result = RustAnalyzer().analyze(tmp_path)
    pairs = {(r.path, r.method) for r in result.routes}
    assert ("/", "GET") in pairs
    assert ("/submit", "POST") in pairs


# ---------- Databases ----------


def test_sqlx_postgres_emits_postgresql_hint_with_line(tmp_path: Path) -> None:
    src = tmp_path / "src" / "db.rs"
    src.parent.mkdir(parents=True)
    src.write_text(
        "use sqlx::postgres::PgPool;\n"
        "\n"
        "pub async fn pool(url: &str) -> PgPool {\n"
        "    PgPool::connect(url).await.unwrap()\n"
        "}\n",
        encoding="utf-8",
    )
    result = RustAnalyzer().analyze(tmp_path)
    pg = next(d for d in result.databases if d.kind == "postgresql")
    assert pg.line == 1
    assert pg.evidence_text and "sqlx::postgres" in pg.evidence_text.lower()


def test_diesel_mongodb_redis_each_get_distinct_kinds(tmp_path: Path) -> None:
    (tmp_path / "diesel_used.rs").write_text(
        "use diesel::prelude::*;\nfn q() {}\n",
        encoding="utf-8",
    )
    (tmp_path / "mongo_used.rs").write_text(
        "use mongodb::Client;\nasync fn x() { Client::with_uri_str(\"mongodb://x\").await.unwrap(); }\n",
        encoding="utf-8",
    )
    (tmp_path / "redis_used.rs").write_text(
        'use redis::Client; fn x() { let _ = redis::Client::open("redis://x"); }\n',
        encoding="utf-8",
    )

    result = RustAnalyzer().analyze(tmp_path)
    kinds = {d.kind for d in result.databases}
    assert "sql" in kinds  # diesel
    assert "mongodb" in kinds
    assert "redis" in kinds


# ---------- Auth ----------


def test_jsonwebtoken_argon2_oauth2_each_emit_auth_hints_with_high_confidence(tmp_path: Path) -> None:
    (tmp_path / "auth.rs").write_text(
        "use jsonwebtoken::{encode, Header};\n"
        "use argon2::Argon2;\n"
        "use oauth2::basic::BasicClient;\n"
        "fn _x() {}\n",
        encoding="utf-8",
    )
    result = RustAnalyzer().analyze(tmp_path)
    by_hint = {h.hint: h for h in result.auth_hints}
    assert "jwt" in by_hint
    assert "argon2" in by_hint
    assert "oauth" in by_hint
    assert by_hint["argon2"].confidence == 0.9
    assert by_hint["jwt"].confidence == 0.85


def test_low_confidence_for_keyword_only_auth_signals(tmp_path: Path) -> None:
    (tmp_path / "headers.rs").write_text(
        'fn check(headers: &str) { if headers.contains("Authorization") { /* ... */ } }\n',
        encoding="utf-8",
    )
    result = RustAnalyzer().analyze(tmp_path)
    auth_header = next(h for h in result.auth_hints if h.hint == "authorization_header")
    assert auth_header.confidence == 0.6


# ---------- Secrets ----------


def test_std_env_var_secret_extraction(tmp_path: Path) -> None:
    src = tmp_path / "config.rs"
    src.write_text(
        "fn config() {\n"
        '    let _jwt = std::env::var("JWT_SECRET").expect("missing");\n'
        '    let _db = std::env::var("DATABASE_PASSWORD").expect("missing");\n'
        '    let _api = env::var("STRIPE_API_KEY").unwrap();\n'
        "}\n",
        encoding="utf-8",
    )
    result = RustAnalyzer().analyze(tmp_path)
    names = {s.name for s in result.secret_hints}
    assert "JWT_SECRET" in names
    assert "DATABASE_PASSWORD" in names
    assert "STRIPE_API_KEY" in names

    jwt_secret = next(s for s in result.secret_hints if s.name == "JWT_SECRET")
    assert jwt_secret.line == 2
    assert jwt_secret.evidence_text and "JWT_SECRET" in jwt_secret.evidence_text


def test_dotenvy_secret_extraction(tmp_path: Path) -> None:
    (tmp_path / "boot.rs").write_text(
        'fn boot() { let _ = dotenvy::var("OAUTH_CLIENT_SECRET").unwrap(); }\n',
        encoding="utf-8",
    )
    result = RustAnalyzer().analyze(tmp_path)
    assert any(s.name == "OAUTH_CLIENT_SECRET" for s in result.secret_hints)


# ---------- External calls ----------


def test_reqwest_get_emits_external_call(tmp_path: Path) -> None:
    src = tmp_path / "client.rs"
    src.write_text(
        'async fn fetch() {\n'
        '    let _ = reqwest::get("https://api.stripe.com/v1/charges").await;\n'
        '}\n',
        encoding="utf-8",
    )
    result = RustAnalyzer().analyze(tmp_path)
    targets = {e.target for e in result.external_calls}
    assert "https://api.stripe.com/v1/charges" in targets


def test_external_call_skips_relative_paths(tmp_path: Path) -> None:
    """A `.get("foo")` call inside the project shouldn't be treated as an external URL."""
    src = tmp_path / "intra.rs"
    src.write_text(
        'fn lookup(map: &HashMap<String, String>) {\n'
        '    let _ = map.get("api_key");\n'
        '}\n',
        encoding="utf-8",
    )
    result = RustAnalyzer().analyze(tmp_path)
    assert result.external_calls == []


# ---------- Frameworks + entrypoints ----------


def test_framework_and_entrypoint_hints(tmp_path: Path) -> None:
    src = tmp_path / "src" / "main.rs"
    src.parent.mkdir(parents=True)
    src.write_text(
        "use axum::{Router, routing::get};\n"
        "\n"
        "#[tokio::main]\n"
        "async fn main() {\n"
        "    let app = Router::new().route(\"/\", get(|| async { \"hi\" }));\n"
        "    let listener = tokio::net::TcpListener::bind(\"0.0.0.0:3000\").await.unwrap();\n"
        "    axum::serve(listener, app).await.unwrap();\n"
        "}\n",
        encoding="utf-8",
    )
    result = RustAnalyzer().analyze(tmp_path)
    fw = {f.hint for f in result.framework_hints}
    assert "axum" in fw
    assert "tokio" in fw

    ep = {e.hint for e in result.entrypoint_hints}
    assert "axum_serve" in ep
    assert "tokio_main" in ep


def test_actix_main_entrypoint(tmp_path: Path) -> None:
    (tmp_path / "main.rs").write_text(
        "use actix_web::{App, HttpServer};\n"
        "\n"
        "#[actix_web::main]\n"
        'async fn main() -> std::io::Result<()> {\n'
        "    HttpServer::new(|| App::new()).bind(\"127.0.0.1:8080\")?.run().await\n"
        "}\n",
        encoding="utf-8",
    )
    result = RustAnalyzer().analyze(tmp_path)
    ep = {e.hint for e in result.entrypoint_hints}
    assert "actix_main" in ep
    assert "actix_http_server" in ep


# ---------- Cargo metadata → service hints ----------


def test_crate_name_picked_up_as_service_hint(tmp_path: Path) -> None:
    (tmp_path / "Cargo.toml").write_text(
        '[package]\nname = "billing-api"\nversion = "0.1.0"\n',
        encoding="utf-8",
    )
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "lib.rs").write_text("// empty\n", encoding="utf-8")
    result = RustAnalyzer().analyze(tmp_path)
    assert any(h.hint == "crate:billing-api" for h in result.service_hints)


def test_workspace_members_picked_up_as_service_hints(tmp_path: Path) -> None:
    (tmp_path / "Cargo.toml").write_text(
        '[workspace]\nmembers = ["crates/api", "crates/worker"]\n',
        encoding="utf-8",
    )
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "lib.rs").write_text("// empty\n", encoding="utf-8")
    result = RustAnalyzer().analyze(tmp_path)
    hints = {h.hint for h in result.service_hints}
    assert "workspace_member:crates/api" in hints
    assert "workspace_member:crates/worker" in hints


# ---------- End-to-end sanity ----------


def test_full_axum_service_produces_expected_signal_set(tmp_path: Path) -> None:
    (tmp_path / "Cargo.toml").write_text(
        '[package]\nname = "demo-api"\n', encoding="utf-8"
    )
    src = tmp_path / "src" / "main.rs"
    src.parent.mkdir()
    src.write_text(
        "use axum::{Router, routing::{get, post}};\n"
        "use sqlx::postgres::PgPool;\n"
        "use jsonwebtoken::decode;\n"
        "\n"
        "async fn handler() {}\n"
        "\n"
        "#[tokio::main]\n"
        "async fn main() {\n"
        '    let _secret = std::env::var("JWT_SECRET").unwrap();\n'
        '    let _ = reqwest::get("https://api.example.com/data").await;\n'
        '    let app = Router::new().route("/login", post(handler)).route("/me", get(handler));\n'
        "    axum::serve(listener, app).await.unwrap();\n"
        "}\n",
        encoding="utf-8",
    )

    result = RustAnalyzer().analyze(tmp_path)

    assert {(r.path, r.method) for r in result.routes} >= {("/login", "POST"), ("/me", "GET")}
    assert any(d.kind == "postgresql" for d in result.databases)
    assert any(h.hint == "jwt" for h in result.auth_hints)
    assert any(s.name == "JWT_SECRET" for s in result.secret_hints)
    assert any(e.target == "https://api.example.com/data" for e in result.external_calls)
    assert any(f.hint == "axum" for f in result.framework_hints)
    assert any(e.hint == "axum_serve" for e in result.entrypoint_hints)
    assert any(h.hint == "crate:demo-api" for h in result.service_hints)

    # Every emitted signal has either a confidence default or a populated line.
    assert all(r.line is not None for r in result.routes)
    jwt_secret = next(s for s in result.secret_hints if s.name == "JWT_SECRET")
    assert jwt_secret.line is not None
    assert jwt_secret.confidence == 0.85


# ---------- Repo walking (mlaify/AttackMap#253) ----------


def _write_axum_main(repo: Path) -> Path:
    repo.mkdir(parents=True, exist_ok=True)
    main = repo / "main.rs"
    main.write_text(
        "use axum::{Router, routing::get};\n"
        "\n"
        "fn app() -> Router {\n"
        '    Router::new()\n'
        '        .route("/users", get(list_users))\n'
        "}\n",
        encoding="utf-8",
    )
    return main


@pytest.mark.parametrize("parents", [("build", "out"), ("target", ".cargo")])
def test_repo_under_skip_dir_names_is_still_analyzed(tmp_path: Path, parents: tuple[str, str]) -> None:
    # These are skip dirs; they must only count inside the repo.
    repo = tmp_path.joinpath(*parents, "repo")
    _write_axum_main(repo / "src")
    analyzer = RustAnalyzer()
    assert analyzer.detect(repo) is True
    result = analyzer.analyze(repo)
    assert result.files_scanned == 1
    assert ("/users", "GET") in {(r.path, r.method) for r in result.routes}


@pytest.mark.skipif(sys.platform == "win32", reason="symlinks need privileges on Windows")
def test_symlinked_file_outside_repo_is_not_analyzed(tmp_path: Path) -> None:
    target = _write_axum_main(tmp_path / "outside")
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "linked.rs").symlink_to(target)
    analyzer = RustAnalyzer()
    assert analyzer.detect(repo) is False
    result = analyzer.analyze(repo)
    assert result.files_scanned == 0
    assert result.routes == []


# ---------- Route.auth contract (AttackMap#256) ----------


def _analyze_files(tmp_path: Path, files: dict[str, str]) -> dict:
    for name, source in files.items():
        target = tmp_path / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(source, encoding="utf-8")
    return {f"{r.method} {r.path}": r for r in RustAnalyzer().analyze(tmp_path).routes}


_AXUM_MAIN = """
use axum::{middleware, routing::{get, post, delete}, Router};
use tower_http::trace::TraceLayer;

mod handlers;

fn protected_routes() -> Router<AppState> {
    Router::new()
        .route("/posts", post(handlers::create_post))
        .route("/posts/:id", delete(handlers::delete_post))
        .route_layer(middleware::from_fn_with_state(state.clone(), require_auth))
        // Added after the route_layer, so outside it:
        .route("/posts/preview", post(handlers::preview_post))
}

#[tokio::main]
async fn main() {
    let app = Router::new()
        .route("/health", get(health))
        .route("/comments", post(handlers::create_comment))
        .route("/me", post(handlers::update_me))
        .merge(protected_routes())
        .layer(TraceLayer::new_for_http());
    axum::serve(listener, app).await.unwrap();
}
"""

_AXUM_HANDLERS = """
pub async fn create_post(State(s): State<AppState>, Json(p): Json<NewPost>) -> impl IntoResponse {}
pub async fn delete_post(Path(id): Path<i64>) -> impl IntoResponse {}
pub async fn preview_post(claims: Option<Claims>, Json(p): Json<NewPost>) -> impl IntoResponse {}
pub async fn create_comment(user: Option<AuthUser>, Json(c): Json<NewComment>) -> impl IntoResponse {}
pub async fn update_me(claims: Claims, Json(b): Json<Me>) -> impl IntoResponse {}
"""


def test_axum_route_layer_and_extractor_guards_are_required(tmp_path: Path) -> None:
    routes = _analyze_files(tmp_path, {"src/main.rs": _AXUM_MAIN, "src/handlers.rs": _AXUM_HANDLERS})
    # route_layer in a router returned by fn and merged into the app.
    create = routes["POST /posts"]
    assert create.auth == "required"
    assert create.guards == ["from_fn_with_state(require_auth)"]
    assert create.guard_evidence == ".route_layer(middleware::from_fn_with_state(state.clone(), require_auth))"
    assert routes["DELETE /posts/:id"].auth == "required"
    # An auth extractor on the handler (defined in another file).
    me = routes["POST /me"]
    assert me.auth == "required"
    assert me.guards == ["Claims"]
    assert me.guard_evidence == "claims: Claims"
    assert routes["GET /health"].auth == "unknown"


def test_axum_optional_extractor_is_explicitly_public(tmp_path: Path) -> None:
    routes = _analyze_files(tmp_path, {"src/main.rs": _AXUM_MAIN, "src/handlers.rs": _AXUM_HANDLERS})
    comment = routes["POST /comments"]
    assert comment.auth == "anonymous"
    assert comment.guards == []
    assert comment.guard_evidence == "user: Option<AuthUser>"


def test_axum_route_after_route_layer_opts_out_of_it(tmp_path: Path) -> None:
    routes = _analyze_files(tmp_path, {"src/main.rs": _AXUM_MAIN, "src/handlers.rs": _AXUM_HANDLERS})
    # Same router as the guarded /posts, but registered after the route_layer.
    preview = routes["POST /posts/preview"]
    assert preview.auth == "anonymous"
    assert preview.guard_evidence == "claims: Option<Claims>"


def test_axum_unrecognised_or_hidden_layers_keep_optional_routes_unknown(tmp_path: Path) -> None:
    routes = _analyze_files(
        tmp_path,
        {
            "src/main.rs": """
use axum::{middleware, routing::post, Router};
async fn feed(user: Option<AuthUser>) {}
async fn inbox(user: Option<AuthUser>) {}
async fn login(session: AuthSession) {}
fn main() {
    let a = Router::new()
        .route("/feed", post(feed))
        .layer(middleware::from_fn(check_request));
    let b = Router::new().route("/inbox", post(inbox)).route("/login", post(login));
    let b = b.layer(AuthManagerLayerBuilder::new(backend, session_layer).build());
    let c = b.layer(some_layer);
}
""",
        },
    )
    # An unknown from_fn layer could be auth: an Option<..> handler isn't proof of public.
    assert routes["POST /feed"].auth == "unknown"
    # `b` is re-layered outside its chain, so its full layer path isn't visible.
    assert routes["POST /inbox"].auth == "unknown"
    # axum-login's AuthSession only loads the user; it doesn't reject.
    assert routes["POST /login"].auth == "unknown"


def test_actix_scope_wrap_and_optional_identity(tmp_path: Path) -> None:
    routes = _analyze_files(
        tmp_path,
        {
            "src/main.rs": """
use actix_web::{web, App, HttpServer, post, put};
use actix_web_httpauth::middleware::HttpAuthentication;

#[post("/signup")]
async fn signup(form: web::Json<Signup>, ident: Option<Identity>) -> HttpResponse { todo!() }

#[put("/account")]
async fn account(body: web::Json<Account>) -> HttpResponse { todo!() }

#[actix_web::main]
async fn main() {
    HttpServer::new(|| {
        App::new()
            .wrap(Logger::default())
            .service(signup)
            .service(web::scope("/api").wrap(HttpAuthentication::bearer(validator)).service(account)
                .route("/tokens", web::post().to(issue_token)))
    }).bind(("0.0.0.0", 8080)).unwrap().run().await
}
""",
        },
    )
    account = routes["PUT /account"]
    assert account.auth == "required"
    assert account.guards == ["HttpAuthentication::bearer"]
    assert account.guard_evidence == ".wrap(HttpAuthentication::bearer(validator))"
    assert routes["POST /tokens"].auth == "required"
    assert routes["POST /signup"].auth == "anonymous"
    assert routes["POST /signup"].guard_evidence == "ident: Option<Identity>"


def test_rocket_request_guards(tmp_path: Path) -> None:
    routes = _analyze_files(
        tmp_path,
        {
            "src/main.rs": """
use rocket::*;

#[post("/notes", data = "<note>")]
fn create_note(user: AuthUser, note: Json<Note>) -> Status { Status::Ok }

#[post("/guestbook", data = "<entry>")]
fn sign(user: Option<AuthUser>, entry: Json<Entry>) -> Status { Status::Ok }

#[delete("/admin/<admin_id>")]
fn remove(admin_id: AdminId) -> Status { Status::Ok }

#[launch]
fn rocket() -> _ { rocket::build() }
""",
        },
    )
    assert routes["POST /notes"].auth == "required"
    assert routes["POST /notes"].guards == ["AuthUser"]
    assert routes["POST /guestbook"].auth == "anonymous"
    # `admin_id` is bound from the path, not a request guard.
    assert routes["DELETE /admin/<admin_id>"].auth == "unknown"
