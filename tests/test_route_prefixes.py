"""Route prefixes (nest / scope / mount), more frameworks and extractor auth (#2).

Each test writes realistic Rust into tmp_path and asserts on the routes
``RustAnalyzer.analyze`` emits, keyed ``"METHOD /path"``.
"""

from __future__ import annotations

import random
import time
from pathlib import Path

from attackmap_analyzer_rust import RustAnalyzer


def _routes(tmp_path: Path, files: dict[str, str]) -> dict:
    for name, source in files.items():
        target = tmp_path / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(source, encoding="utf-8")
    return {f"{r.method} {r.path}": r for r in RustAnalyzer().analyze(tmp_path).routes}


# ---------- axum ----------

_AXUM_MAIN = """
use axum::{middleware, routing::{get, post}, Router};
mod users;
mod posts;
mod admin;

#[tokio::main]
async fn main() {
    let health = Router::new().route("/health", get(health));
    let api = Router::new()
        .nest("/users", users::routes())
        .nest("/posts", posts::routes(state.clone()))
        .nest("/v1", Router::new().route("/ping", get(ping)));
    let app = Router::new()
        .merge(health)
        .nest("/api", api)
        .nest("/admin", admin::router())
        .route_layer(middleware::from_fn(require_auth))
        .nest("/preview", admin::router());
    axum::serve(listener, app).await.unwrap();
}
"""

_AXUM_USERS = """
use axum::{routing::{get, post}, Router};

pub fn routes() -> Router<AppState> {
    async fn local_helper() {}

    #[allow(deprecated)]
    Router::new()
        .route("/", get(list).post(create))
        .route("/{id}", get(show))
}
"""

_AXUM_POSTS = """
pub fn routes(state: AppState) -> Router {
    let router = Router::new().route("/", get(list_posts));
    router
}
"""

_AXUM_ADMIN = """
pub fn router() -> Router {
    Router::new().route("/stats", get(stats))
}
"""


def _axum(tmp_path: Path) -> dict:
    return _routes(
        tmp_path,
        {
            "src/main.rs": _AXUM_MAIN,
            "src/users.rs": _AXUM_USERS,
            "src/posts.rs": _AXUM_POSTS,
            "src/admin/mod.rs": _AXUM_ADMIN,
        },
    )


def test_axum_nest_joins_prefixes_across_files(tmp_path: Path) -> None:
    routes = _axum(tmp_path)
    # `users::routes()` is resolved to users.rs (several fns named `routes` exist)
    # and is nested under "/users" in `api`, itself nested under "/api".
    assert {"GET /api/users", "POST /api/users", "GET /api/users/{id}"} <= set(routes)
    assert "GET /{id}" not in routes
    # Inline router in a nest argument.
    assert "GET /api/v1/ping" in routes
    # merge adds no prefix.
    assert "GET /health" in routes
    # `admin::router()` lives in admin/mod.rs.
    assert routes["GET /admin/stats"].line == 3


def test_axum_router_nested_twice_gets_both_prefixes_and_its_own_layers(tmp_path: Path) -> None:
    routes = _axum(tmp_path)
    # The route_layer wraps what was added before it: /admin, not /preview.
    admin = routes["GET /admin/stats"]
    assert admin.auth == "required"
    assert admin.guards == ["from_fn(require_auth)"]
    assert routes["GET /preview/stats"].auth == "unknown"
    assert routes["GET /api/users"].auth == "required"


def test_axum_unresolved_mounts_keep_the_local_path(tmp_path: Path) -> None:
    routes = _routes(
        tmp_path,
        {
            "src/main.rs": """
fn main() {
    let app = Router::new()
        .nest(&format!("/{}", base), Router::new().route("/dynamic", get(h)))
        .nest("/a", routes());
}
""",
            # Two `fn routes` in other files, neither qualified nor in main.rs:
            # the mount is ambiguous, so neither gets "/a".
            "src/one.rs": 'pub fn routes() -> Router { Router::new().route("/one", get(h)) }\n',
            "src/two.rs": 'pub fn routes() -> Router { Router::new().route("/two", get(h)) }\n',
        },
    )
    assert "GET /dynamic" in routes
    assert {"GET /one", "GET /two"} <= set(routes)
    assert not any(key.startswith("GET /a/") for key in routes)


def test_axum_let_binding_resolves_to_the_nearest_earlier_one(tmp_path: Path) -> None:
    routes = _routes(
        tmp_path,
        {
            "src/main.rs": """
fn a() {
    let api = Router::new().route("/first", get(h));
    let app = Router::new().nest("/one", api);
}
fn b() {
    let api = Router::new().route("/second", get(h));
    let app = Router::new().nest("/two", api);
}
""",
        },
    )
    assert {"GET /one/first", "GET /two/second"} <= set(routes)
    assert "GET /two/first" not in routes and "GET /one/second" not in routes


# ---------- actix-web ----------

_ACTIX_MAIN = """
use actix_web::{web, App, HttpServer, http::Method};
mod handlers;
mod users;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    HttpServer::new(|| {
        App::new()
            .service(handlers::index)
            .service(
                web::scope("/api/v1")
                    .wrap(HttpAuthentication::bearer(validator))
                    .configure(users::config)
                    .service(handlers::me)
                    .service(web::resource("/items/{id}")
                        .route(web::get().to(get_item))
                        .route(web::method(Method::PUT).to(put_item)))
                    .route("", web::get().to(api_root)),
            )
    })
    .bind(("0.0.0.0", 8080))?
    .run()
    .await
}
"""

_ACTIX_HANDLERS = """
use actix_web::{get, HttpResponse};

#[get("/")]
pub async fn index() -> HttpResponse { todo!() }

#[get("/me")]
pub async fn me() -> HttpResponse { todo!() }

#[get("/orphan")]
pub async fn orphan() -> HttpResponse { todo!() }
"""

_ACTIX_USERS = """
use actix_web::web::{self, scope, resource, get, post, ServiceConfig};

pub fn config(cfg: &mut ServiceConfig) {
    cfg.service(
        scope("/users")
            .service(resource("").route(get().to(list)).route(post().to(create)))
            .route("/{id}", get().to(show)),
    );
}
"""


def _actix(tmp_path: Path) -> dict:
    return _routes(
        tmp_path,
        {"src/main.rs": _ACTIX_MAIN, "src/handlers.rs": _ACTIX_HANDLERS, "src/users.rs": _ACTIX_USERS},
    )


def test_actix_scopes_resources_and_configure_join_prefixes(tmp_path: Path) -> None:
    routes = _actix(tmp_path)
    # web::resource inside web::scope; `.route(web::method(Method::PUT)..)`.
    assert {"GET /api/v1/items/{id}", "PUT /api/v1/items/{id}"} <= set(routes)
    # An empty scope route is the scope itself.
    assert "GET /api/v1" in routes
    # `.configure(users::config)` inside the scope; bare `scope`/`resource`/`get()`
    # are actix's because users.rs imports them from actix_web.
    assert {"GET /api/v1/users", "POST /api/v1/users", "GET /api/v1/users/{id}"} <= set(routes)
    # Attribute handlers take the prefix of the scope that mounts them.
    assert "GET /api/v1/me" in routes and "GET /me" not in routes
    assert "GET /" in routes
    # Not mounted anywhere visible: its own path.
    assert "GET /orphan" in routes


def test_actix_scope_wrap_covers_resources_configured_routes_and_services(tmp_path: Path) -> None:
    routes = _actix(tmp_path)
    for key in ("GET /api/v1/items/{id}", "GET /api/v1/users", "GET /api/v1/users/{id}", "GET /api/v1/me"):
        assert routes[key].auth == "required", key
        assert routes[key].guards == ["HttpAuthentication::bearer"]
    assert routes["GET /"].auth == "unknown"


def test_bare_scope_without_actix_import_is_not_a_scope(tmp_path: Path) -> None:
    routes = _routes(
        tmp_path,
        {
            "src/main.rs": """
use actix_web::web;
fn telemetry() { let s = scope("/ignored"); }
fn main() { App::new().service(web::scope("/real").route("/x", web::get().to(h))); }
""",
        },
    )
    assert "GET /real/x" in routes
    assert not any("/ignored" in key for key in routes)


# ---------- rocket ----------


def test_rocket_mount_prefixes_by_handler_name(tmp_path: Path) -> None:
    routes = _routes(
        tmp_path,
        {
            "src/main.rs": """
#[macro_use] extern crate rocket;
mod admin;

#[get("/")]
fn index() -> &'static str { "hi" }

#[post("/notes", data = "<note>")]
fn create_note(user: AuthUser, note: Json<Note>) -> Status { Status::Ok }

#[get("/unmounted")]
fn unmounted() -> &'static str { "" }

#[launch]
fn rocket() -> _ {
    rocket::build()
        .mount("/", routes![index])
        .mount("/api", routes![create_note, index])
        .mount("/admin", admin::routes())
}
""",
            "src/admin.rs": """
use rocket::*;

#[delete("/users/<id>")]
fn remove(id: u32) -> Status { Status::Ok }

pub fn routes() -> Vec<Route> { routes![remove] }
""",
        },
    )
    assert {"GET /", "GET /api", "POST /api/notes", "DELETE /admin/users/<id>", "GET /unmounted"} <= set(routes)
    assert "POST /notes" not in routes
    # No visible FromRequest impl for AuthUser: not proof of auth.
    assert routes["POST /api/notes"].auth == "unknown"


# ---------- poem / salvo / loco ----------


def test_poem_route_at_and_nest(tmp_path: Path) -> None:
    routes = _routes(
        tmp_path,
        {
            "src/main.rs": """
use poem::{get, handler, post, Route, EndpointExt};

fn api() -> Route {
    Route::new()
        .at("/users", get(list_users).post(create_user))
        .at("/users/:id", get(get_user))
        .with(JwtAuth::new(key))
}

#[tokio::main]
async fn main() {
    let app = Route::new().at("/", index).nest("/api", api());
    poem::Server::new(TcpListener::bind("0.0.0.0:3000")).run(app).await
}
""",
        },
    )
    assert {"ANY /", "GET /api/users", "POST /api/users", "GET /api/users/:id"} <= set(routes)
    assert routes["GET /api/users"].auth == "required"
    assert routes["ANY /"].auth == "unknown"


def test_salvo_with_path_push_and_hoop(tmp_path: Path) -> None:
    routes = _routes(
        tmp_path,
        {
            "src/main.rs": """
use salvo::prelude::*;

#[tokio::main]
async fn main() {
    let users = Router::with_path("users")
        .hoop(auth_check)
        .get(list_users)
        .post(create_user)
        .push(Router::with_path("{id}").get(show_user).delete(delete_user));
    let router = Router::new()
        .get(index)
        .push(Router::with_path("api").push(users));
    Server::new(acceptor).serve(router).await;
}
""",
        },
    )
    assert {"GET /", "GET /api/users", "POST /api/users", "GET /api/users/{id}", "DELETE /api/users/{id}"} <= set(
        routes
    )
    # hoop covers the router and everything pushed into it.
    assert routes["DELETE /api/users/{id}"].auth == "required"
    assert routes["GET /"].auth == "unknown"


def test_loco_routes_prefix_and_app_routes(tmp_path: Path) -> None:
    routes = _routes(
        tmp_path,
        {
            "src/controllers/notes.rs": """
use loco_rs::prelude::*;

pub async fn list(State(ctx): State<AppContext>) -> Result<Response> { todo!() }
pub async fn remove(auth: auth::JWT, Path(id): Path<i32>) -> Result<Response> { todo!() }

pub fn routes() -> Routes {
    Routes::new()
        .prefix("notes")
        .add("/", get(list))
        .add("/{id}", get(get_one).delete(remove))
}
""",
            "src/app.rs": """
use loco_rs::{controller::AppRoutes, prelude::*};

fn routes(_ctx: &AppContext) -> AppRoutes {
    AppRoutes::with_default_routes()
        .prefix("/api")
        .add_route(controllers::notes::routes())
}
""",
        },
    )
    assert {"GET /api/notes", "GET /api/notes/{id}", "DELETE /api/notes/{id}"} <= set(routes)
    # loco's auth::JWT extractor rejects anonymous callers.
    assert routes["DELETE /api/notes/{id}"].auth == "required"
    assert routes["DELETE /api/notes/{id}"].guards == ["JWT"]


# ---------- warp / tide ----------


def test_warp_path_macro_routes(tmp_path: Path) -> None:
    routes = _routes(
        tmp_path,
        {
            "src/filters.rs": """
use warp::Filter;

pub fn todos_list() -> impl Filter<Extract = (impl warp::Reply,), Error = warp::Rejection> + Clone {
    warp::path!("todos")
        .and(warp::get())
        .and(warp::query::<ListOptions>())
        .and_then(handlers::list_todos)
}

pub fn todos_update() -> impl Filter<Extract = (impl warp::Reply,), Error = warp::Rejection> + Clone {
    warp::put().and(warp::path!("todos" / u64)).and(json_body()).and_then(handlers::update_todo)
}

pub fn hello() -> impl Filter<Extract = (impl warp::Reply,), Error = warp::Rejection> + Clone {
    warp::path!("hello" / String).map(|name| format!("Hello, {}!", name))
}

pub fn api() -> impl Filter<Extract = (impl warp::Reply,), Error = warp::Rejection> + Clone {
    // A prefix filter, and a path! under another filter: neither is a full route.
    warp::path!("api" / ..).and(warp::path("v1").and(warp::path!("nested")))
}
""",
        },
    )
    assert {"GET /todos", "PUT /todos/{u64}", "ANY /hello/{String}"} <= set(routes)
    assert not any("api" in key or "nested" in key for key in routes)


def test_tide_at_chains_and_bound_prefixes(tmp_path: Path) -> None:
    routes = _routes(
        tmp_path,
        {
            "src/main.rs": """
#[async_std::main]
async fn main() -> tide::Result<()> {
    let mut app = tide::new();
    app.at("/").get(index);
    app.at("/users").get(list_users).post(create_user);
    app.at("/users").at("/:id").get(get_user).delete(delete_user);
    let mut api = app.at("/api");
    api.at("/items/:id").put(update_item);
    app.at("/any").all(catch_all);
    app.listen("127.0.0.1:8080").await?;
    Ok(())
}
""",
        },
    )
    assert {
        "GET /",
        "GET /users",
        "POST /users",
        "GET /users/:id",
        "DELETE /users/:id",
        "PUT /api/items/:id",
        "ANY /any",
    } <= set(routes)
    assert "PUT /items/:id" not in routes


def test_tide_and_warp_need_their_crate(tmp_path: Path) -> None:
    routes = _routes(
        tmp_path,
        {
            "src/main.rs": """
fn main() {
    calendar.at("/2026").get(day);
    let p = path!("x" / "y");
}
""",
        },
    )
    assert routes == {}


# ---------- Extractor auth needs a visible, fallible impl ----------


def test_extractor_auth_requires_a_visible_fallible_impl(tmp_path: Path) -> None:
    routes = _routes(
        tmp_path,
        {
            "src/main.rs": """
use axum::{routing::{get, post}, Router};

async fn visible(user: AuthUser) {}
async fn invisible(user: CurrentUser) {}
async fn never_rejects(user: MaybeAdmin) {}
async fn bearer(auth: BearerAuth) {}

fn main() {
    let app = Router::new()
        .route("/visible", get(visible))
        .route("/invisible", get(invisible))
        .route("/never", get(never_rejects))
        .route("/bearer", post(bearer));
}
""",
            "src/extract.rs": """
impl<S> FromRequestParts<S> for AuthUser
where
    S: Send + Sync,
{
    type Rejection = AuthError;
    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let header = parts.headers.get(AUTHORIZATION).ok_or(AuthError::Missing)?;
        todo!()
    }
}

impl<S: Send + Sync> FromRequestParts<S> for MaybeAdmin {
    type Rejection = std::convert::Infallible;
    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> { todo!() }
}
""",
        },
    )
    assert routes["GET /visible"].auth == "required"
    assert routes["GET /visible"].guards == ["AuthUser"]
    # Named like auth but its impl isn't in the repo.
    assert routes["GET /invisible"].auth == "unknown"
    # Its impl can't reject.
    assert routes["GET /never"].auth == "unknown"
    # A well-known library extractor (actix-web-httpauth).
    assert routes["POST /bearer"].auth == "required"


# ---------- Bounds ----------


def _fixtures() -> list[str]:
    return [
        _AXUM_MAIN,
        _AXUM_USERS,
        _AXUM_POSTS,
        _ACTIX_MAIN,
        _ACTIX_USERS,
        _ACTIX_HANDLERS,
        'use salvo::*;\nfn r() { Router::with_path("a").hoop(x).get(h).push(Router::with_path("b").post(p)); }\n',
        'use poem::*;\nfn r() -> Route { Route::new().at("/a", get(h)).nest("/b", api()).with(Auth) }\n',
        'fn routes() -> Routes { Routes::new().prefix("x").add("/", get(l)) }\n'
        'fn app() { AppRoutes::empty().prefix("/a").add_route(routes()) }\n',
        'use warp::Filter;\nfn f() { warp::get().and(warp::path!("a" / u32 / "b")).and_then(h) }\n',
        'fn main() { let mut app = tide::new(); let mut a = app.at("/a"); a.at("/b").get(h); }\n',
        'use rocket::*;\n#[get("/x")] fn x() {}\nfn r() { rocket::build().mount("/p", routes![x]); }\n',
    ]


def test_scanners_survive_truncated_and_mutated_input(tmp_path: Path) -> None:
    rng = random.Random(2)
    alphabet = '()[]{}<>"\'/\\.,;:!|#&*=-_ \nabrRouteApwebscopeget'
    analyzer = RustAnalyzer()
    for i in range(160):
        source = rng.choice(_fixtures())
        if i % 3 == 0:
            source = source[: rng.randrange(len(source) + 1)]
        elif i % 3 == 1:
            chars = list(source)
            for _ in range(rng.randrange(1, 40)):
                chars[rng.randrange(len(chars))] = rng.choice(alphabet)
            source = "".join(chars)
        else:
            source = "".join(rng.choice(alphabet) for _ in range(rng.randrange(1, 400)))
        repo = tmp_path / f"r{i}"
        (repo / "src").mkdir(parents=True)
        (repo / "src" / "main.rs").write_text(source, encoding="utf-8")
        (repo / "src" / "other.rs").write_text(rng.choice(_fixtures()), encoding="utf-8")
        analyzer.analyze(repo)  # must not raise


def test_adversarial_nesting_and_fan_in_stay_fast(tmp_path: Path) -> None:
    depth = 3000
    nested = "".join(f'.nest("/n{i}", Router::new()' for i in range(depth)) + ".route(\"/leaf\", get(h))" + ")" * depth
    fan_in = "\n".join(f'fn m{i}() {{ let a = Router::new().nest("/p{i}", routes()).merge(routes()); }}' for i in range(800))
    defs = "\n".join(f'mod x{i} {{ pub fn routes() -> Router {{ Router::new().route("/r{i}", get(h)) }} }}' for i in range(400))
    scopes = "use actix_web::web::*;\nfn c() { App::new()" + ".service(scope(\"/s\")" * 1500 + ")" * 1500 + "; }\n"
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "nested.rs").write_text("fn main() { let app = Router::new()" + nested + "; }\n", encoding="utf-8")
    (tmp_path / "src" / "fan.rs").write_text(fan_in + "\n" + defs, encoding="utf-8")
    (tmp_path / "src" / "scopes.rs").write_text(scopes, encoding="utf-8")
    started = time.monotonic()
    result = RustAnalyzer().analyze(tmp_path)
    assert time.monotonic() - started < 20
    # The nested leaf is past the depth bound: emitted, with a bounded prefix.
    leaf = [r for r in result.routes if r.path.endswith("/leaf")]
    assert len(leaf) == 1 and leaf[0].path.count("/") <= 18


# ---------- Review fixes ----------

_OPTIONAL_USER = """
async fn opt(user: Option<AuthUser>) {}
impl<S: Send + Sync> FromRequestParts<S> for AuthUser {
    type Rejection = StatusCode;
    async fn from_request_parts(parts: &mut Parts, _: &S) -> Result<Self, StatusCode> {
        parts.headers.get(AUTHORIZATION).ok_or(StatusCode::UNAUTHORIZED)?;
        todo!()
    }
}
"""


def test_let_binding_in_another_fn_is_not_a_mount(tmp_path: Path) -> None:
    routes = _routes(
        tmp_path,
        {
            "src/main.rs": _OPTIONAL_USER
            + """
use axum::{middleware, routing::get, Router};
fn public_routes() -> Router {
    let api = Router::new().route("/feed", get(opt));
    api
}
fn protected(api: Router) -> Router {
    // `api` is this fn's parameter, not public_routes()'s binding.
    Router::new().nest("/admin", api).route_layer(middleware::from_fn(require_auth))
}
""",
        },
    )
    assert "GET /admin/feed" not in routes
    assert routes["GET /feed"].auth == "unknown"


def test_unseen_mounts_and_dynamic_prefixes_are_not_known_roots(tmp_path: Path) -> None:
    routes = _routes(
        tmp_path,
        {
            "src/main.rs": _OPTIONAL_USER
            + """
use axum::{routing::get, Router};
fn api_routes() -> Router { Router::new().route("/me", get(opt)) }
fn build(r: Router) -> Router { Router::new().nest("/api", r).route_layer(from_fn(require_auth)) }

#[tokio::main]
async fn main() {
    let other = build(api_routes());
    let app = Router::new()
        .route("/public", get(opt))
        .nest(&format!("/{}", base), Router::new().route("/dynamic", get(opt)));
    axum::serve(listener, app).await.unwrap();
}
""",
        },
    )
    # Mounted through `build(..)`, which isn't visible as a mount: not a known root.
    assert routes["GET /me"].auth == "unknown"
    # Under a non-literal prefix.
    assert routes["GET /dynamic"].auth == "unknown"
    # The served root itself is fully seen.
    assert routes["GET /public"].auth == "anonymous"


def test_rejecting_extractor_without_credential_checks_is_not_auth(tmp_path: Path) -> None:
    routes = _routes(
        tmp_path,
        {
            "src/main.rs": """
use axum::{routing::get, Router};
async fn list(filters: AdminFilters) {}
impl<S: Send + Sync> FromRequestParts<S> for AdminFilters {
    type Rejection = StatusCode;
    async fn from_request_parts(parts: &mut Parts, _: &S) -> Result<Self, StatusCode> {
        let query = parts.uri.query().ok_or(StatusCode::BAD_REQUEST)?;
        serde_urlencoded::from_str(query).map_err(|_| StatusCode::BAD_REQUEST)
    }
}
fn main() { let app = Router::new().route("/admin/users", get(list)); axum::serve(l, app); }
""",
        },
    )
    assert routes["GET /admin/users"].auth == "unknown"


def test_salvo_word_in_a_comment_keeps_axum_parsing(tmp_path: Path) -> None:
    routes = _routes(
        tmp_path,
        {
            "src/routes.rs": """
use crate::prelude::*; // unlike salvo, routers here nest by prefix
fn app() -> Router { Router::new().nest("/api", Router::new().route("/x", get(h))) }
""",
        },
    )
    assert "GET /api/x" in routes


def test_rebinding_continues_the_router(tmp_path: Path) -> None:
    routes = _routes(
        tmp_path,
        {
            "src/main.rs": """
use axum::{middleware, routing::get, Router};
fn main() {
    let api = Router::new().route("/a", get(a));
    let api = api.route("/b", get(b)).route_layer(middleware::from_fn(require_auth));
    let app = Router::new().nest("/api/", api).nest("/root/", Router::new().route("/", get(r)));
    axum::serve(listener, app);
}
""",
        },
    )
    assert routes["GET /api/a"].auth == "required"
    assert routes["GET /api/b"].auth == "required"
    # "/root/" + "/" is "/root".
    assert "GET /root" in routes and "GET /root/" not in routes


def test_many_tide_bindings_stay_fast(tmp_path: Path) -> None:
    n = 20000
    source = "use tide;\nfn main() {\n" + "".join(
        f'    let mut a = app.at("/p{i}");\n    a.at("/x").get(h);\n' for i in range(n)
    ) + "}\n"
    (tmp_path / "main.rs").write_text(source, encoding="utf-8")
    started = time.monotonic()
    result = RustAnalyzer().analyze(tmp_path)
    # Each receiver lookup is a bisect, not a scan of every binding, and
    # route dedup is a set lookup.
    assert time.monotonic() - started < 8
    assert any(r.path == f"/p{n - 1}/x" for r in result.routes)


def test_many_router_definitions_and_mounts_stay_fast(tmp_path: Path) -> None:
    # 200 `fn routes()` in m0.rs..m199.rs, mounted 3000 times (15 each, under the per-router bound) as `mN::routes()`.
    for i in range(200):
        (tmp_path / f"m{i}.rs").write_text(
            f'pub fn routes() -> Router {{ Router::new().route("/r{i}", get(h)) }}\n', encoding="utf-8"
        )
    mounts = "fn app() {\n" + "".join(f'    let a{i} = Router::new().nest("/p", m{i % 200}::routes());\n' for i in range(3000)) + "}\n"
    (tmp_path / "main.rs").write_text("use axum::Router;\n" + mounts, encoding="utf-8")
    started = time.monotonic()
    result = RustAnalyzer().analyze(tmp_path)
    assert time.monotonic() - started < 8
    assert any(r.path == "/p/r199" for r in result.routes)


def test_pick_definition_is_memoized_per_name_qualifier_and_file(tmp_path: Path, monkeypatch) -> None:
    from attackmap_analyzer_rust import routing

    calls = []
    real = routing.pick_definition

    def counting(defs, ref, from_file):
        calls.append((ref.name, ref.qualifier, from_file))
        return real(defs, ref, from_file)

    monkeypatch.setattr(routing, "pick_definition", counting)
    for i in range(3):
        (tmp_path / f"m{i}.rs").write_text(f'pub fn routes() -> Router {{ Router::new().route("/r{i}", get(h)) }}\n')
    mounts = "".join(f'    let a{i} = Router::new().nest("/p{i}", m{i % 3}::routes());\n' for i in range(12))
    (tmp_path / "main.rs").write_text("use axum::Router;\nfn app() {\n" + mounts + "}\n")
    routes = {r.path for r in RustAnalyzer().analyze(tmp_path).routes}
    assert {"/p0/r0", "/p4/r1", "/p11/r2"} <= routes
    mount_calls = [c for c in calls if c[0] == "routes"]
    assert len(mount_calls) == len(set(mount_calls)) == 3


_REALWORLD_EXTRACTORS = """
pub struct AuthUser { pub user_id: Uuid }
pub struct MaybeAuthUser(pub Option<AuthUser>);

impl<S> FromRequestParts<S> for AuthUser where S: Send + Sync {
    type Rejection = Error;
    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let ctx: Extension<ApiContext> = Extension::from_request_parts(parts, state).await.expect("ctx");
        let auth_header = parts.headers.get(AUTHORIZATION).ok_or(Error::Unauthorized)?;
        Self::from_authorization(&ctx, auth_header)
    }
}

impl<S> FromRequestParts<S> for MaybeAuthUser where S: Send + Sync {
    type Rejection = Error;
    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let ctx: Extension<ApiContext> = Extension::from_request_parts(parts, state).await.expect("ctx");
        Ok(Self(
            parts.headers.get(AUTHORIZATION)
                .map(|auth_header| AuthUser::from_authorization(&ctx, auth_header))
                .transpose()?,
        ))
    }
}
"""


def test_optional_user_extractor_is_not_a_guard(tmp_path: Path) -> None:
    routes = _routes(
        tmp_path,
        {
            "src/http/extractor.rs": _REALWORLD_EXTRACTORS,
            "src/http/profiles.rs": """
use axum::{routing::{get, post}, Router};
pub(crate) fn router() -> Router {
    Router::new()
        .route("/api/profiles/:username", get(get_user_profile))
        .route("/api/profiles/:username/follow", post(follow_user))
}
async fn get_user_profile(maybe_auth_user: MaybeAuthUser, Path(username): Path<String>) {}
async fn follow_user(auth_user: AuthUser, Path(username): Path<String>) {}
""",
        },
    )
    # Only parses a token when one is sent; anonymous callers get through.
    assert routes["GET /api/profiles/:username"].auth == "unknown"
    # `ok_or(Error::Unauthorized)?` on a missing header rejects them.
    assert routes["POST /api/profiles/:username/follow"].auth == "required"
    assert routes["POST /api/profiles/:username/follow"].guards == ["AuthUser"]


def test_extractor_must_reject_missing_credentials(tmp_path: Path) -> None:
    routes = _routes(
        tmp_path,
        {
            "src/main.rs": """
use axum::{routing::get, Router};
async fn a(user: CurrentUser) {}
async fn b(user: OptionalAuth) {}
async fn c(user: SessionUser) {}
fn main() { let app = Router::new().route("/a", get(a)).route("/b", get(b)).route("/c", get(c)); axum::serve(l, app); }

// Reads the cookie but never rejects when it's absent.
impl<S: Send + Sync> FromRequestParts<S> for CurrentUser {
    type Rejection = StatusCode;
    async fn from_request_parts(parts: &mut Parts, _: &S) -> Result<Self, StatusCode> {
        let jar = CookieJar::from_headers(&parts.headers);
        Ok(Self(jar.get("sid").map(|c| c.value().to_owned())))
    }
}

// Rejects, but its name says it's optional.
impl<S: Send + Sync> FromRequestParts<S> for OptionalAuth {
    type Rejection = StatusCode;
    async fn from_request_parts(parts: &mut Parts, _: &S) -> Result<Self, StatusCode> {
        parts.headers.get(AUTHORIZATION).ok_or(StatusCode::UNAUTHORIZED)?;
        todo!()
    }
}

// Early return when the session cookie is absent.
impl<S: Send + Sync> FromRequestParts<S> for SessionUser {
    type Rejection = Response;
    async fn from_request_parts(parts: &mut Parts, _: &S) -> Result<Self, Response> {
        let Some(cookie) = parts.headers.get(COOKIE) else {
            return Err(Redirect::to("/login").into_response());
        };
        todo!()
    }
}
""",
        },
    )
    assert routes["GET /a"].auth == "unknown"
    assert routes["GET /b"].auth == "unknown"
    assert routes["GET /c"].auth == "required"
