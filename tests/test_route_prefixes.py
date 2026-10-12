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
    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> { todo!() }
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
