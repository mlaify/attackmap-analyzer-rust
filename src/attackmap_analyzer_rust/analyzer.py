"""Rust ecosystem analyzer for AttackMap.

Coverage (v0.1):
- Web frameworks: axum, actix-web, rocket, poem, salvo, loco, warp, tide (routes
  with the prefixes of the routers that mount them; entrypoints)
- Databases: sqlx, diesel, sea-orm, mongodb, redis, rusqlite, tokio-postgres
- Auth crates: jsonwebtoken, argon2/bcrypt/scrypt, oauth2, tower-http auth, axum-login,
  actix-identity, tower-sessions
- HTTP clients (external calls): reqwest, hyper-client, isahc, surf, ureq
- Secrets: std::env::var, dotenv/dotenvy, secrecy crate
- Entrypoints: axum::serve, HttpServer::new(...).run, rocket::build, tide::new
- Workspace/crate names from Cargo.toml for service-name hints

Emits Signal v2 fields (line numbers + evidence snippets + confidence) so
downstream insights can cite `path/to/file.rs:NN`.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse

from attackmap.sdk import DEFAULT_SKIP_DIRS, iter_repo_files, line_of, read_source, rel

from . import frameworks as fw
from . import route_auth as ra
from . import routing as rt
from .contracts import (
    AnalyzerMetadata,
    AuthHint,
    DatabaseHint,
    EntrypointHint,
    ExternalCall,
    FrameworkHint,
    Route,
    ScanResult,
    SecretHint,
    ServiceHint,
)

CODE_SUFFIXES = {".rs"}
# Rust-specific directories on top of the SDK defaults (which already cover
# target/, vendor/, .git and node_modules). Matched against directory names
# inside the repo only (mlaify/AttackMap#253).
SKIP_DIRS = DEFAULT_SKIP_DIRS | {".cargo"}
_SNIPPET_MAX_CHARS = 160


# ---------- Patterns ----------

# Axum: Router::new().route("/path", get(h).post(h2))
# We capture the path then walk a restricted method-chain that follows.
AXUM_ROUTE_PATTERN = re.compile(
    r'\.route\(\s*"([^"]*)"\s*,\s*([a-zA-Z_][a-zA-Z0-9_:]*)\s*\(',
    re.MULTILINE,
)
# Method-chain on the routing function, e.g. get(h).post(h2)
AXUM_METHOD_CHAIN_PATTERN = re.compile(
    r"\.(get|post|put|delete|patch|head|options|trace|connect)\s*\(",
    re.IGNORECASE,
)

# Actix-web attribute macros: #[get("/path")] / #[post("/path")] etc.
ACTIX_ATTRIBUTE_ROUTE_PATTERN = re.compile(
    r'#\[\s*(get|post|put|delete|patch|head|options)\s*\(\s*"([^"]+)"',
    re.IGNORECASE,
)
# Actix-web .route(): .route("/path", web::get().to(h))
ACTIX_WEB_ROUTE_PATTERN = re.compile(
    r'\.route\(\s*"([^"]+)"\s*,\s*web::(get|post|put|delete|patch|head|options)\s*\(\s*\)',
    re.IGNORECASE,
)
# Actix-web service routes: web::resource("/path").route(web::get().to(...)).
# Kept for API compatibility; resources and scopes are parsed as chains
# (routing.actix_chains), which also joins their prefixes.
ACTIX_RESOURCE_PATTERN = re.compile(
    r'web::(?:resource|scope)\(\s*"([^"]+)"',
    re.IGNORECASE,
)
# The method of an actix route: `web::get()`, bare `get()` (imported), or
# `web::method(Method::POST)`.
ACTIX_METHOD_PATTERN = re.compile(
    r"\s*(?:web\s*::\s*)?(get|post|put|delete|patch|head|options|trace|connect|method)\s*\(\s*(?:(?:http\s*::\s*)?Method\s*::\s*(\w+))?",
    re.IGNORECASE,
)

# The handler fn an attribute macro decorates, and the dynamic segments of a
# Rocket path / data param (`<id>`, `<path..>`, `data = "<form>"`), which bind
# parameters that aren't request guards.
FN_AFTER_ATTRIBUTE_PATTERN = re.compile(r"\bfn\s+(\w+)")
ROCKET_PATH_PARAM_PATTERN = re.compile(r"<(\w+)(?:\.\.)?>")
# The handler of an actix `.route("/x", web::post().to(handler))`.
ACTIX_TO_PATTERN = re.compile(r"\.\s*to\s*\(\s*([\w:]+)\s*\)")

# Rocket attribute macros: #[get("/path")], also with format/data: #[post("/users", data = "...")]
ROCKET_ATTRIBUTE_ROUTE_PATTERN = re.compile(
    r'#\[\s*(get|post|put|delete|patch|head|options)\s*\(\s*"([^"]+)"',
    re.IGNORECASE,
)

# External HTTP calls
OUTBOUND_PATTERNS: list[re.Pattern[str]] = [
    re.compile(
        r'\breqwest::(?:get|Client::new\(\)\.[a-z]+|blocking::get)\s*\(\s*["]([^"]+)["]',
        re.IGNORECASE,
    ),
    re.compile(r'\.(?:get|post|put|delete|patch)\s*\(\s*["](https?://[^"]+)["]', re.IGNORECASE),
    re.compile(r'\bisahc::(?:get|post|put|delete|patch)\s*\(\s*["]([^"]+)["]', re.IGNORECASE),
    re.compile(r'\bsurf::(?:get|post|put|delete|patch)\s*\(\s*["]([^"]+)["]', re.IGNORECASE),
    re.compile(r'\bureq::(?:get|post|put|delete|patch)\s*\(\s*["]([^"]+)["]', re.IGNORECASE),
]

# Database libs (regex anchored on common entry points)
DB_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"\bsqlx::(?:postgres|Postgres)", re.IGNORECASE), "postgresql"),
    (re.compile(r"\bsqlx::(?:mysql|MySql)", re.IGNORECASE), "mysql"),
    (re.compile(r"\bsqlx::(?:sqlite|Sqlite)", re.IGNORECASE), "sqlite"),
    (re.compile(r"\bsqlx::(?:Pool|Connection|query|query_as|query!)", re.IGNORECASE), "sql"),
    (re.compile(r"\bdiesel::", re.IGNORECASE), "sql"),
    (re.compile(r"\bsea_orm::|\bSeaOrm\b", re.IGNORECASE), "sql"),
    (re.compile(r"\btokio_postgres::|\bpostgres::Client::", re.IGNORECASE), "postgresql"),
    (re.compile(r"\brusqlite::", re.IGNORECASE), "sqlite"),
    (re.compile(r"\bmongodb::Client", re.IGNORECASE), "mongodb"),
    (re.compile(r"\bredis::(?:Client::open|aio::|Connection|cmd)", re.IGNORECASE), "redis"),
    (re.compile(r"\bdeadpool_postgres", re.IGNORECASE), "postgresql"),
    (re.compile(r"\bdeadpool_redis", re.IGNORECASE), "redis"),
    (re.compile(r"\baws_sdk_s3::|\bS3Client\b", re.IGNORECASE), "object_storage"),
    (re.compile(r"\baws_sdk_dynamodb::", re.IGNORECASE), "dynamodb"),
]

# Auth-related signals (pattern, hint label)
AUTH_PATTERNS: list[tuple[re.Pattern[str], str, float]] = [
    (re.compile(r"\bjsonwebtoken::", re.IGNORECASE), "jwt", 0.85),
    (re.compile(r"\bargon2::", re.IGNORECASE), "argon2", 0.9),
    (re.compile(r"\bbcrypt::", re.IGNORECASE), "bcrypt", 0.9),
    (re.compile(r"\bscrypt::", re.IGNORECASE), "scrypt", 0.9),
    (re.compile(r"\bpassword_hash::", re.IGNORECASE), "password_hash", 0.85),
    (re.compile(r"\boauth2::", re.IGNORECASE), "oauth", 0.85),
    (re.compile(r"\baxum_login::", re.IGNORECASE), "axum_login", 0.85),
    (re.compile(r"\bactix_identity::", re.IGNORECASE), "actix_identity", 0.85),
    (re.compile(r"\btower_sessions::", re.IGNORECASE), "tower_sessions", 0.85),
    (re.compile(r"\btower_http::auth::", re.IGNORECASE), "tower_http_auth", 0.85),
    (re.compile(r"\bAuthorization\b", re.IGNORECASE), "authorization_header", 0.6),
    (re.compile(r"\bBearer\b", re.IGNORECASE), "bearer_token", 0.6),
    (re.compile(r"\bapi[_-]?key\b", re.IGNORECASE), "api_key", 0.6),
]

# Web framework presence. Confidence high — these markers are unambiguous.
FRAMEWORK_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"\baxum::", re.IGNORECASE), "axum"),
    (re.compile(r"\bactix_web::", re.IGNORECASE), "actix-web"),
    (re.compile(r"#\[\s*launch\s*\]|\brocket::build\s*\(", re.IGNORECASE), "rocket"),
    (re.compile(r"\btide::", re.IGNORECASE), "tide"),
    (re.compile(r"\bwarp::", re.IGNORECASE), "warp"),
    (re.compile(r"\bpoem::", re.IGNORECASE), "poem"),
    (re.compile(r"\bsalvo::", re.IGNORECASE), "salvo"),
    (re.compile(r"\btower::Service\b", re.IGNORECASE), "tower"),
    (re.compile(r"\bhyper::", re.IGNORECASE), "hyper"),
    (re.compile(r"\btokio::", re.IGNORECASE), "tokio"),
]

# Entrypoint markers — server bind / listen / startup
ENTRYPOINT_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"\baxum::serve\s*\(", re.IGNORECASE), "axum_serve"),
    (re.compile(r"\baxum::Server::bind\s*\(", re.IGNORECASE), "axum_server_bind"),
    (re.compile(r"\bHttpServer::new\s*\(", re.IGNORECASE), "actix_http_server"),
    (re.compile(r"\brocket::build\s*\(", re.IGNORECASE), "rocket_build"),
    (re.compile(r"#\[\s*launch\s*\]", re.IGNORECASE), "rocket_launch_attr"),
    (re.compile(r"\btide::new\s*\(", re.IGNORECASE), "tide_new"),
    (re.compile(r"#\[\s*tokio::main\s*\]", re.IGNORECASE), "tokio_main"),
    (re.compile(r"#\[\s*actix_web::main\s*\]", re.IGNORECASE), "actix_main"),
]

# Secrets — env var names containing SECRET/TOKEN/KEY/PASSWORD/PASS/PWD
SECRET_PATTERNS: list[re.Pattern[str]] = [
    re.compile(
        r'(?:std::)?env::var\s*\(\s*["]([A-Z0-9_]*(SECRET|TOKEN|KEY|PASSWORD|PASS|PWD)[A-Z0-9_]*)["]',
        re.IGNORECASE,
    ),
    re.compile(
        r'\bdotenv(?:y)?::var\s*\(\s*["]([A-Z0-9_]*(SECRET|TOKEN|KEY|PASSWORD|PASS|PWD)[A-Z0-9_]*)["]',
        re.IGNORECASE,
    ),
    re.compile(
        r'\benv!\s*\(\s*["]([A-Z0-9_]*(SECRET|TOKEN|KEY|PASSWORD|PASS|PWD)[A-Z0-9_]*)["]',
        re.IGNORECASE,
    ),
    re.compile(r'\bsecrecy::SecretString::new\s*\(', re.IGNORECASE),
]


# Kept rather than attackmap.sdk.line_snippet: this takes a match offset and
# splits on "\n" only, so it stays consistent with line_of() on files that
# contain form feeds or other str.splitlines() separators, and it costs
# O(line) per match instead of O(file).
def _line_snippet(content: str, offset: int, *, max_chars: int = _SNIPPET_MAX_CHARS) -> str:
    line_start = content.rfind("\n", 0, offset) + 1
    line_end = content.find("\n", offset)
    if line_end == -1:
        line_end = len(content)
    line = content[line_start:line_end].strip()
    if len(line) > max_chars:
        line = line[: max_chars - 1] + "…"
    return line


def _crate_name_from_cargo(cargo_path: Path, root: Path | None = None) -> str | None:
    text = read_source(cargo_path, root=root)
    if text is None:
        return None
    match = re.search(r'^\s*\[package\]\s*\n.*?^\s*name\s*=\s*"([^"]+)"', text, re.MULTILINE | re.DOTALL)
    if match:
        return match.group(1)
    return None


def _workspace_members(cargo_path: Path, root: Path | None = None) -> list[str]:
    text = read_source(cargo_path, root=root)
    if text is None:
        return []
    block = re.search(r"\[workspace\][^\[]*?members\s*=\s*\[([^\]]*)\]", text, re.DOTALL)
    if not block:
        return []
    return re.findall(r'"([^"]+)"', block.group(1))


# `use salvo::prelude::*;` / `pub(crate) use poem::{..}` / `extern crate warp;`
_USE_CRATE = {
    crate: re.compile(rf"^[ \t]*(?:pub(?:\([^)\n]{{0,40}}\))?[ \t]+)?(?:use|extern[ \t]+crate)[ \t]+(?:::)?{crate}\b", re.MULTILINE)
    for crate in ("axum", "salvo", "poem", "loco_rs", "warp", "tide")
}
# Crate paths used without a `use` line (`warp::path!(..)`, `tide::new()`).
WARP_PATH_PATTERN = re.compile(r"\bwarp\s*::\s*(?:path!|get\s*\(|post\s*\(|Filter\b|serve\s*\()")
TIDE_PATH_PATTERN = re.compile(r"\btide\s*::\s*(?:new|with_state|Server|Request)\b")


def _uses(content: str, crate: str) -> bool:
    return _USE_CRATE[crate].search(content) is not None


@dataclass
class _Candidate:
    """A route found in one file, emitted after the walk (#2)."""

    path: str  # as written, before any prefix
    method: str
    file: str
    line: int | None
    # "chain": item `where` of a router chain; "service": actix attribute
    # handler; "rocket": rocket handler; "plain": no router context.
    kind: str
    where: tuple | None = None
    handler: object = None  # handler name / Ref
    sig: ra.Signature | None = None
    prefix: str = ""


class RustAnalyzer:
    metadata = AnalyzerMetadata(
        name="rust",
        display_name="Rust Analyzer",
        version="0.1.0",
        description="Rust ecosystem analyzer covering axum, actix-web, rocket, common DB/auth crates, and reqwest.",
        scope="Rust crates and workspaces. Cargo-bearing repos are auto-detected; pure .rs trees also work.",
        targets=["rust", "axum", "actix-web", "rocket"],
        languages=["rust"],
        priority=20,
        experimental=False,
        enabled_by_default=True,
    )

    @property
    def name(self) -> str:
        return self.metadata.name

    # ---------- Public entry points ----------

    def detect(self, repo_path: str | Path) -> bool:
        root = Path(repo_path).resolve()
        if not root.exists() or not root.is_dir():
            return False
        if (root / "Cargo.toml").exists() or (root / "Cargo.lock").exists():
            return True
        # Any nested Cargo.toml or .rs file; stop at the first one.
        return next(iter_repo_files(root, suffixes=CODE_SUFFIXES, names={"Cargo.toml"}, skip_dirs=SKIP_DIRS), None) is not None

    def analyze(self, repo_path: str | Path) -> ScanResult:
        root = Path(repo_path).resolve()
        result = ScanResult(root=str(root))
        if not root.exists() or not root.is_dir():
            return result

        crate_name = _crate_name_from_cargo(root / "Cargo.toml", root)
        workspace_members = _workspace_members(root / "Cargo.toml", root)
        if crate_name:
            self._append_unique_service(result, f"crate:{crate_name}", "Cargo.toml")
        for member in workspace_members:
            self._append_unique_service(result, f"workspace_member:{member}", "Cargo.toml")

        # Routes are emitted after the walk: their prefixes and auth come from
        # routers mounted and handlers defined across files (#2, AttackMap#256).
        registry = rt.Registry()
        pending: list[_Candidate] = []
        for file_path in iter_repo_files(root, suffixes=CODE_SUFFIXES, skip_dirs=SKIP_DIRS):
            content = read_source(file_path, root=root)
            if content is None:
                continue

            result.files_scanned += 1
            if "rust" not in result.languages:
                result.languages.append("rust")

            relative = rel(file_path, root)
            self._extract_routes(content, relative, result, registry, pending)
            self._extract_databases(content, relative, result)
            self._extract_auth(content, relative, result)
            self._extract_secrets(content, relative, result)
            self._extract_external_calls(content, relative, result)
            self._extract_frameworks(content, relative, result)
            self._extract_entrypoints(content, relative, result)
            self._infer_service_role(content, relative, result)

        self._emit_routes(result, registry, pending)

        result.languages.sort()
        return result

    def _emit_routes(self, result: ScanResult, registry: rt.Registry, pending: list[_Candidate]) -> None:
        # (path, method, file) already emitted: a set, so dedup stays linear.
        seen = {(r.path, r.method, r.file) for r in result.routes}
        for cand in pending:
            for prefix, state, sig in self._expand(registry, cand):
                if prefix in ("", "/") and cand.path:
                    path = cand.path
                else:
                    path = rt.join_path(prefix, cand.path)
                index = self._append_unique_route(result, path, cand.method, cand.file, cand.line, seen=seen)
                if index is not None:
                    self._set_route_auth(result, index, ra.resolve(state, sig))

    @staticmethod
    def _expand(registry: rt.Registry, cand: _Candidate) -> list[tuple[str, ra.PathState, ra.Signature | None]]:
        """``(prefix, layers, handler signature)`` for each path the route is
        reachable under."""
        if cand.kind == "chain" and cand.where is not None:
            sig = registry.signature(cand.handler, cand.file)
            return [(p, state, sig) for p, state in registry.mounts(*cand.where)]
        if cand.kind == "service":
            sig = registry.confirm(cand.sig)
            return [(p, state, sig) for p, state in registry.service_mounts(str(cand.handler), cand.file)]
        if cand.kind == "rocket":
            # Rocket has no route middleware: request guards are the whole story.
            sig = registry.confirm(cand.sig)
            return [(p, ra.PathState(), sig) for p in registry.rocket_prefixes(str(cand.handler), cand.file)]
        sig = registry.signature(cand.handler, cand.file) if cand.handler else None
        return [(cand.prefix, ra.PathState(known=False), sig)]

    # ---------- Extractors ----------

    def _extract_routes(
        self,
        content: str,
        relative: str,
        result: ScanResult,
        registry: rt.Registry | None = None,
        pending: list[_Candidate] | None = None,
    ) -> None:
        """Collect route candidates; ``analyze`` emits them once every file
        is read. Called on its own (no registry), it emits them directly."""
        standalone = registry is None
        registry = registry if registry is not None else rt.Registry()
        pending = pending if pending is not None else []
        before = len(pending)

        # Frameworks that share builder names are told apart by what the file
        # imports, not by words that might sit in a comment.
        salvo_file = _uses(content, "salvo") and not _uses(content, "axum")
        groups = [
            rt.axum_like_chains(content, relative, "axum") if "Router" in content and not salvo_file else [],
            rt.actix_chains(content, relative) if "actix" in content else [],
            rt.axum_like_chains(content, relative, "poem") if "Route" in content and _uses(content, "poem") else [],
            rt.salvo_chains(content, relative) if salvo_file and "Router" in content else [],
            rt.loco_chains(content, relative) if "Routes" in content and _uses(content, "loco_rs") else [],
        ]
        for group in groups:
            rt.nest_chains(group)
            registry.add_chains(group)
        axum, actix, poem, salvo, loco = groups
        if axum or poem or salvo or loco:
            registry.add_served(rt.served_refs(content), relative)
        if axum:
            dots = {item.dot for chain in axum for item in chain.items}
            registry.opaque |= rt.opaque_router_names(content, dots)
        signatures = ra.fn_signatures(content)
        registry.add_signatures(relative, signatures)
        if "FromRequest" in content:
            for name, flags in ra.extractor_impls(content).items():
                registry.extractors.setdefault(name, []).extend(flags)
        route_items = {
            item.dot: (chain, i)
            for chain in axum + actix
            for i, item in enumerate(chain.items)
            if item.kind == "route"
        }

        def add(path: str, method: str, offset: int, kind: str, **kw) -> None:
            pending.append(_Candidate(path, method, relative, line_of(content, offset), kind, **kw))

        # axum: .route("/x", get(h).post(h2)) — pull every method in the routing chain.
        # The capture-group regex sits on the *first* method call (e.g. `get(`); after the opening
        # paren we walk forward looking for additional `.method(` chain links.
        _http_verbs = {"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "TRACE", "CONNECT"}
        for match in AXUM_ROUTE_PATTERN.finditer(content):
            path = match.group(1)
            where = route_items.get(match.start())
            # `.route("/x", web::post().to(h))` inside an actix App/scope chain
            # also matches here; it is resolved as actix.
            actix_route = where is not None and where[0].framework == "actix"
            if not path and not actix_route:
                continue  # only an actix scope route may be empty ("" is the scope itself)
            close = ra.matching_close(content, content.find("(", match.start()))
            if actix_route:
                to = ACTIX_TO_PATTERN.search(content, match.end(), close) if close > 0 else None
                method = self._actix_method(content, match.start(2), close)
                add(path, method, match.start(), "chain", where=where, handler=to.group(1) if to else None)
                continue
            methods: set[str] = set()
            # First method is the one captured in group 2 (when it's an HTTP verb).
            first_call = match.group(2).split("::")[-1].upper()
            if first_call in _http_verbs:
                methods.add(first_call)
            # Walk the rest of the `.route(..)` call for chained `.post(...)` / `.delete(...)`
            # etc., bounded, and stopping at the next .route( or Router::new boundary.
            window_end = close if close > 0 else match.end() + 300
            chain_window = content[match.end() : min(window_end, match.end() + 300)]
            stop = chain_window.find(".route(")
            stop_alt = chain_window.find("Router::new")
            if stop_alt != -1 and (stop == -1 or stop_alt < stop):
                stop = stop_alt
            if stop != -1:
                chain_window = chain_window[:stop]
            for chain_match in AXUM_METHOD_CHAIN_PATTERN.finditer(chain_window):
                methods.add(chain_match.group(1).upper())
            if not methods:
                methods = {"ANY"}
            handlers = ra.handlers_by_method(content, match.start(2), close) if close > 0 else {}
            for method in sorted(methods):
                add(path, method, match.start(), "chain" if where else "plain", where=where,
                    handler=handlers.get(method))

        # actix web::resource("/x").route(web::get().to(h)) / .to(h): the
        # resource's own path is the route's.
        for chain in actix:
            if not chain.resource:
                continue
            for i, item in enumerate(chain.items):
                if item.kind != "route":
                    continue
                args = ra.split_args(content, item.open, item.close)
                if item.value == "to":
                    handler = rt.parse_ref(content, *args[0]) if len(args) == 1 else None
                    add("", "ANY", item.dot, "chain", where=(chain, i), handler=handler)
                elif len(args) == 1 and rt.literal(content, *args[0]) is None:
                    to = ACTIX_TO_PATTERN.search(content, item.open, item.close)
                    method = self._actix_method(content, item.open + 1, item.close)
                    add("", method, item.dot, "chain", where=(chain, i), handler=to.group(1) if to else None)

        # poem Route::new().at("/x", get(h).post(h2)) and loco Routes::new().add("/x", get(h)).
        for chain in poem + loco:
            for i, item in enumerate(chain.items):
                if item.kind != "route":
                    continue
                args = ra.split_args(content, item.open, item.close)
                path = rt.literal(content, *args[0]) if len(args) == 2 else None
                if path is None:
                    continue
                handlers = ra.handlers_by_method(content, args[1][0], args[1][1])
                if not handlers:
                    add(path, "ANY", item.dot, "chain", where=(chain, i), handler=rt.parse_ref(content, *args[1]))
                for method, handler in handlers.items():
                    add(path, method, item.dot, "chain", where=(chain, i), handler=handler)

        # salvo Router::with_path("x").get(h): the router's own path is the route's.
        for chain in salvo:
            for i, item in enumerate(chain.items):
                if item.kind == "route":
                    args = ra.split_args(content, item.open, item.close)
                    handler = rt.parse_ref(content, *args[0]) if len(args) == 1 else None
                    add("", str(item.value), item.dot, "chain", where=(chain, i), handler=handler)

        # actix / rocket attribute routes: #[get("/path")] just above an fn
        is_rocket = "rocket" in content.lower() and "actix_web" not in content
        for match in ACTIX_ATTRIBUTE_ROUTE_PATTERN.finditer(content):
            method, path = match.group(1).upper(), match.group(2)
            fn = FN_AFTER_ATTRIBUTE_PATTERN.search(content, match.end(), match.end() + 600)
            sig = None
            if fn:
                sig = next((s for offset, s in signatures.get(fn.group(1), []) if offset == fn.start()), None)
                registry.attr_handlers.setdefault(fn.group(1), set()).add(relative)
            handler = fn.group(1) if fn else None
            if is_rocket:
                if sig is not None:
                    attr_end = content.find("]", match.end())
                    attr = content[match.start() : attr_end if attr_end > 0 else match.end()]
                    sig = sig.without_params(set(ROCKET_PATH_PARAM_PATTERN.findall(attr)))
                add(path, method, match.start(), "rocket" if handler else "plain", handler=handler, sig=sig)
            elif handler:
                add(path, method, match.start(), "service", handler=handler, sig=sig)
            else:
                add(path, method, match.start(), "plain")

        # actix .route(...): only fires when web:: namespace appears (so it doesn't double-count axum)
        for match in ACTIX_WEB_ROUTE_PATTERN.finditer(content):
            path, method = match.group(1), match.group(2).upper()
            close = ra.matching_close(content, content.find("(", match.start()))
            to = ACTIX_TO_PATTERN.search(content, match.end(), close) if close > 0 else None
            where = route_items.get(match.start())
            add(path, method, match.start(), "chain" if where else "plain", where=where,
                handler=to.group(1) if to else None)

        # rocket .mount("/base", routes![..]) prefixes.
        if "routes!" in content or ("mount" in content and "rocket" in content.lower()):
            registry.add_rocket(*rt.rocket_mounts(content, relative), relative)

        # warp path! filters and tide app.at("/x").get(h) chains.
        if "warp" in content and (_uses(content, "warp") or WARP_PATH_PATTERN.search(content)):
            for found in fw.warp_routes(content):
                add(found.path, found.method, found.offset, "plain")
        if "tide" in content and (_uses(content, "tide") or TIDE_PATH_PATTERN.search(content)):
            for found in fw.tide_routes(content):
                add(found.path, found.method, found.offset, "plain")

        if standalone:
            self._emit_routes(result, registry, pending[before:])
            del pending[before:]

    @staticmethod
    def _actix_method(content: str, start: int, end: int) -> str:
        """``web::get()`` / ``get()`` / ``web::method(Method::POST)`` -> verb."""
        match = ACTIX_METHOD_PATTERN.match(content, start, end)
        if not match:
            return "ANY"
        if match.group(1).lower() == "method":
            return match.group(2).upper() if match.group(2) else "ANY"
        return match.group(1).upper()

    def _extract_databases(self, content: str, relative: str, result: ScanResult) -> None:
        for pattern, kind in DB_PATTERNS:
            match = pattern.search(content)
            if match is None:
                continue
            self._append_unique_database(
                result,
                kind,
                relative,
                line_of(content, match.start()),
                _line_snippet(content, match.start()),
            )

    def _extract_auth(self, content: str, relative: str, result: ScanResult) -> None:
        for pattern, hint, confidence in AUTH_PATTERNS:
            match = pattern.search(content)
            if match is None:
                continue
            self._append_unique_auth(
                result,
                hint,
                relative,
                line_of(content, match.start()),
                _line_snippet(content, match.start()),
                confidence,
            )

    def _extract_secrets(self, content: str, relative: str, result: ScanResult) -> None:
        for pattern in SECRET_PATTERNS:
            for match in pattern.finditer(content):
                groups = match.groups()
                name = groups[0] if groups and groups[0] else "secrecy::SecretString"
                self._append_unique_secret(
                    result,
                    name,
                    relative,
                    line_of(content, match.start()),
                    _line_snippet(content, match.start()),
                )

    def _extract_external_calls(self, content: str, relative: str, result: ScanResult) -> None:
        for pattern in OUTBOUND_PATTERNS:
            for match in pattern.finditer(content):
                target = match.group(1)
                # Skip path-only matches (no URL scheme); they're often intra-crate paths.
                if not (target.startswith("http://") or target.startswith("https://") or target.startswith("env://")):
                    continue
                self._append_unique_external(
                    result,
                    target,
                    relative,
                    line_of(content, match.start()),
                    _line_snippet(content, match.start()),
                )

    def _extract_frameworks(self, content: str, relative: str, result: ScanResult) -> None:
        for pattern, name in FRAMEWORK_PATTERNS:
            match = pattern.search(content)
            if match is None:
                continue
            self._append_unique_framework(
                result,
                name,
                relative,
                line_of(content, match.start()),
                _line_snippet(content, match.start()),
            )

    def _extract_entrypoints(self, content: str, relative: str, result: ScanResult) -> None:
        for pattern, hint in ENTRYPOINT_PATTERNS:
            match = pattern.search(content)
            if match is None:
                continue
            self._append_unique_entrypoint(
                result,
                hint,
                relative,
                line_of(content, match.start()),
                _line_snippet(content, match.start()),
            )

    def _infer_service_role(self, content: str, relative: str, result: ScanResult) -> None:
        haystack = (relative + " " + content[:500]).lower()
        role: str | None = None
        if any(token in haystack for token in ("worker", "consumer", "queue", "background")):
            role = "worker"
        elif any(token in haystack for token in ("api", "server", "handler", "routes")):
            role = "api"
        elif any(token in haystack for token in ("client", "sdk")):
            role = "client"
        if role:
            self._append_unique_service(result, f"service_role:{role}", relative)

    # ---------- Append helpers (dedup-aware) ----------

    @staticmethod
    def _append_unique_route(
        result: ScanResult,
        path: str,
        method: str,
        file: str,
        line: int | None,
        *,
        auth: str = ra.UNKNOWN,
        guards: list[str] | None = None,
        guard_evidence: str | None = None,
        seen: set[tuple[str, str, str]] | None = None,
    ) -> int | None:
        """Append a route once per (path, method, file); return its index, or
        None when it was already recorded. ``seen`` (the keys already in
        ``result.routes``) replaces the linear scan."""
        key = (path, method, file)
        if seen is not None:
            if key in seen:
                return None
            seen.add(key)
        elif any((item.path, item.method, item.file) == key for item in result.routes):
            return None
        result.routes.append(
            Route(
                path=path, method=method, file=file, line=line,
                auth=auth, guards=list(guards or []), guard_evidence=guard_evidence,
            )
        )
        return len(result.routes) - 1

    @staticmethod
    def _set_route_auth(result: ScanResult, index: int, resolution: ra.Resolution) -> None:
        """Declare a route's auth (AttackMap#256); older cores ignore the fields.
        Rebuilt rather than mutated so Route's guard_evidence redaction runs."""
        if resolution.auth == ra.UNKNOWN:
            return
        route = result.routes[index]
        result.routes[index] = Route(
            path=route.path, method=route.method, file=route.file, line=route.line,
            auth=resolution.auth, guards=list(resolution.guards), guard_evidence=resolution.evidence,
        )

    @staticmethod
    def _append_unique_database(
        result: ScanResult,
        kind: str,
        file: str,
        line: int | None,
        evidence: str | None,
    ) -> None:
        key = (kind, file)
        if any((item.kind, item.file) == key for item in result.databases):
            return
        result.databases.append(
            DatabaseHint(kind=kind, file=file, line=line, evidence_text=evidence)
        )

    @staticmethod
    def _append_unique_auth(
        result: ScanResult,
        hint: str,
        file: str,
        line: int | None,
        evidence: str | None,
        confidence: float,
    ) -> None:
        key = (hint, file)
        if any((item.hint, item.file) == key for item in result.auth_hints):
            return
        result.auth_hints.append(
            AuthHint(hint=hint, file=file, line=line, evidence_text=evidence, confidence=confidence)
        )

    @staticmethod
    def _append_unique_secret(
        result: ScanResult,
        name: str,
        file: str,
        line: int | None,
        evidence: str | None,
    ) -> None:
        key = (name, file)
        if any((item.name, item.file) == key for item in result.secret_hints):
            return
        result.secret_hints.append(
            SecretHint(name=name, file=file, line=line, evidence_text=evidence, confidence=0.85)
        )

    @staticmethod
    def _append_unique_external(
        result: ScanResult,
        target: str,
        file: str,
        line: int | None,
        evidence: str | None,
    ) -> None:
        key = (target, file)
        if any((item.target, item.file) == key for item in result.external_calls):
            return
        result.external_calls.append(
            ExternalCall(target=target, file=file, line=line, evidence_text=evidence)
        )

    @staticmethod
    def _append_unique_framework(
        result: ScanResult,
        hint: str,
        file: str,
        line: int | None,
        evidence: str | None,
    ) -> None:
        key = (hint, file)
        if any((item.hint, item.file) == key for item in result.framework_hints):
            return
        result.framework_hints.append(
            FrameworkHint(hint=hint, file=file, line=line, evidence_text=evidence)
        )

    @staticmethod
    def _append_unique_entrypoint(
        result: ScanResult,
        hint: str,
        file: str,
        line: int | None,
        evidence: str | None,
    ) -> None:
        key = (hint, file)
        if any((item.hint, item.file) == key for item in result.entrypoint_hints):
            return
        result.entrypoint_hints.append(
            EntrypointHint(hint=hint, file=file, line=line, evidence_text=evidence)
        )

    @staticmethod
    def _append_unique_service(result: ScanResult, hint: str, file: str) -> None:
        key = (hint, file)
        if any((item.hint, item.file) == key for item in result.service_hints):
            return
        result.service_hints.append(ServiceHint(hint=hint, file=file))


__all__ = ["RustAnalyzer"]
