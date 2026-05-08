"""Rust ecosystem analyzer for AttackMap.

Coverage (v0.1):
- Web frameworks: axum, actix-web, rocket (route + entrypoint extraction)
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
from pathlib import Path
from urllib.parse import urlparse

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
SKIP_DIRS = {"target", ".git", "node_modules", ".cargo", "vendor"}
_SNIPPET_MAX_CHARS = 160


# ---------- Patterns ----------

# Axum: Router::new().route("/path", get(h).post(h2))
# We capture the path then walk a restricted method-chain that follows.
AXUM_ROUTE_PATTERN = re.compile(
    r'\.route\(\s*"([^"]+)"\s*,\s*([a-zA-Z_][a-zA-Z0-9_:]*)\s*\(',
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
# Actix-web service routes: web::resource("/path").route(web::get().to(...))
ACTIX_RESOURCE_PATTERN = re.compile(
    r'web::(?:resource|scope)\(\s*"([^"]+)"',
    re.IGNORECASE,
)

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


def _line_of(content: str, offset: int) -> int:
    """1-indexed line for an offset in content."""
    if offset <= 0:
        return 1
    return content.count("\n", 0, offset) + 1


def _line_snippet(content: str, offset: int, *, max_chars: int = _SNIPPET_MAX_CHARS) -> str:
    line_start = content.rfind("\n", 0, offset) + 1
    line_end = content.find("\n", offset)
    if line_end == -1:
        line_end = len(content)
    line = content[line_start:line_end].strip()
    if len(line) > max_chars:
        line = line[: max_chars - 1] + "…"
    return line


def _crate_name_from_cargo(cargo_path: Path) -> str | None:
    if not cargo_path.exists():
        return None
    try:
        text = cargo_path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return None
    match = re.search(r'^\s*\[package\]\s*\n.*?^\s*name\s*=\s*"([^"]+)"', text, re.MULTILINE | re.DOTALL)
    if match:
        return match.group(1)
    return None


def _workspace_members(cargo_path: Path) -> list[str]:
    if not cargo_path.exists():
        return []
    try:
        text = cargo_path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return []
    block = re.search(r"\[workspace\][^\[]*?members\s*=\s*\[([^\]]*)\]", text, re.DOTALL)
    if not block:
        return []
    return re.findall(r'"([^"]+)"', block.group(1))


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
        for path in root.rglob("Cargo.toml"):
            if any(part in SKIP_DIRS for part in path.parts):
                continue
            return True
        for path in root.rglob("*.rs"):
            if any(part in SKIP_DIRS for part in path.parts):
                continue
            return True
        return False

    def analyze(self, repo_path: str | Path) -> ScanResult:
        root = Path(repo_path).resolve()
        result = ScanResult(root=str(root))
        if not root.exists() or not root.is_dir():
            return result

        crate_name = _crate_name_from_cargo(root / "Cargo.toml")
        workspace_members = _workspace_members(root / "Cargo.toml")
        if crate_name:
            self._append_unique_service(result, f"crate:{crate_name}", "Cargo.toml")
        for member in workspace_members:
            self._append_unique_service(result, f"workspace_member:{member}", "Cargo.toml")

        for file_path in root.rglob("*.rs"):
            if not file_path.is_file():
                continue
            if any(part in SKIP_DIRS for part in file_path.parts):
                continue

            result.files_scanned += 1
            if "rust" not in result.languages:
                result.languages.append("rust")

            try:
                content = file_path.read_text(encoding="utf-8")
            except UnicodeDecodeError:
                continue

            relative = str(file_path.relative_to(root))
            self._extract_routes(content, relative, result)
            self._extract_databases(content, relative, result)
            self._extract_auth(content, relative, result)
            self._extract_secrets(content, relative, result)
            self._extract_external_calls(content, relative, result)
            self._extract_frameworks(content, relative, result)
            self._extract_entrypoints(content, relative, result)
            self._infer_service_role(content, relative, result)

        result.languages.sort()
        return result

    # ---------- Extractors ----------

    def _extract_routes(self, content: str, relative: str, result: ScanResult) -> None:
        # axum: .route("/x", get(h).post(h2)) — pull every method in the routing chain.
        # The capture-group regex sits on the *first* method call (e.g. `get(`); after the opening
        # paren we walk forward looking for additional `.method(` chain links.
        _http_verbs = {"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "TRACE", "CONNECT"}
        for match in AXUM_ROUTE_PATTERN.finditer(content):
            path = match.group(1)
            line = _line_of(content, match.start())
            methods: set[str] = set()
            # First method is the one captured in group 2 (when it's an HTTP verb).
            first_call = match.group(2).split("::")[-1].upper()
            if first_call in _http_verbs:
                methods.add(first_call)
            # Walk a bounded window for chained `.post(...)` / `.delete(...)` etc., stopping at
            # the next .route( or Router::new boundary so we don't pull from the next entry.
            chain_window = content[match.end(): match.end() + 300]
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
            for method in sorted(methods):
                self._append_unique_route(result, path, method, relative, line)

        # actix attribute routes: #[get("/path")] just above an fn
        for match in ACTIX_ATTRIBUTE_ROUTE_PATTERN.finditer(content):
            method, path = match.group(1).upper(), match.group(2)
            self._append_unique_route(result, path, method, relative, _line_of(content, match.start()))

        # actix .route(...): only fires when web:: namespace appears (so it doesn't double-count axum)
        for match in ACTIX_WEB_ROUTE_PATTERN.finditer(content):
            path, method = match.group(1), match.group(2).upper()
            self._append_unique_route(result, path, method, relative, _line_of(content, match.start()))

        # rocket attribute routes — same shape as actix attribute regex; emit only if rocket markers present.
        if "rocket" in content.lower():
            for match in ROCKET_ATTRIBUTE_ROUTE_PATTERN.finditer(content):
                method, path = match.group(1).upper(), match.group(2)
                self._append_unique_route(result, path, method, relative, _line_of(content, match.start()))

    def _extract_databases(self, content: str, relative: str, result: ScanResult) -> None:
        for pattern, kind in DB_PATTERNS:
            match = pattern.search(content)
            if match is None:
                continue
            self._append_unique_database(
                result,
                kind,
                relative,
                _line_of(content, match.start()),
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
                _line_of(content, match.start()),
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
                    _line_of(content, match.start()),
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
                    _line_of(content, match.start()),
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
                _line_of(content, match.start()),
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
                _line_of(content, match.start()),
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
    ) -> None:
        key = (path, method, file)
        if any((item.path, item.method, item.file) == key for item in result.routes):
            return
        result.routes.append(Route(path=path, method=method, file=file, line=line))

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
