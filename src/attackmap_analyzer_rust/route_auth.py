"""Route-level auth resolution for the AttackMap#256 contract.

Each emitted ``Route`` carries ``auth`` (``required`` / ``anonymous`` /
``unknown``), the ``guards`` that apply and the ``guard_evidence`` source text
that established the state. Core trusts a declared state over its own
resolution (which can't read Rust), so this only declares what the source
verifiably says.

- **axum** — a ``Router::new()...`` chain is read in order: ``.layer(L)`` and
  ``.route_layer(L)`` wrap the routes added *before* them, so a route added
  after the layer is outside it. Routers bound with ``let name = ...`` or
  returned from ``fn name() -> Router`` are followed through
  ``.merge(name)`` / ``.nest("/x", name)`` into the router that mounts them,
  across files, and pick up that router's later layers too.
- **actix-web** — ``.wrap(L)`` on ``App::new()`` / ``web::scope(...)`` wraps
  every service in it, nested scopes included. ``.service(handler)``
  links attribute-macro handlers to the scope that mounts them.
- **Extractor / request guards** (axum, actix, rocket, poem, loco) — a handler
  argument whose type is named like an auth extractor (``Claims``, ``AuthUser``,
  ``CurrentUser``, ``Jwt<..>``, ...) rejects anonymous callers when its
  ``FromRequestParts`` / ``FromRequest`` impl is in the repo and can fail, or
  when it is a known library extractor (``BearerAuth``, ``Identity``, loco
  ``JWT``).
  ``Option<AuthUser>`` explicitly admits them: when no auth layer applies and
  every layer on the path is a known non-auth one, the route is
  ``anonymous``.

A layer is a guard when its constructor or ``from_fn`` function names auth
(``middleware::from_fn(require_auth)``, ``RequireAuthorizationLayer::bearer``,
``ValidateRequestHeaderLayer::bearer``, ``login_required!(..)``,
``HttpAuthentication::bearer(..)``). axum-login's ``AuthManagerLayer`` and
``AuthSession`` only load the user, so they don't count. Anything else stays
``unknown``.

Linear: brackets are matched in one cached pass per file, argument lists are
split by jumping over nested closures, and lookups are bounded. Router chains,
mounts and prefixes live in ``routing.py``; this module holds the shared
bracket scanner, layer and extractor classification, and ``resolve``.
"""

from __future__ import annotations

import functools
import re
from dataclasses import dataclass, field

REQUIRED = "required"
ANONYMOUS = "anonymous"
UNKNOWN = "unknown"

_EVIDENCE_MAX = 200
_ARG_SCAN = 4000
# Router mount levels followed upward before giving up.
_MAX_DEPTH = 16
# Mount points of one router considered before giving up.
_MAX_REFS = 16


def clip(text: str) -> str:
    text = " ".join(text.split())
    return text if len(text) <= _EVIDENCE_MAX else text[: _EVIDENCE_MAX - 1] + "…"


# ---------- Brackets ----------

# Strings ("..", r#".."#), char literals ('a', '\n') and comments are
# skipped. A `'` that doesn't close a char literal is a lifetime.
_SCAN_TOKEN = re.compile(r"\"|\br(#*)\"|'(?:[^'\\\n]|\\[^\n]{1,10})'|//|/\*|[()\[\]{}]")
_ARG_TOKEN = re.compile(r"\"|\br(#*)\"|'(?:[^'\\\n]|\\[^\n]{1,10})'|//|/\*|[(\[{,]")
_STRING_BODY = re.compile(r'[^"\\]*(?:\\.[^"\\]*)*"', re.DOTALL)
_OPEN = "([{"


def _skip(content: str, match: re.Match, limit: int) -> int:
    """Offset after the string/comment ``match`` opens (or after the token)."""
    token = match.group()
    pos = match.end()
    if token == '"':
        body = _STRING_BODY.match(content, pos, limit)
        return body.end() if body else limit
    if match.group(1) is not None:  # raw string r#"..."#
        end = content.find('"' + match.group(1), pos, limit)
        return limit if end < 0 else end + 1 + len(match.group(1))
    if token == "//":
        nl = content.find("\n", pos, limit)
        return limit if nl < 0 else nl
    if token == "/*":
        end = content.find("*/", pos, limit)
        return limit if end < 0 else end + 2
    return pos


@functools.lru_cache(maxsize=4)
def bracket_pairs(content: str) -> dict[int, int]:
    """Opening-bracket offset -> closing-bracket offset, in one forward pass."""
    pairs: dict[int, int] = {}
    stack: list[int] = []
    pos = 0
    n = len(content)
    while pos < n:
        match = _SCAN_TOKEN.search(content, pos)
        if not match:
            break
        token = match.group()
        if len(token) == 1 and token in _OPEN:
            stack.append(match.start())
            pos = match.end()
        elif len(token) == 1 and token in ")]}":
            if stack:
                pairs[stack.pop()] = match.start()
            pos = match.end()
        else:
            pos = _skip(content, match, n)
    return pairs


def matching_close(content: str, open_idx: int) -> int:
    if open_idx < 0:
        return -1
    return bracket_pairs(content).get(open_idx, -1)


def split_args(content: str, open_idx: int, close: int) -> list[tuple[int, int]]:
    """``(start, end)`` of each top-level argument of the bracket at
    ``open_idx``; nested brackets and strings are jumped over."""
    pairs = bracket_pairs(content)
    args: list[tuple[int, int]] = []
    start = pos = open_idx + 1
    while pos < close:
        match = _ARG_TOKEN.search(content, pos, close)
        if not match:
            break
        token = match.group()
        if token == ",":
            args.append((start, match.start()))
            start = pos = match.end()
        elif len(token) == 1 and token in _OPEN:
            pos = max(match.end(), pairs.get(match.start(), close - 1) + 1)
        else:
            pos = _skip(content, match, close)
    if content[start:close].strip():
        args.append((start, close))
    return args


# Whitespace and (bounded) comments may sit between chain links.
_GAP = r"(?:\s|//[^\n]{0,500}|/\*(?:[^*]|\*(?!/)){0,500}\*/)*"
_CHAIN_LINK = re.compile(_GAP + r"\.\s*(\w+)\s*(?:::\s*<[^<>()]*>\s*)?\(")


@dataclass
class Link:
    name: str
    start: int  # offset of the `.`
    open: int
    close: int


def parse_chain(content: str, idx: int, limit: int = 4096) -> list[Link]:
    """``.name(args)`` calls chained after ``idx`` (at most ``limit``)."""
    links: list[Link] = []
    while len(links) < limit:
        match = _CHAIN_LINK.match(content, idx)
        if not match:
            break
        open_idx = match.end() - 1
        close = matching_close(content, open_idx)
        if close < 0:
            break
        links.append(Link(match.group(1), content.rindex(".", match.start(), match.start(1)), open_idx, close))
        idx = close + 1
    return links


def _text(content: str, start: int, end: int) -> str:
    return content[start : min(end, start + _ARG_SCAN)]


# ---------- Layers ----------

_LAYER_AUTH = re.compile(
    r"auth(?!or)|jwt|bearer|login_required|permission_required|require_?(?:user|login)|api_?key",
    re.IGNORECASE,
)
# Set-up layers that load a user or a session but never reject a request.
_LAYER_NOT_AUTH = re.compile(r"AuthManagerLayer|AuthSessionLayer|IdentityMiddleware|SessionManagerLayer")
_LAYER_BENIGN = re.compile(
    r"^(?:TraceLayer|CorsLayer|Cors|CompressionLayer|Compress|DecompressionLayer|TimeoutLayer"
    r"|RequestBodyLimitLayer|DefaultBodyLimit|CatchPanicLayer|PropagateRequestIdLayer"
    r"|SetRequestIdLayer|Extension|AddExtensionLayer|HandleErrorLayer|ConcurrencyLimitLayer"
    r"|BufferLayer|NormalizePathLayer|NormalizePath|SetResponseHeaderLayer|SetSensitiveHeadersLayer"
    r"|SetSensitiveRequestHeadersLayer|CookieManagerLayer|SessionManagerLayer|AuthManagerLayer"
    r"|AuthManagerLayerBuilder|IdentityMiddleware|SessionMiddleware|Logger|DefaultHeaders"
    r"|ErrorHandlers|GovernorLayer|Governor|RateLimitLayer|LoadShedLayer|ServiceBuilder)$"
)
_CALLEE = re.compile(r"\s*([A-Za-z_][\w:]*!?)")
_FROM_FN = re.compile(r"(?:\w+::)*(from_fn|from_fn_with_state|from_extractor|from_extractor_with_state)$")
_TURBOFISH = re.compile(r"::\s*<\s*([\w:]+)")


@dataclass
class Layer:
    kind: str  # "auth" | "benign" | "other"
    name: str = ""
    evidence: str = ""


def classify_layer(content: str, start: int, end: int, evidence: str) -> Layer:
    """Classify the layer/middleware expression ``content[start:end]``."""
    end = min(end, start + _ARG_SCAN)
    callee = _CALLEE.match(content, start, end)
    if not callee:
        return Layer("other")
    path = callee.group(1).rstrip(":")
    rest = callee.end()
    from_fn = _FROM_FN.search(path.rstrip("!"))
    if from_fn:
        # The function (or extractor type) is what authenticates, not the state.
        if from_fn.group(1).startswith("from_extractor"):
            target = _TURBOFISH.search(content, callee.start(1), min(end, rest + 200))
            target_name = target.group(1) if target else ""
        else:
            paren = content.find("(", rest, end)
            close = matching_close(content, paren)
            args = split_args(content, paren, close) if paren >= 0 and close > 0 else []
            index = 1 if from_fn.group(1) == "from_fn_with_state" else 0
            target_name = content[args[index][0] : args[index][1]].strip() if len(args) > index else ""
        if _LAYER_AUTH.search(target_name) and not _LAYER_NOT_AUTH.search(target_name):
            return Layer("auth", f"{from_fn.group(1)}({target_name.split('::')[-1]})", evidence)
        return Layer("other")
    segments = path.rstrip("!").split("::")
    type_name = next((s for s in reversed(segments) if s[:1].isupper()), segments[-1])
    if path.startswith("ServiceBuilder"):
        inner = [l for l in parse_chain(content, content.find(")", rest, end) + 1, 64) if l.name == "layer"]
        kinds = [classify_layer(content, l.open + 1, l.close, evidence) for l in inner]
        auth = [k for k in kinds if k.kind == "auth"]
        if auth:
            return Layer("auth", auth[0].name, evidence)
        return Layer("benign" if all(k.kind == "benign" for k in kinds) else "other")
    if _LAYER_NOT_AUTH.search(path):
        return Layer("benign")
    if _LAYER_AUTH.search(path):
        return Layer("auth", path, evidence)
    if _LAYER_BENIGN.match(type_name):
        return Layer("benign")
    return Layer("other")


# ---------- Handler extractors ----------

_FN_DECL = re.compile(r"\bfn\s+(\w+)\s*(?:<[^<>{}()]*>\s*)?\(")
_GUARD_TYPE = re.compile(
    r"auth(?!or)|claims|jwt|bearer|current_?user|logged_?(?:in|user)|session_?user|identity|api_?key|admin",
    re.IGNORECASE,
)
# Extractors that load an optional user without rejecting.
_NOT_GUARD_TYPE = re.compile(r"^(?:AuthSession|Session|TypedHeader|HeaderMap|Authorization)$")
# `MaybeAuthUser`, `OptionalUser`, `OptAuth`: named as admitting anonymous callers.
_OPTIONAL_TYPE = re.compile(r"(?:Maybe|Optional|Opt)(?=[A-Z_])")
_WORD = re.compile(r"\w+")
_TYPE_HEAD = re.compile(r"\s*(?:&\s*)?(?:'\w+\s+)?(?:mut\s+)?([\w:]+)\s*(<)?")


@dataclass
class Signature:
    name: str
    # (type, evidence, binding names in the parameter pattern)
    guards: list[tuple[str, str, frozenset[str]]] = field(default_factory=list)
    optional: list[tuple[str, str, frozenset[str]]] = field(default_factory=list)

    def without_params(self, names: set[str]) -> "Signature":
        """Drop parameters bound from the path (rocket `<id>`), which aren't
        request guards."""
        if not names:
            return self
        return Signature(
            self.name,
            [g for g in self.guards if not g[2] & names],
            [g for g in self.optional if not g[2] & names],
        )


def _param_type(content: str, start: int, end: int) -> tuple[str, str] | None:
    """``(pattern, type)`` of a ``pat: Type`` parameter."""
    text = content[start : min(end, start + 400)]
    depth = 0
    for i, ch in enumerate(text):
        if ch in "([{<":
            depth += 1
        elif ch in ")]}>":
            depth -= 1
        elif ch == ":" and depth == 0 and text[i + 1 : i + 2] != ":" and text[i - 1 : i] != ":":
            return text[:i].strip(), text[i + 1 :].strip()
    return None


def _classify_type(type_text: str) -> tuple[str, str] | None:
    """("guard" | "optional", type name) for an auth extractor type."""
    head = _TYPE_HEAD.match(type_text)
    if not head:
        return None
    name = head.group(1).split("::")[-1]
    if name == "Option" and head.group(2):
        inner = _classify_type(type_text[head.end() :])
        return ("optional", inner[1]) if inner and inner[0] == "guard" else None
    if name in ("Extension", "State", "Json", "Form", "Query", "Path", "Data", "web"):
        return None
    if _NOT_GUARD_TYPE.match(name) or _OPTIONAL_TYPE.match(name) or not _GUARD_TYPE.search(name):
        return None
    return "guard", name


def fn_signatures(content: str) -> dict[str, list[tuple[int, Signature]]]:
    """Every ``fn name(params)`` with the auth extractors among its params."""
    found: dict[str, list[tuple[int, Signature]]] = {}
    for match in _FN_DECL.finditer(content):
        open_idx = match.end() - 1
        close = matching_close(content, open_idx)
        if close < 0:
            continue
        sig = Signature(match.group(1))
        for start, end in split_args(content, open_idx, close)[:32]:
            param = _param_type(content, start, end)
            if param is None:
                continue
            pattern, type_text = param
            kind = _classify_type(type_text)
            if kind is None:
                continue
            evidence = clip(f"{pattern}: {type_text}")
            names = frozenset(_WORD.findall(pattern[:100]))
            (sig.guards if kind[0] == "guard" else sig.optional).append((kind[1], evidence, names))
        found.setdefault(sig.name, []).append((match.start(), sig))
    return found


# ---------- Extractor impls ----------

# `impl<S> FromRequestParts<S> for AuthUser` / `impl FromRequest for Identity`
# / `impl<'r> FromRequest<'r> for User`: the extractor is defined in the repo.
# (`OptionalFromRequestParts`, which backs `Option<T>`, doesn't count.)
_EXTRACTOR_IMPL = re.compile(
    r"\bimpl\b[^{};]{0,300}?\b(?:FromRequestParts|FromRequest)\b"
    r"[^{};]{0,200}?\bfor\s+(?:[A-Za-z_]\w*::){0,8}([A-Za-z_]\w*)"
)
_IMPL_BODY = re.compile(r"[^{};]{0,400}\{")
# An extractor that can't fail never rejects a request.
_INFALLIBLE = re.compile(r"\btype\s+(?:Rejection|Error)\s*=\s*(?:[\w:]*::)?Infallible\b")
# What makes an impl an auth check: it reads credentials (an auth header, a
# cookie, the session, a token) or rejects with 401/403. A rejecting
# extractor that merely has an auth-like name (`AdminFilters`) isn't one.
_IMPL_AUTH_EVIDENCE = re.compile(
    r"\bAUTHORIZATION\b|\bAuthorization\b|\bBearer\b|\bCOOKIE\b|\bCookie(?:Jar)?\b|\bcookies?\s*\(|\bcookie\s*\("
    r"|\bSession\b|\bsession\b|\b(?:jwt|token|api_?key)\b|\bdecode\s*(?:::\s*<[^<>]{0,80}>\s*)?\("
    r"|\bIdentity\b|\bUNAUTHORIZED\b|\bUnauthorized\b|\bFORBIDDEN\b|\bForbidden\b|\b40[13]\b",
)

# ...and it must have a way to reject a request that lacks them. An extractor
# that only parses credentials when present (`MaybeAuthUser`:
# `Ok(Self(headers.get(AUTHORIZATION).map(..).transpose()?))`) admits anonymous
# callers, so a bare `?` doesn't count.
_IMPL_REJECTS = re.compile(
    r"\.\s*ok_or(?:_else)?\s*\("
    r"|\breturn\s+(?:[\w:]+\s*\(\s*)?Err\s*\("
    r"|\bErr\s*\([^;]{0,200}?\b(?:UNAUTHORIZED|Unauthorized|Unauthenticated|FORBIDDEN|Forbidden|40[13])\b"
    r"|\bOutcome\s*::\s*(?:Error|Failure|Forward)\s*\([^;]{0,120}?\b(?:Unauthorized|Forbidden)\b"
    r"|\bNone\s*=>\s*(?:return\s+)?[\w:]*(?:Err|Error|Failure)\b"
)
# A required typed header extraction rejects when the header is missing
# (`parts.extract::<TypedHeader<Authorization<Bearer>>>().await.map_err(..)?`).
_REQUIRED_TYPED_HEADER = re.compile(r"(?<!Option<)\bTypedHeader\s*<\s*Authorization\b")

# Library extractors that reject anonymous callers, whose impl lives outside
# the repo: actix-web-httpauth, actix-identity, loco.
LIBRARY_AUTH_EXTRACTORS = frozenset({"BearerAuth", "BasicAuth", "Identity", "JWT", "JWTWithUser"})


def extractor_impls(content: str) -> dict[str, list[bool]]:
    """Extractor type -> one flag per ``FromRequest(Parts)`` impl in
    ``content``: True when the impl can reject, its body checks credentials
    (``_IMPL_AUTH_EVIDENCE``) and it rejects when they're missing
    (``_IMPL_REJECTS``)."""
    found: dict[str, list[bool]] = {}
    for match in _EXTRACTOR_IMPL.finditer(content):
        body = _IMPL_BODY.match(content, match.end())
        guard = False
        if body:
            close = matching_close(content, body.end() - 1)
            end = min(close if close > 0 else body.end(), body.end() + _ARG_SCAN)
            guard = (
                _INFALLIBLE.search(content, body.end(), end) is None
                and _IMPL_AUTH_EVIDENCE.search(content, body.end(), end) is not None
                and (
                    _IMPL_REJECTS.search(content, body.end(), end) is not None
                    or _REQUIRED_TYPED_HEADER.search(content, body.end(), end) is not None
                )
            )
        found.setdefault(match.group(1), []).append(guard)
    return found


# ---------- Router chains (shared patterns; see routing.py) ----------

_AXUM_START = re.compile(r"\bRouter\s*(?:::\s*<[^<>]*>\s*)?::\s*new\s*\(\s*\)")
_LET_NAME = re.compile(r"let\s+(?:mut\s+)?(\w+)\s*(?::[^=;{}]{0,120})?=\s*$")
_FN_RETURNING = re.compile(r"\bfn\s+(\w+)\s*(?:<[^<>{}]{0,120}>)?\s*\([^{};]{0,400}\)[^{};]{0,200}\{\s*$")
_HANDLER_CALL = re.compile(r"\b(?:get|post|put|delete|patch|head|options|trace|any)\s*\(\s*([\w:]+)\s*\)")


@dataclass
class Resolution:
    auth: str = UNKNOWN
    guards: list[str] = field(default_factory=list)
    evidence: str | None = None


@dataclass
class PathState:
    """Layers on one path from a route up to the app."""

    guards: list[Layer] = field(default_factory=list)
    clean: bool = True  # every layer on the path is a known non-auth one
    known: bool = True  # the whole path was followed


def resolve(path: PathState, sig: Signature | None) -> Resolution:
    guards = [(layer.name, layer.evidence) for layer in path.guards]
    if sig is not None:
        guards += [(name, ev) for name, ev, _ in sig.guards]
    if guards:
        names = list(dict.fromkeys(name for name, _ in guards))
        return Resolution(REQUIRED, names, clip("; ".join(dict.fromkeys(ev for _, ev in guards))))
    if sig is not None and sig.optional and path.known and path.clean:
        return Resolution(ANONYMOUS, [], clip("; ".join(ev for _, ev, _ in sig.optional)))
    return Resolution()


def handlers_by_method(content: str, start: int, end: int) -> dict[str, str]:
    """``get(h).post(h2)`` -> {"GET": "h", "POST": "h2"} within an axum
    ``.route(path, ...)`` call."""
    text = content[start : min(end, start + _ARG_SCAN)]
    out: dict[str, str] = {}
    for match in _HANDLER_CALL.finditer(text):
        method = match.group(0).split("(", 1)[0].strip().split("::")[-1].upper()
        out.setdefault(method, match.group(1))
    return out
