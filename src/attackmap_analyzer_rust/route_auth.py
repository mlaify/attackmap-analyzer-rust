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
- **Extractor / request guards** (axum, actix, rocket) — a handler argument
  whose type is an auth extractor (``Claims``, ``AuthUser``, ``CurrentUser``,
  ``BearerAuth``, ``Identity``, ``Jwt<..>``, ...) rejects anonymous callers.
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
split by jumping over nested closures, and lookups are bounded.
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
    r"auth(?!or)|claims|jwt|bearer|current_?user|logged_?in|session_?user|identity|api_?key|admin",
    re.IGNORECASE,
)
# Extractors that load an optional user without rejecting.
_NOT_GUARD_TYPE = re.compile(r"^(?:AuthSession|Session|TypedHeader|HeaderMap|Authorization)$")
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
    if _NOT_GUARD_TYPE.match(name) or not _GUARD_TYPE.search(name):
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


# ---------- Router chains ----------

_AXUM_START = re.compile(r"\bRouter\s*(?:::\s*<[^<>]*>\s*)?::\s*new\s*\(\s*\)")
_ACTIX_START = re.compile(r"\bApp\s*::\s*new\s*\(\s*\)|\bweb\s*::\s*scope\s*\(")
_LET_NAME = re.compile(r"let\s+(?:mut\s+)?(\w+)\s*(?::[^=;{}]{0,120})?=\s*$")
_FN_RETURNING = re.compile(r"\bfn\s+(\w+)\s*(?:<[^<>{}]{0,120}>)?\s*\([^{};]{0,400}\)[^{};]{0,200}\{\s*$")
_REF_NAME = re.compile(r"\s*(?:&\s*)?([\w:]+)\s*(?:\(\s*[^()]{0,200}\))?\s*(?:\.\s*clone\s*\(\s*\))?\s*$")
_HANDLER_CALL = re.compile(r"\b(?:get|post|put|delete|patch|head|options|trace|any)\s*\(\s*([\w:]+)\s*\)")


@dataclass
class Chain:
    framework: str  # "axum" | "actix"
    file: str
    start: int
    name: str | None
    end: int
    # In order: ("route", offset) / ("layer", Layer) / ("mount", ref name)
    # / ("service", fn name) / ("scope", chain start offset)
    items: list[tuple[str, object]] = field(default_factory=list)
    parent: "Chain | None" = None  # actix: the chain whose argument holds this scope
    dots: list[int] = field(default_factory=list)  # offsets of each link's `.`


def _chain_name(content: str, start: int) -> str | None:
    window = content[max(0, start - 600) : start]
    let = _LET_NAME.search(window[-200:])
    if let:
        return let.group(1)
    func = _FN_RETURNING.search(window)
    return func.group(1) if func else None


def _ref_name(content: str, start: int, end: int) -> str | None:
    text = content[start : min(end, start + 300)]
    match = _REF_NAME.match(text)
    return match.group(1).split("::")[-1] if match else None


_ROUTER_CALL = re.compile(r"(\w+)?\s*\.\s*(merge|nest|nest_service|layer|route_layer)\s*\(")


def opaque_router_names(content: str, chains: list[Chain], links: set[int]) -> set[str]:
    """Router names used by ``.layer`` / ``.merge`` / ``.nest`` calls that
    aren't part of a parsed ``Router::new()`` chain (``links``: the offsets of
    the chain links' dots)."""
    names: set[str] = set()
    for match in _ROUTER_CALL.finditer(content):
        dot = content.rfind(".", 0, match.start(2) + 1)
        if dot in links:
            continue
        if match.group(1):
            names.add(match.group(1))
        if match.group(2) in ("merge", "nest", "nest_service"):
            close = matching_close(content, match.end() - 1)
            args = split_args(content, match.end() - 1, close) if close > 0 else []
            if args and (target := _ref_name(content, *args[-1])):
                names.add(target)
    return names


def axum_chains(content: str, file: str) -> list[Chain]:
    chains = []
    for match in _AXUM_START.finditer(content):
        links = parse_chain(content, match.end())
        chain = Chain("axum", file, match.start(), _chain_name(content, match.start()),
                      links[-1].close if links else match.end())
        chain.dots = [link.start for link in links]
        for link in links:
            if link.name == "route":
                chain.items.append(("route", link.start))
            elif link.name in ("layer", "route_layer"):
                evidence = clip(content[link.start : min(link.close + 1, link.start + 2 * _EVIDENCE_MAX)])
                chain.items.append(("layer", classify_layer(content, link.open + 1, link.close, evidence)))
            elif link.name in ("merge", "nest", "nest_service"):
                args = split_args(content, link.open, link.close)
                target = args[-1] if args else None
                if target is not None:
                    chain.items.append(("mount", _ref_name(content, *target)))
        chains.append(chain)
    return chains


def actix_chains(content: str, file: str) -> list[Chain]:
    chains: list[Chain] = []
    for match in _ACTIX_START.finditer(content):
        idx = match.end()
        if match.group().endswith("("):  # web::scope("...")
            close = matching_close(content, match.end() - 1)
            if close < 0:
                continue
            idx = close + 1
        links = parse_chain(content, idx)
        chain = Chain("actix", file, match.start(), None, links[-1].close if links else idx)
        for link in links:
            if link.name == "wrap":
                evidence = clip(content[link.start : min(link.close + 1, link.start + 2 * _EVIDENCE_MAX)])
                chain.items.append(("layer", classify_layer(content, link.open + 1, link.close, evidence)))
            elif link.name == "route":
                chain.items.append(("route", link.start))
            elif link.name == "service":
                name = _ref_name(content, link.open + 1, link.close)
                if name is not None:
                    chain.items.append(("service", name))
        chains.append(chain)
    # A scope inside another chain's arguments is nested in it.
    ordered = sorted(chains, key=lambda c: c.start)
    stack: list[Chain] = []
    for chain in ordered:
        while stack and stack[-1].end < chain.start:
            stack.pop()
        if stack:
            chain.parent = stack[-1]
        stack.append(chain)
    return chains


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


class Registry:
    """Router chains and handler signatures across the repo."""

    def __init__(self) -> None:
        self.axum: dict[str, list[Chain]] = {}  # router name -> chains bound to it
        self.mounts: dict[str, list[tuple[Chain, int]]] = {}  # router name -> (mounting chain, item index)
        self.actix_services: dict[str, list[Chain]] = {}  # handler fn -> chains mounting it
        self.signatures: dict[str, list[Signature]] = {}
        # Router names also touched outside a parsed chain (`app = app.layer(..)`,
        # `app.merge(api)`): their full layer path isn't visible.
        self.opaque: set[str] = set()
        self._memo: dict[tuple[str, int], PathState] = {}

    def add_chains(self, chains: list[Chain]) -> None:
        for chain in chains:
            if chain.framework == "axum" and chain.name:
                self.axum.setdefault(chain.name, []).append(chain)
            for index, (kind, value) in enumerate(chain.items):
                if kind == "mount" and value:
                    self.mounts.setdefault(str(value), []).append((chain, index))
                elif kind == "service":
                    self.actix_services.setdefault(str(value), []).append(chain)

    def add_signatures(self, found: dict[str, list[tuple[int, Signature]]]) -> None:
        for name, sigs in found.items():
            self.signatures.setdefault(name, []).extend(sig for _, sig in sigs)

    # -- layer paths --

    def axum_path(self, chain: Chain, index: int, depth: int = 0) -> PathState:
        """Layers wrapping item ``index`` of ``chain``, up through every router
        that mounts it. Several mount points must agree."""
        state = PathState()
        for kind, value in chain.items[index + 1 :]:
            if kind == "layer":
                layer = value  # type: ignore[assignment]
                if layer.kind == "auth":
                    state.guards.append(layer)
                elif layer.kind == "other":
                    state.clean = False
        if state.guards or not chain.name:
            return state
        mounted = self._mounted(chain.name, depth)
        state.guards = mounted.guards
        state.clean = state.clean and mounted.clean
        state.known = mounted.known
        return state

    def _mounted(self, name: str, depth: int) -> PathState:
        """Layers every mount point of router ``name`` adds; several mount
        points must agree. Memoized per (name, depth), so fan-in stays linear."""
        key = (name, depth)
        cached = self._memo.get(key)
        if cached is not None:
            return cached
        state = PathState()
        if depth >= _MAX_DEPTH or len(self.axum.get(name, [])) > 1 or name in self.opaque:
            state.known = False  # too deep, bound twice, or touched outside a chain
        else:
            refs = self.mounts.get(name, [])
            if len(refs) > _MAX_REFS:
                state.known = False
            elif refs:
                parents = [self.axum_path(parent, i, depth + 1) for parent, i in refs]
                if all(p.guards for p in parents):
                    state.guards = [g for p in parents for g in p.guards]
                state.clean = all(p.clean for p in parents)
                state.known = all(p.known for p in parents)
        self._memo[key] = state
        return state

    def actix_path(self, chain: Chain | None, depth: int = 0) -> PathState:
        state = PathState()
        while chain is not None and depth < _MAX_DEPTH:
            for kind, value in chain.items:
                if kind == "layer":
                    layer = value  # type: ignore[assignment]
                    if layer.kind == "auth":
                        state.guards.append(layer)
                    elif layer.kind == "other":
                        state.clean = False
            chain = chain.parent
            depth += 1
        if chain is not None:
            state.known = False
        return state

    def actix_service_path(self, handler: str) -> PathState:
        chains = self.actix_services.get(handler, [])
        if not chains or len(chains) > _MAX_REFS:
            return PathState(known=False)
        paths = [self.actix_path(c) for c in chains]
        state = PathState()
        if all(p.guards for p in paths):
            state.guards = [g for p in paths for g in p.guards]
        state.clean = all(p.clean for p in paths)
        state.known = all(p.known for p in paths)
        return state

    # -- handlers --

    def signature(self, handler: str | None) -> Signature | None:
        if not handler:
            return None
        sigs = self.signatures.get(handler.split("::")[-1], [])
        if len(sigs) != 1:
            return None  # unknown, or ambiguous across modules
        return sigs[0]


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
