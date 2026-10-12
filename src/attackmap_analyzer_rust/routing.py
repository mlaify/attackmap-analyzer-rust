"""Router graphs: the full path and the layers of every chained route (#2).

A *chain* is a builder expression such as ``Router::new().route(..).nest(..)``
(axum), ``web::scope("/api").service(..)`` (actix-web), ``Route::new().at(..)``
(poem), ``Router::with_path("x").get(h).push(..)`` (salvo) or
``Routes::new().prefix("x").add(..)`` (loco). Its *items* are the route,
layer and mount links in source order. A route's full path is its own path
joined to the prefixes of every chain that mounts it, up to a root:

- **containment** — a chain written inside a mount link of another one
  (``.nest("/api", Router::new()...)``, ``.service(web::scope("/x")...)``,
  ``.push(Router::with_path("x")...)``);
- **by name** — a chain bound with ``let name = ...`` (same file, nearest
  binding before the use) or returned from ``fn name()`` (any file), mounted by
  ``.nest("/p", name)`` / ``.nest("/p", path::name())`` / ``.merge(..)`` /
  ``.add_route(..)``. Several definitions of one fn name are told apart by the
  module path (``users::routes`` -> ``users.rs`` / ``users/mod.rs``) or by
  living in the caller's file; otherwise the mount is left unresolved;
- **actix** ``.configure(path::f)`` — the root chains in ``fn f``;
- **actix attribute handlers** — ``.service(handler)``;
- **rocket** — ``.mount("/base", routes![a, m::b])`` or
  ``.mount("/base", m::routes())`` where ``fn routes`` returns ``routes![..]``.

A router mounted at several prefixes yields one route per prefix, each with the
layers on its own path. axum and poem layers wrap only the routes added *before*
them; actix ``wrap``, salvo ``hoop`` and loco ``layer`` cover the whole chain.

Everything is bounded: links per chain, mount points per router, depth, prefixes
per route, and every lookup is memoized, so fan-in stays linear.
"""

from __future__ import annotations

import bisect
import functools
import re
from dataclasses import dataclass, field
from pathlib import PurePosixPath

from . import route_auth as ra
from .route_auth import Layer, PathState

_MAX_DEPTH = 16  # mount levels followed upward
_MAX_REFS = 16  # mount points of one router
_MAX_PATHS = 16  # distinct prefixes per route
_MAX_LINKS = 4096
_OWNER_STEPS = 64
_MAX_DEFS = 256  # definitions of one name considered when disambiguating

HTTP_VERBS = ("get", "post", "put", "delete", "patch", "head", "options", "trace", "connect")


def join_path(prefix: str, path: str) -> str:
    """Join two route segments like core's ``_join_route_parts``."""

    def norm(value: str) -> str:
        value = (value or "").strip()
        if not value:
            return "/"
        if not value.startswith("/"):
            value = "/" + value
        while "//" in value:
            value = value.replace("//", "/")
        return value

    base, suffix = norm(prefix), norm(path)
    if base == "/":
        return suffix
    if suffix == "/":
        return base
    return f"{base.rstrip('/')}/{suffix.lstrip('/')}"


# ---------- Small parsers ----------

_STR_LIT = re.compile(r'r?"([^"\\\n]*)"')


def literal(content: str, start: int, end: int) -> str | None:
    """The string literal that is the whole of ``content[start:end]``."""
    text = content[start : min(end, start + 600)].strip()
    match = _STR_LIT.fullmatch(text)
    return match.group(1) if match else None


_REF_HEAD = re.compile(
    r"\s*(?:&\s*)?(?:mut\s+)?([A-Za-z_]\w*(?:\s*::\s*[A-Za-z_]\w*){0,16})\s*(?:::\s*<[^<>()]{0,200}>\s*)?"
)
_CLOSURE_HEAD = re.compile(r"\s*(?:move\s*)?\|[^|]{0,200}\|\s*")
# Calls that hand the same router back.
_REF_TAIL = frozenset({"clone", "with_state", "into", "boxed", "to_owned"})


@dataclass(frozen=True)
class Ref:
    name: str
    qualifier: tuple[str, ...]
    call: bool
    offset: int


def parse_ref(content: str, start: int, end: int, *, closure: bool = False) -> Ref | None:
    """``name`` / ``a::b::name(..)`` (optionally ``.clone()`` / ``.with_state(..)``)
    as the whole of ``content[start:end]``; with ``closure``, also the body of
    ``|cfg| a::name(cfg, ..)``."""
    end = min(end, start + 2000)
    pos = start
    if closure:
        head = _CLOSURE_HEAD.match(content, pos, end)
        if head:
            pos = head.end()
    head = _REF_HEAD.match(content, pos, end)
    if not head:
        return None
    segments = [s.strip() for s in head.group(1).split("::")]
    pos = head.end()
    call = False
    if pos < end and content[pos] == "(":
        close = ra.matching_close(content, pos)
        if close < 0 or close >= end:
            return None
        call, pos = True, close + 1
    for link in ra.parse_chain(content, pos, 8):
        if link.close >= end or link.name not in _REF_TAIL:
            return None
        pos = link.close + 1
    if content[pos:end].strip():
        return None
    if len(segments) > 1 and segments[-2][:1].isupper():
        return None  # `Type::new(..)`: a value, not a router fn
    qualifier = tuple(s for s in segments[:-1] if s not in ("crate", "self", "super"))
    return Ref(segments[-1], qualifier, call, start)


_BODY_OPEN = re.compile(r"[^{};]{0,400}\{")


@functools.lru_cache(maxsize=4)
def fn_bodies(content: str) -> tuple[list[int], list[tuple[int, int, str, int]]]:
    """``(body opens, [(open, close, fn name, decl offset)])`` sorted by open."""
    bodies = []
    for match in ra._FN_DECL.finditer(content):
        close = ra.matching_close(content, match.end() - 1)
        if close < 0:
            continue
        brace = _BODY_OPEN.match(content, close + 1)
        if not brace:
            continue
        body_open = brace.end() - 1
        body_close = ra.matching_close(content, body_open)
        if body_close > 0:
            bodies.append((body_open, body_close, match.group(1), match.start()))
    bodies.sort()
    return [b[0] for b in bodies], bodies


def owner(content: str, offset: int) -> tuple[int, int, str, int] | None:
    """The innermost fn body around ``offset``: ``(open, close, name, decl)``."""
    opens, bodies = fn_bodies(content)
    index = bisect.bisect_left(opens, offset) - 1
    for _ in range(_OWNER_STEPS):
        if index < 0:
            break
        if bodies[index][1] > offset:
            return bodies[index]
        index -= 1
    return None


_TAIL = re.compile(ra._GAP + r"\}")
_RETURN_BEFORE = re.compile(r"\breturn\s*$")


def _module_match(file: str, qualifier: tuple[str, ...], strict: bool) -> bool:
    last = qualifier[-1].replace("-", "_")
    parts = [p.replace("-", "_") for p in PurePosixPath(file).parts]
    if not parts:
        return False
    stem = parts[-1].rsplit(".", 1)[0]
    if strict:
        return stem == last or (stem in ("mod", "lib") and len(parts) > 1 and parts[-2] == last)
    return last in parts[:-1]


def pick_definition(defs: dict[tuple[str, int], list], ref: Ref, from_file: str) -> list:
    """The one definition ``ref`` names, by module path or by sharing the
    caller's file; nothing when that's ambiguous."""
    if len(defs) <= 1:
        return [x for group in defs.values() for x in group]
    if len(defs) > _MAX_DEFS:
        return []
    if ref.qualifier:
        for strict in (True, False):
            keys = [k for k in defs if _module_match(k[0], ref.qualifier, strict)]
            if len(keys) == 1:
                return defs[keys[0]]
        return []
    keys = [k for k in defs if k[0] == from_file]
    return defs[keys[0]] if len(keys) == 1 else []


# ---------- Chains ----------


@dataclass
class Mount:
    ref: Ref | None
    prefix: str | None  # None: not a literal


@dataclass
class Item:
    kind: str  # "route" | "layer" | "mount" | "service" | "configure"
    dot: int
    open: int
    close: int
    value: object = None  # Layer | Mount | Ref | method name


@dataclass(eq=False)
class Chain:
    framework: str  # "axum" | "actix" | "poem" | "salvo" | "loco" | "loco_app"
    file: str
    start: int
    end: int  # offset of the last character
    ordered: bool = True  # layers wrap only the items before them
    prefix: str | None = ""  # the chain's own path (scope / resource / with_path / prefix)
    resource: bool = False  # actix web::resource
    name: str | None = None
    name_kind: str | None = None  # "let" | "fn"
    definition: int = -1  # offset of the binding / fn that names it
    owner: tuple[int, int, str, int] | None = None
    items: list[Item] = field(default_factory=list)
    parent: "Chain | None" = None
    parent_index: int | None = None
    inline_mounts: set[int] = field(default_factory=set)
    _opens: list[int] = field(default_factory=list, repr=False)

    def item_at(self, offset: int) -> int | None:
        """Index of the item whose arguments contain ``offset``."""
        if len(self._opens) != len(self.items):
            self._opens = [item.open for item in self.items]
        index = bisect.bisect_right(self._opens, offset) - 1
        if index >= 0 and self.items[index].close > offset:
            return index
        return None


def _layer(content: str, link: ra.Link) -> Layer:
    evidence = ra.clip(content[link.start : min(link.close + 1, link.start + 2 * ra._EVIDENCE_MAX)])
    return ra.classify_layer(content, link.open + 1, link.close, evidence)


def _name_chain(content: str, chain: Chain) -> None:
    """``let name = <chain>`` or a chain that is what ``fn name`` returns."""
    window = content[max(0, chain.start - 200) : chain.start]
    let = ra._LET_NAME.search(window)
    if let:
        chain.name, chain.name_kind = let.group(1), "let"
        chain.definition = chain.start
        return
    body = chain.owner
    if body is None:
        return
    head = content[body[0] + 1 : chain.start]
    first = not head.strip() or ra._FN_RETURNING.search(content[max(0, chain.start - 600) : chain.start])
    tail = _TAIL.match(content, chain.end + 1)
    returned = tail is not None and tail.end() - 1 == body[1]
    if returned or first or _RETURN_BEFORE.search(content[max(0, chain.start - 40) : chain.start]):
        chain.name, chain.name_kind, chain.definition = body[2], "fn", body[3]


def _start_chain(content: str, file: str, framework: str, start: int, idx: int, **kw) -> tuple[Chain, list[ra.Link]]:
    links = ra.parse_chain(content, idx, _MAX_LINKS)
    end = links[-1].close if links else idx - 1
    chain = Chain(framework, file, start, end, **kw)
    chain.owner = owner(content, start)
    _name_chain(content, chain)
    return chain, links


def _args(content: str, link: ra.Link) -> list[tuple[int, int]]:
    return ra.split_args(content, link.open, link.close)


def _mount(content: str, link: ra.Link, with_prefix: bool) -> Mount:
    args = _args(content, link)
    prefix: str | None = ""
    if with_prefix:
        prefix = literal(content, *args[0]) if len(args) > 1 else None
    target = parse_ref(content, *args[-1]) if args else None
    return Mount(target, prefix)


_AXUM_START = ra._AXUM_START
_POEM_START = re.compile(r"\bRoute\s*::\s*new\s*\(\s*\)")
_LOCO_START = re.compile(r"\bRoutes\s*::\s*new\s*\(\s*\)")
_LOCO_APP_START = re.compile(r"\bAppRoutes\s*::\s*(?:with_default_routes|empty)\s*\(\s*\)")
_SALVO_START = re.compile(r"\bRouter\s*::\s*(?:(new)\s*\(\s*\)|(with_path|with_hoop)\s*\()")
_ACTIX_START = re.compile(r"\bApp\s*::\s*new\s*\(\s*\)|\bweb\s*::\s*(scope|resource)\s*\(")
_ACTIX_BARE_START = re.compile(r"(?<![\w:.])(scope|resource)\s*\(")
_ACTIX_USE = re.compile(r"\buse\s+actix_web\b")
_WORD_SCOPE = re.compile(r"\b(?:scope|resource)\b|\bweb\s*::\s*\*")


def axum_like_chains(content: str, file: str, framework: str) -> list[Chain]:
    """axum ``Router::new()`` and poem ``Route::new()`` chains."""
    start_re, route_link = (_AXUM_START, "route") if framework == "axum" else (_POEM_START, "at")
    mounts = ("merge", "nest", "nest_service") if framework == "axum" else ("nest", "nest_no_strip")
    layers = ("layer", "route_layer") if framework == "axum" else ("with", "around")
    chains = []
    for match in start_re.finditer(content):
        chain, links = _start_chain(content, file, framework, match.start(), match.end())
        for link in links:
            if link.name == route_link:
                chain.items.append(Item("route", link.start, link.open, link.close))
            elif link.name in layers:
                chain.items.append(Item("layer", link.start, link.open, link.close, _layer(content, link)))
            elif link.name in mounts:
                mount = _mount(content, link, link.name != "merge")
                chain.items.append(Item("mount", link.start, link.open, link.close, mount))
        chains.append(chain)
    return chains


def loco_chains(content: str, file: str) -> list[Chain]:
    """loco ``Routes::new().prefix("x").add("/y", get(h))`` and
    ``AppRoutes::..().prefix("/api").add_route(m::routes())``."""
    chains = []
    for match in _LOCO_START.finditer(content):
        chain, links = _start_chain(content, file, "loco", match.start(), match.end(), ordered=False)
        for link in links:
            if link.name == "prefix":
                args = _args(content, link)
                chain.prefix = literal(content, *args[0]) if len(args) == 1 else None
            elif link.name == "add":
                chain.items.append(Item("route", link.start, link.open, link.close))
            elif link.name == "layer":
                chain.items.append(Item("layer", link.start, link.open, link.close, _layer(content, link)))
        chains.append(chain)
    for match in _LOCO_APP_START.finditer(content):
        chain, links = _start_chain(content, file, "loco_app", match.start(), match.end(), ordered=False)
        current: str | None = ""
        for link in links:
            if link.name == "prefix":
                args = _args(content, link)
                current = literal(content, *args[0]) if len(args) == 1 else None
            elif link.name == "add_route":
                mount = _mount(content, link, False)
                mount.prefix = current
                chain.items.append(Item("mount", link.start, link.open, link.close, mount))
            elif link.name == "layer":
                chain.items.append(Item("layer", link.start, link.open, link.close, _layer(content, link)))
        chains.append(chain)
    return chains


def salvo_chains(content: str, file: str) -> list[Chain]:
    """salvo ``Router::with_path("x").hoop(m).get(h).push(child)``."""
    chains = []
    for match in _SALVO_START.finditer(content):
        prefix: str | None = ""
        pre_items: list[Item] = []
        idx = match.end()
        if match.group(2):
            open_idx = match.end() - 1
            close = ra.matching_close(content, open_idx)
            if close < 0:
                continue
            idx = close + 1
            if match.group(2) == "with_path":
                prefix = literal(content, open_idx + 1, close)
            else:
                link = ra.Link("hoop", match.start(), open_idx, close)
                pre_items.append(Item("layer", link.start, open_idx, close, _layer(content, link)))
        chain, links = _start_chain(content, file, "salvo", match.start(), idx, ordered=False, prefix=prefix)
        chain.items.extend(pre_items)
        for link in links:
            if link.name == "path":
                args = _args(content, link)
                path = literal(content, *args[0]) if len(args) == 1 else None
                chain.prefix = None if path is None or chain.prefix is None else join_path(chain.prefix, path)
            elif link.name in HTTP_VERBS or link.name in ("goal", "any"):
                method = link.name.upper() if link.name in HTTP_VERBS else "ANY"
                chain.items.append(Item("route", link.start, link.open, link.close, method))
            elif link.name == "hoop":
                chain.items.append(Item("layer", link.start, link.open, link.close, _layer(content, link)))
            elif link.name == "push":
                chain.items.append(Item("mount", link.start, link.open, link.close, _mount(content, link, False)))
        chains.append(chain)
    return chains


def _actix_bare_imported(content: str) -> bool:
    """``use actix_web::web::{scope, resource}`` or ``web::*`` (so a bare
    ``scope("..")`` is actix's)."""
    for match in _ACTIX_USE.finditer(content):
        end = content.find(";", match.end(), match.end() + 4000)
        if end > 0 and _WORD_SCOPE.search(content, match.end(), end):
            return True
    return False


def actix_chains(content: str, file: str) -> list[Chain]:
    """``App::new()`` / ``web::scope("/x")`` / ``web::resource("/x")`` chains."""
    starts: list[tuple[int, int, str | None]] = [
        (m.start(), m.end(), m.group(1)) for m in _ACTIX_START.finditer(content)
    ]
    if _actix_bare_imported(content):
        starts += [(m.start(), m.end(), m.group(1)) for m in _ACTIX_BARE_START.finditer(content)]
    chains: list[Chain] = []
    for start, end, kind in sorted(starts):
        idx, prefix = end, ""
        if kind:  # scope("..") / resource("..")
            close = ra.matching_close(content, end - 1)
            if close < 0:
                continue
            args = ra.split_args(content, end - 1, close)
            if len(args) != 1:
                continue
            prefix = literal(content, *args[0])
            idx = close + 1
        chain, links = _start_chain(
            content, file, "actix", start, idx, ordered=False, prefix=prefix, resource=kind == "resource"
        )
        for link in links:
            if link.name in ("wrap", "wrap_fn"):
                chain.items.append(Item("layer", link.start, link.open, link.close, _layer(content, link)))
            elif link.name == "route" or (link.name == "to" and chain.resource):
                chain.items.append(Item("route", link.start, link.open, link.close, link.name))
            elif link.name in ("service", "default_service"):
                ref = parse_ref(content, link.open + 1, link.close)
                chain.items.append(Item("service", link.start, link.open, link.close, ref))
            elif link.name == "configure":
                ref = parse_ref(content, link.open + 1, link.close, closure=True)
                chain.items.append(Item("configure", link.start, link.open, link.close, ref))
        chains.append(chain)
    return chains


def nest_chains(chains: list[Chain]) -> None:
    """Link each chain written inside another chain's link arguments to it."""
    stack: list[Chain] = []
    for chain in sorted(chains, key=lambda c: (c.start, -c.end)):
        while stack and stack[-1].end < chain.start:
            stack.pop()
        if stack and stack[-1].start < chain.start:
            outer = stack[-1]
            index = outer.item_at(chain.start)
            if index is not None:
                chain.parent, chain.parent_index = outer, index
                outer.inline_mounts.add(index)
        stack.append(chain)


# ---------- Opaque router names (axum) ----------

# Anchored on the `.`; the receiver name is read backwards (bounded), so a
# long word or whitespace run can't make the scan quadratic.
_ROUTER_CALL = re.compile(r"\.[ \t\r\n]*(merge|nest|nest_service|layer|route_layer)[ \t\r\n]*\(")


def _receiver(content: str, end: int) -> str | None:
    """The identifier right before ``end`` (whitespace skipped), bounded."""
    i = end
    while i > 0 and end - i < 200 and content[i - 1].isspace():
        i -= 1
    j = i
    while j > 0 and i - j < 200 and (content[j - 1].isalnum() or content[j - 1] == "_"):
        j -= 1
    return content[j:i] or None


def opaque_router_names(content: str, dots: set[int]) -> set[str]:
    """Router names used by ``.layer`` / ``.merge`` / ``.nest`` calls that
    aren't links of a parsed chain (``dots``): their full layer path isn't
    visible."""
    names: set[str] = set()
    for match in _ROUTER_CALL.finditer(content):
        if match.start() in dots:
            continue
        receiver = _receiver(content, match.start())
        if receiver:
            names.add(receiver)
        if match.group(1) in ("merge", "nest", "nest_service"):
            close = ra.matching_close(content, match.end() - 1)
            args = ra.split_args(content, match.end() - 1, close) if close > 0 else []
            target = parse_ref(content, *args[-1]) if args else None
            if target is not None:
                names.add(target.name)
    return names


# ---------- Rocket mounts ----------

_ROCKET_MOUNT = re.compile(r"\.\s*mount\s*\(")
_ROUTES_MACRO = re.compile(r"\broutes!\s*[\[(]")


def _macro_refs(content: str, open_idx: int) -> list[Ref]:
    close = ra.matching_close(content, open_idx)
    if close < 0:
        return []
    refs = [parse_ref(content, s, e) for s, e in ra.split_args(content, open_idx, close)[:256]]
    return [r for r in refs if r is not None and not r.call]


@dataclass
class RocketMount:
    base: str | None
    file: str
    refs: list[Ref] = field(default_factory=list)  # handlers in routes![..]
    via: Ref | None = None  # `m::routes()` returning routes![..]


def rocket_mounts(content: str, file: str) -> tuple[list[RocketMount], list[tuple[str, int, list[Ref]]]]:
    """``.mount(base, routes![..] | f())`` calls, and the ``routes![..]`` that
    each fn returns: ``[(fn name, decl offset, refs)]``."""
    mounts: list[RocketMount] = []
    in_mount: set[int] = set()
    for match in _ROCKET_MOUNT.finditer(content):
        close = ra.matching_close(content, match.end() - 1)
        if close < 0:
            continue
        args = ra.split_args(content, match.end() - 1, close)
        if len(args) != 2:
            continue
        mount = RocketMount(literal(content, *args[0]), file)
        target = content[args[1][0] : args[1][1]]
        macro = _ROUTES_MACRO.match(content, args[1][0] + len(target) - len(target.lstrip()))
        if macro:
            in_mount.add(macro.start())
            mount.refs = _macro_refs(content, macro.end() - 1)
        else:
            mount.via = parse_ref(content, *args[1])
            if mount.via is None or not mount.via.call:
                continue
        mounts.append(mount)
    returned = []
    for macro in _ROUTES_MACRO.finditer(content):
        if macro.start() in in_mount:
            continue
        body = owner(content, macro.start())
        if body is not None:
            returned.append((body[2], body[3], _macro_refs(content, macro.end() - 1)))
    return mounts, returned


# ---------- Registry ----------

MountPath = tuple[str, PathState]


def _combine(local: PathState, outer: PathState) -> PathState:
    return PathState(local.guards + outer.guards, local.clean and outer.clean, local.known and outer.known)


def _merge(paths: list[MountPath]) -> list[MountPath]:
    """One entry per prefix; mount points sharing a prefix must agree."""
    grouped: dict[str, list[PathState]] = {}
    for prefix, state in paths:
        grouped.setdefault(prefix, []).append(state)
    out = []
    for prefix, states in list(grouped.items())[:_MAX_PATHS]:
        if len(states) == 1:
            out.append((prefix, states[0]))
            continue
        merged = PathState()
        if all(s.guards for s in states):
            merged.guards = [g for s in states for g in s.guards]
        merged.clean = all(s.clean for s in states)
        merged.known = all(s.known for s in states)
        out.append((prefix, merged))
    return out


@dataclass
class Handler:
    file: str
    signature: ra.Signature


class Registry:
    """Router chains, mounts and handler signatures across the repo."""

    def __init__(self) -> None:
        self.chains: list[Chain] = []
        self.signatures: dict[str, list[Handler]] = {}
        # Router names also touched outside a parsed chain (`app = app.layer(..)`,
        # `app.merge(api)`): their full layer path isn't visible.
        self.opaque: set[str] = set()
        # Extractor type -> one flag per visible FromRequest(Parts) impl: can it reject?
        self.extractors: dict[str, list[bool]] = {}
        self.attr_handlers: dict[str, set[str]] = {}  # actix/rocket handler fn -> files
        self.rocket: list[RocketMount] = []
        self.rocket_fns: dict[str, list[tuple[str, int, list[Ref]]]] = {}
        self._final = False
        self._mounted_by: dict[Chain, list[tuple[Chain, int, str | None]]] = {}
        self._services: dict[str, list[tuple[Chain, int, Ref]]] = {}
        self._rocket_refs: dict[str, list[tuple[str | None, Ref, str]]] = {}
        self._memo: dict[tuple[Chain, int | None, int], list[MountPath]] = {}
        self._sig_memo: dict[tuple[str, tuple[str, ...], str], ra.Signature | None] = {}
        self._service_memo: dict[tuple[str, str], list[MountPath]] = {}
        self._suffix: dict[Chain, list[tuple[tuple[Layer, ...], bool]]] = {}

    # -- collection --

    def add_chains(self, chains: list[Chain]) -> None:
        self.chains.extend(chains)
        self._final = False

    def add_signatures(self, file: str, found: dict[str, list[tuple[int, ra.Signature]]]) -> None:
        for name, sigs in found.items():
            self.signatures.setdefault(name, []).extend(Handler(file, sig) for _, sig in sigs)

    def add_rocket(self, mounts: list[RocketMount], returned: list[tuple[str, int, list[Ref]]], file: str) -> None:
        self.rocket.extend(mounts)
        for name, decl, refs in returned:
            self.rocket_fns.setdefault(name, []).append((file, decl, refs))
        self._final = False

    # -- resolution --

    def _finalize(self) -> None:
        if self._final:
            return
        self._final = True
        self._mounted_by.clear()
        self._services.clear()
        self._memo.clear()
        self._service_memo.clear()
        self._suffix.clear()
        # `let` bindings: (family, file, name) -> chains sorted by offset.
        lets: dict[tuple[str, str, str], list[Chain]] = {}
        # Router fns: (family, name) -> {(file, fn offset): chains}.
        fns: dict[tuple[str, str], dict[tuple[str, int], list[Chain]]] = {}
        # actix root chains by the fn they're in (for `.configure(f)`).
        roots: dict[str, dict[tuple[str, int], list[Chain]]] = {}
        for chain in self.chains:
            family = "loco" if chain.framework == "loco_app" else chain.framework
            if chain.name and chain.name_kind == "let":
                lets.setdefault((family, chain.file, chain.name), []).append(chain)
            elif chain.name and chain.name_kind == "fn":
                fns.setdefault((family, chain.name), {}).setdefault((chain.file, chain.definition), []).append(chain)
            if chain.framework == "actix" and chain.parent is None and chain.owner is not None:
                roots.setdefault(chain.owner[2], {}).setdefault((chain.file, chain.owner[3]), []).append(chain)
        let_starts: dict[tuple[str, str, str], list[int]] = {}
        for key, bound in lets.items():
            bound.sort(key=lambda c: c.start)
            let_starts[key] = [c.start for c in bound]
        for chain in self.chains:
            family = "loco" if chain.framework == "loco_app" else chain.framework
            for index, item in enumerate(chain.items):
                if index in chain.inline_mounts:
                    continue
                targets: list[Chain] = []
                prefix: str | None = ""
                if item.kind == "mount" and isinstance(item.value, Mount) and item.value.ref:
                    ref, prefix = item.value.ref, item.value.prefix
                    if ref.call:
                        targets = pick_definition(fns.get((family, ref.name), {}), ref, chain.file)
                    else:
                        # A `let` binding: the nearest one before the use, in the same file.
                        key = (family, chain.file, ref.name)
                        at = bisect.bisect_left(let_starts.get(key, []), ref.offset)
                        targets = [lets[key][at - 1]] if at > 0 else []
                elif item.kind == "configure" and isinstance(item.value, Ref):
                    targets = pick_definition(roots.get(item.value.name, {}), item.value, chain.file)
                for target in targets:
                    if target is not chain:
                        self._mounted_by.setdefault(target, []).append((chain, index, prefix))
                if item.kind == "service" and isinstance(item.value, Ref) and not item.value.call:
                    self._services.setdefault(item.value.name, []).append((chain, index, item.value))
        self._rocket_refs.clear()
        for mount in self.rocket:
            refs = mount.refs
            if mount.via is not None:
                defs = {(f, d): r for f, d, r in self.rocket_fns.get(mount.via.name, [])}
                refs = pick_definition(defs, mount.via, mount.file)
            for ref in refs[:256]:
                self._rocket_refs.setdefault(ref.name, []).append((mount.base, ref, mount.file))

    def _layers(self, chain: Chain, index: int | None) -> tuple[tuple[Layer, ...], bool]:
        """Auth layers wrapping item ``index`` and whether every layer there is
        a known non-auth one: the layers after it (ordered chains) or all of
        them. Suffixes are computed once per chain."""
        suffix = self._suffix.get(chain)
        if suffix is None:
            suffix = [((), True)]
            for item in reversed(chain.items):
                guards, clean = suffix[-1]
                if item.kind == "layer" and isinstance(item.value, Layer):
                    if item.value.kind == "auth":
                        guards = (item.value,) + guards
                    elif item.value.kind == "other":
                        clean = False
                suffix.append((guards, clean))
            suffix.reverse()  # suffix[i]: layers in items[i:]
            self._suffix[chain] = suffix
        if chain.ordered and index is not None:
            return suffix[min(index + 1, len(suffix) - 1)]
        return suffix[0]

    def _parents(self, chain: Chain) -> list[tuple[Chain, int, str | None]] | None:
        """Where ``chain`` is mounted; ``[]`` for a root, ``None`` when too many."""
        if chain.parent is not None:
            assert chain.parent_index is not None
            item = chain.parent.items[chain.parent_index]
            if item.kind == "mount" and isinstance(item.value, Mount):
                return [(chain.parent, chain.parent_index, item.value.prefix)]
            if item.kind == "service":
                return [(chain.parent, chain.parent_index, "")]
            return []
        refs = self._mounted_by.get(chain, [])
        return None if len(refs) > _MAX_REFS else refs

    def mounts(self, chain: Chain, index: int | None, depth: int = 0) -> list[MountPath]:
        """``(prefix, layers)`` for item ``index`` of ``chain`` — one entry per
        distinct prefix it is reachable under (the chain's own path included)."""
        self._finalize()
        key = (chain, index, depth)
        cached = self._memo.get(key)
        if cached is not None:
            return cached
        guards, clean = self._layers(chain, index)
        local = PathState(list(guards), clean)
        if chain.framework == "axum" and chain.name and chain.name in self.opaque:
            local.known = False
        own = chain.prefix or ""
        parents = self._parents(chain)
        if parents is None or depth >= _MAX_DEPTH:
            local.known = False
            out = [(join_path("", own), local)]
        elif not parents:
            out = [(join_path("", own), local)]
        else:
            paths: list[MountPath] = []
            for parent, parent_index, prefix in parents:
                for outer_prefix, outer in self.mounts(parent, parent_index, depth + 1):
                    full = join_path(join_path(outer_prefix, prefix or ""), own)
                    paths.append((full, _combine(local, outer)))
            out = _merge(paths)
        self._memo[key] = out
        return out

    def service_mounts(self, handler: str, file: str) -> list[MountPath]:
        """Prefixes and layers for an actix attribute handler mounted with
        ``.service(handler)``."""
        self._finalize()
        key = (handler, file)
        if key not in self._service_memo:
            refs = self._services.get(handler, [])
            refs = self._pick_refs(refs, handler, file, lambda r: r[0].file, lambda r: r[2])
            if not refs or len(refs) > _MAX_REFS:
                self._service_memo[key] = [("/", PathState(known=False))]
            else:
                paths: list[MountPath] = []
                for chain, index, _ in refs:
                    paths.extend(self.mounts(chain, index))
                self._service_memo[key] = _merge(paths)
        return self._service_memo[key]

    def rocket_prefixes(self, handler: str, file: str) -> list[str]:
        self._finalize()
        refs = self._rocket_refs.get(handler, [])
        refs = self._pick_refs(refs, handler, file, lambda r: r[2], lambda r: r[1])
        if not refs:
            return ["/"]
        bases = [join_path("", base) if base is not None else "/" for base, _, _ in refs[:_MAX_PATHS]]
        return list(dict.fromkeys(bases))

    def _pick_refs(self, refs: list, handler: str, file: str, file_of, ref_of) -> list:
        """The references that mean the handler defined in ``file``."""
        if not refs or len(refs) > _MAX_DEFS:
            return []
        same = [r for r in refs if file_of(r) == file]
        if same:
            return same
        qualified = [r for r in refs if ref_of(r).qualifier]
        matching = [r for r in qualified if _module_match(file, ref_of(r).qualifier, True)]
        if matching:
            return matching
        if len(self.attr_handlers.get(handler, ())) == 1:
            return [r for r in refs if not ref_of(r).qualifier]
        return []

    # -- handlers --

    def signature(self, handler: Ref | str | None, file: str) -> ra.Signature | None:
        if not handler:
            return None
        ref = handler if isinstance(handler, Ref) else Ref(handler.split("::")[-1], tuple(handler.split("::")[:-1]), False, -1)
        key = (ref.name, ref.qualifier, file)
        if key not in self._sig_memo:
            defs: dict[tuple[str, int], list[ra.Signature]] = {}
            for i, found in enumerate(self.signatures.get(ref.name, [])[: _MAX_DEFS + 1]):
                defs.setdefault((found.file, i), []).append(found.signature)
            picked = pick_definition(defs, ref, file)
            self._sig_memo[key] = picked[0] if len(picked) == 1 else None
        return self.confirm(self._sig_memo[key])

    def confirm(self, sig: ra.Signature | None) -> ra.Signature | None:
        """Keep only extractors that are known to reject anonymous callers: a
        visible ``FromRequest(Parts)`` impl that can fail, or a well-known
        library auth extractor."""
        if sig is None:
            return None

        def ok(type_name: str) -> bool:
            flags = self.extractors.get(type_name)
            if flags:
                return all(flags)
            return type_name in ra.LIBRARY_AUTH_EXTRACTORS

        return ra.Signature(sig.name, [g for g in sig.guards if ok(g[0])], [g for g in sig.optional if ok(g[0])])


__all__ = [
    "Chain",
    "Registry",
    "Ref",
    "actix_chains",
    "axum_like_chains",
    "join_path",
    "literal",
    "loco_chains",
    "nest_chains",
    "opaque_router_names",
    "parse_ref",
    "rocket_mounts",
    "salvo_chains",
]
