"""Routes of frameworks that aren't built as one router chain (#2).

- **warp** — ``warp::path!("users" / u32)`` is one route (``/users/{u32}``).
  Its method is the ``warp::get()`` filter combined with it right before
  (``warp::get().and(warp::path!(..))``) or after (``.and(warp::post())``);
  without one it is ``ANY``. A ``path!`` that ends in ``..`` is a prefix
  filter, and one composed under another filter (``x.and(warp::path!(..))``)
  has a prefix that isn't visible, so neither is emitted.
- **tide** — ``app.at("/x").at("/y").get(h).post(h2)``. A receiver bound with
  ``let mut api = app.at("/api");`` or nested with ``app.at("/api").nest(api)``
  adds its path (same file, bounded depth).

Only route paths and methods are extracted: neither framework declares auth in
a way that can be read from one call site, so these routes stay ``unknown``.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from . import route_auth as ra
from .routing import HTTP_VERBS, Ref, join_path, literal, parse_ref

_MAX_SEGMENTS = 64
_MAX_LINKS = 64
_MAX_DEPTH = 8


@dataclass
class FoundRoute:
    path: str
    method: str
    offset: int
    handler: Ref | None = None


# ---------- warp ----------

_WARP_PATH = re.compile(r"(?<![\w.:])(?:warp\s*::\s*)?path!\s*\(")
_WARP_SEGMENT = re.compile(r'\s*(?:"([^"\\\n]*)"|(\.\.)|([A-Za-z_][\w:]*(?:\s*<[^<>()]{0,80}>)?))\s*')
_WARP_METHOD = re.compile(
    r"\s*warp\s*::\s*(?:filters\s*::\s*method\s*::\s*)?(get|post|put|delete|patch|head|options)\s*\(\s*\)\s*$"
)
_WARP_METHOD_BEFORE = re.compile(
    r"warp\s*::\s*(get|post|put|delete|patch|head|options)\s*\(\s*\)\s*\.\s*and\s*\(\s*$"
)
_AND_BEFORE = re.compile(r"\.\s*and\s*\(\s*$")


def _warp_path(content: str, open_idx: int, close: int) -> str | None:
    segments: list[str] = []
    pos = open_idx + 1
    while pos < close and len(segments) < _MAX_SEGMENTS:
        seg = _WARP_SEGMENT.match(content, pos, close)
        if not seg or seg.end() == pos or seg.group(2):
            return None  # unparsable, or a `..` prefix filter
        if seg.group(1) is not None:
            segments.append(seg.group(1).strip("/"))
        else:
            segments.append("{" + seg.group(3).split("::")[-1].split("<")[0].strip() + "}")
        pos = seg.end()
        if pos < close:
            if content[pos] != "/":
                return None
            pos += 1
    if pos < close or not segments:
        return None
    return "/" + "/".join(s for s in segments if s)


def warp_routes(content: str) -> list[FoundRoute]:
    found = []
    for match in _WARP_PATH.finditer(content):
        open_idx = match.end() - 1
        close = ra.matching_close(content, open_idx)
        if close < 0:
            continue
        path = _warp_path(content, open_idx, close)
        if path is None:
            continue
        before = content[max(0, match.start() - 120) : match.start()]
        method = None
        method_before = _WARP_METHOD_BEFORE.search(before)
        if method_before:
            method = method_before.group(1).upper()
        elif _AND_BEFORE.search(before):
            continue  # under another filter whose prefix isn't visible
        handler = None
        for link in ra.parse_chain(content, close + 1, _MAX_LINKS):
            if link.name == "and" and method is None:
                inner = _WARP_METHOD.match(content, link.open + 1, link.close)
                if inner:
                    method = inner.group(1).upper()
            elif link.name in ("and_then", "map", "then") and handler is None:
                handler = parse_ref(content, link.open + 1, link.close)
        found.append(FoundRoute(path, method or "ANY", match.start(), handler))
    return found


# ---------- tide ----------

_TIDE_AT = re.compile(r"\b([A-Za-z_]\w*)\s*\.\s*at\s*\(")
_TIDE_VERBS = frozenset(HTTP_VERBS) | {"all"}


def tide_routes(content: str) -> list[FoundRoute]:
    entries: list[tuple[int, str, str, list[tuple[str, ra.Link]]]] = []
    bindings: dict[str, list[tuple[int, str, str]]] = {}  # `let api = app.at("/api")`
    nests: dict[str, list[tuple[int, str, str]]] = {}  # `app.at("/api").nest(api)`
    for match in _TIDE_AT.finditer(content):
        close = ra.matching_close(content, match.end() - 1)
        if close < 0:
            continue
        path = literal(content, match.end(), close)
        if path is None:
            continue
        verbs: list[tuple[str, ra.Link]] = []
        for link in ra.parse_chain(content, close + 1, _MAX_LINKS):
            if link.name == "at":
                more = literal(content, link.open + 1, link.close)
                if more is None:
                    break
                path = join_path(path, more)
            elif link.name in _TIDE_VERBS:
                verbs.append((link.name, link))
            elif link.name == "nest":
                ref = parse_ref(content, link.open + 1, link.close)
                if ref is not None and not ref.call:
                    nests.setdefault(ref.name, []).append((match.start(), match.group(1), path))
        let = ra._LET_NAME.search(content[max(0, match.start() - 200) : match.start()])
        if let and not verbs:
            bindings.setdefault(let.group(1), []).append((match.start(), match.group(1), path))
        if verbs:
            entries.append((match.start(), match.group(1), path, verbs))

    def prefix(name: str, offset: int, depth: int) -> str:
        if depth > _MAX_DEPTH:
            return ""
        bound = [b for b in bindings.get(name, []) if b[0] < offset]
        if bound:
            at, receiver, path = max(bound)
        elif len(nests.get(name, [])) == 1:
            at, receiver, path = nests[name][0]
        else:
            return ""
        return join_path(prefix(receiver, at, depth + 1), path)

    found = []
    for offset, receiver, path, verbs in entries:
        full = join_path(prefix(receiver, offset, 0), path)
        for verb, link in verbs:
            method = "ANY" if verb == "all" else verb.upper()
            found.append(FoundRoute(full, method, offset, parse_ref(content, link.open + 1, link.close)))
    return found


__all__ = ["FoundRoute", "tide_routes", "warp_routes"]
