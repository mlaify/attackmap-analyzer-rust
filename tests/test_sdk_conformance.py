"""SDK 1.0 conformance (mlaify/AttackMap#254): attackmap.sdk.testing.assert_conforms."""

from pathlib import Path

from attackmap.sdk.testing import assert_conforms

from attackmap_analyzer_rust import RustAnalyzer


def _has_signals(result) -> None:
    assert any(isinstance(v, list) and v for v in result.__dict__.values()), "the analyzer emitted nothing"


SAMPLE = {'Cargo.toml': '[package]\nname = "sample"\nversion = "0.1.0"\n\n[dependencies]\naxum = "0.7"\n', 'src/main.rs': 'use axum::{routing::get, Router};\n\nfn app() -> Router {\n    Router::new().route("/users/:id", get(user))\n}\n'}


def test_conforms_to_the_sdk(tmp_path: Path) -> None:
    for rel, text in SAMPLE.items():
        (tmp_path / rel).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / rel).write_text(text, encoding="utf-8")
    _has_signals(assert_conforms(RustAnalyzer(), tmp_path))
