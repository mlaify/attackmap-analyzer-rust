from __future__ import annotations

from attackmap.sdk.contracts import AnalyzerMetadata, AnalyzerProtocol
from attackmap.sdk.models import (
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

# Compatibility alias used by existing analyzer implementations.
AttackMapAnalyzerProtocol = AnalyzerProtocol

__all__ = [
    "AnalyzerMetadata",
    "AttackMapAnalyzerProtocol",
    "Route",
    "ExternalCall",
    "DatabaseHint",
    "AuthHint",
    "EntrypointHint",
    "FrameworkHint",
    "ServiceHint",
    "SecretHint",
    "ScanResult",
]
