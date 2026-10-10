"""
ai_engine.py - FraudLens PK open-weight AI integration (placeholder).

STAGE 1 STATUS: No AI model is connected yet.

In Stage 2 this module will connect to an eligible open-weight model
(maximum 8 billion parameters) through either a local Ollama runtime or a
cloud API. The exact model will only be chosen after its identifier,
parameter count, license, and availability have been verified.

Until then, this module honestly reports that AI analysis is unavailable.
It never pretends a model responded.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class AIStatus:
    configured: bool
    message: str


def get_ai_status() -> AIStatus:
    """Report whether an eligible AI model is configured (always False in Stage 1)."""
    return AIStatus(
        configured=False,
        message=(
            "AI contextual analysis is not set up yet. Results below come only "
            "from the local rule-based detector."
        ),
    )
