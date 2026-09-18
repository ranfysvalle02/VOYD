"""Cognition entry point (Voyage AI embeddings)."""

from __future__ import annotations

from ..config import VoyageConfig
from .voyage import VoyageIntelligence


class Intelligence:
    """Public factory. ``Intelligence.Voyage(...)`` -> :class:`VoyageIntelligence`."""

    @staticmethod
    def Voyage(api_key: str, model: str = "voyage-3",
               dimensions: int = 1024) -> VoyageIntelligence:
        return VoyageIntelligence(
            VoyageConfig(api_key=api_key, model=model, dimensions=dimensions)
        )


__all__ = ["Intelligence", "VoyageIntelligence"]
