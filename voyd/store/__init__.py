"""Storage-agnostic entry point for the MongoDB operational layer."""

from __future__ import annotations

from ..config import MongoConfig
from .mongo import MongoStore


class Store:
    """Public factory. ``Store.Mongo(uri, db_name=...)`` -> :class:`MongoStore`."""

    @staticmethod
    def Mongo(uri: str, db_name: str = "voyd", *,
              ledger_key: str | None = None) -> MongoStore:
        return MongoStore(MongoConfig(uri=uri, db_name=db_name,
                                      ledger_key=ledger_key))


__all__ = ["Store", "MongoStore"]
