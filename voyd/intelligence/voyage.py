"""Voyage AI embeddings.

The client is created lazily so importing/constructing VOYD never requires
network access or a valid key -- only actual embedding calls do. Text is
truncated to a bounded window before it leaves the process.
"""

from __future__ import annotations

from ..config import VoyageConfig


class VoyageIntelligence:
    def __init__(self, config: VoyageConfig):
        self.config = config
        self._client = None

    def _get_client(self):
        if self._client is None:
            import voyageai  # imported lazily; only needed when embedding

            self._client = voyageai.AsyncClient(api_key=self.config.api_key)
        return self._client

    def _truncate(self, text: str) -> str:
        return text[: self.config.max_input_chars]

    async def embed_document(self, text: str) -> list[float]:
        client = self._get_client()
        resp = await client.embed(
            [self._truncate(text)], model=self.config.model, input_type="document"
        )
        return list(resp.embeddings[0])

    async def embed_query(self, text: str) -> list[float]:
        client = self._get_client()
        resp = await client.embed(
            [self._truncate(text)], model=self.config.model, input_type="query"
        )
        return list(resp.embeddings[0])
